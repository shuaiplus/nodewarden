import assert from 'node:assert/strict';
import test from 'node:test';
import * as OTPAuth from 'otpauth';

import { LIMITS } from '../config/limits';
import { hashPassword } from '../services/auth-password';
import type { Env, User } from '../types';
import { sha256Base64Url } from '../utils/account-passkeys';
import { signHs256Jwt, verifyHs256Jwt } from '../utils/jwt';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import * as userRepo from '../services/storage-user-repo';

const PASSWORD = 'client-master-password-hash';
const TOTP = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const PUBLIC_ID = 'cccccccccccc';

async function getProvider(env: Env, user: User, provider: string): Promise<Record<string, any>> {
  const response = await authedFetch(env, {
    method: 'POST', path: `/api/two-factor/get-${provider}`, userId: user.id,
    body: { masterPasswordHash: PASSWORD },
  });
  assert.equal(response.status, 200);
  return response.json();
}

test('official authenticator DELETE verifies its key-bound token and clears the Better Auth secret', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, yubikeyKey1: PUBLIC_ID });
  const settings = await getProvider(env, user, 'authenticator');
  assert.deepEqual(settings.Authenticator, { Enabled: true, Key: TOTP });
  const request = (key: string) => authedFetch(env, {
    method: 'DELETE', path: '/api/two-factor/authenticator', userId: user.id,
    body: { key, userVerificationToken: settings.UserVerificationToken, type: 3 },
  });
  assert.equal((await request('WRONGKEY')).status, 400);
  const disabled = await request(TOTP);
  assert.equal(disabled.status, 204);
  assert.equal(await disabled.text(), '');
  const updated = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(updated.totpSecret, null);
  assert.equal(updated.yubikeyKey1, PUBLIC_ID);
  const token = new OTPAuth.TOTP({ secret: TOTP }).generate();
  const enabled = await authedFetch(env, {
    method: 'PUT', path: '/api/two-factor/authenticator', userId: user.id,
    body: { key: TOTP, token, userVerificationToken: settings.UserVerificationToken },
  });
  assert.equal(enabled.status, 200);
  assert.deepEqual((await enabled.json() as { Authenticator: unknown }).Authenticator, { Enabled: true, Key: TOTP });
});

test('official YubiKey token-only enable/disable keeps TOTP; legacy password disable still works', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP });
  const settings = await getProvider(env, user, 'yubikey');
  assert.equal(settings.YubiKey.Enabled, false);
  const token = settings.UserVerificationToken;
  const enabled = await authedFetch(env, {
    method: 'PUT', path: '/api/two-factor/yubi-key', userId: user.id,
    body: { key1: PUBLIC_ID, nfc: true, userVerificationToken: token },
  });
  assert.equal(enabled.status, 200);
  const result = await enabled.json() as { YubiKey: { Enabled: boolean; Key1: string; Nfc: boolean } };
  assert.equal(result.YubiKey.Enabled, true);
  assert.equal(result.YubiKey.Key1, PUBLIC_ID);
  assert.equal(result.YubiKey.Nfc, true);
  const disabled = await authedFetch(env, {
    method: 'DELETE', path: '/api/two-factor/yubikey', userId: user.id,
    body: { userVerificationToken: token, type: 0 },
  });
  assert.equal(disabled.status, 204);
  const updated = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(updated.yubikeyKey1, null);
  assert.equal(updated.totpSecret, TOTP);
  assert.equal(updated.securityStamp, user.securityStamp);
  const legacy = await authedFetch(env, {
    method: 'POST', path: '/api/two-factor/disable', userId: user.id, body: { type: 0, secret: PASSWORD },
  });
  assert.equal(legacy.status, 200);
  assert.equal((await userRepo.getUserById(env.DB, user.id))!.totpSecret, null);
});

test('provider tokens are scoped to a user, provider, current stamp and finite 30-minute expiry', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, yubikeyKey1: PUBLIC_ID });
  const other = await seedUser(env, { masterPasswordHash: user.masterPasswordHash });
  const authenticator = await getProvider(env, user, 'authenticator');
  const yubikey = await getProvider(env, user, 'yubikey');
  const otherYubikey = await getProvider(env, other, 'yubikey');
  const claims = (await verifyHs256Jwt(yubikey.UserVerificationToken, env.JWT_SECRET))!;
  assert.equal(claims.iss, 'nodewarden|two_factor_uv');
  assert.equal(claims.sub, user.id);
  assert.equal(claims.ptype, 3);
  assert.equal(claims.sst, await sha256Base64Url(user.securityStamp));
  assert.equal(claims.key, undefined);
  assert.ok(Math.abs(Number(claims.exp) - Math.floor(Date.now() / 1000) - LIMITS.auth.twoFactorUserVerificationTtlSeconds) <= 1);

  const mutations = [
    ['PUT', '/api/two-factor/yubikey', { key1: PUBLIC_ID }],
    ['DELETE', '/api/two-factor/yubikey', {}],
    ['POST', '/api/two-factor/get-webauthn-challenge', {}],
    ['PUT', '/api/two-factor/webauthn', {}],
    ['DELETE', '/api/two-factor/webauthn', { id: 1 }],
    ['DELETE', '/api/two-factor/webauthn/all', {}],
  ] as const;
  for (const [method, path, body] of mutations) {
    const response = await authedFetch(env, {
      method, path, userId: user.id, body: { ...body, userVerificationToken: authenticator.UserVerificationToken },
    });
    assert.equal(response.status, 400, path);
    assert.equal((await response.json() as { error: string }).error, 'User verification failed.', path);
  }
  const { exp: _exp, ...withoutExpiry } = claims;
  for (const token of [
    otherYubikey.UserVerificationToken,
    await signHs256Jwt({ ...claims, exp: Math.floor(Date.now() / 1000) - 1 }, env.JWT_SECRET),
    await signHs256Jwt(withoutExpiry, env.JWT_SECRET),
    await signHs256Jwt({ ...claims, exp: 'forever' }, env.JWT_SECRET),
    await signHs256Jwt({ ...claims, iss: 'nodewarden' }, env.JWT_SECRET),
    `${yubikey.UserVerificationToken}invalid`,
  ]) {
    const response = await authedFetch(env, { method: 'DELETE', path: '/api/two-factor/yubikey', userId: user.id, body: { userVerificationToken: token } });
    assert.equal(response.status, 400);
    assert.equal((await response.json() as { error: string }).error, 'User verification failed.');
  }
  const changed = await authedFetch(env, {
    method: 'POST', path: '/api/accounts/password', userId: user.id,
    body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: 'new-client-hash', key: user.key },
  });
  assert.equal(changed.status, 200);
  const stale = await authedFetch(env, { method: 'DELETE', path: '/api/two-factor/yubikey', userId: user.id, body: { userVerificationToken: yubikey.UserVerificationToken } });
  assert.equal(stale.status, 400);
  assert.equal((await userRepo.getUserById(env.DB, user.id))!.yubikeyKey1, PUBLIC_ID);
});
