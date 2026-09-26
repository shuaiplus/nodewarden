import assert from 'node:assert/strict';
import test from 'node:test';

import { AuthService } from '../src/services/auth';
import { hashPassword } from '../src/services/auth-password';
import { StorageService } from '../src/services/storage';
import type { User } from '../src/types';
import { authedFetch, createTestEnv, drainWaitUntil, portalFetch, seedUser, signInToAdminPortal } from './support/env';

const PASSWORD = 'old-client-password';
const NEXT_PASSWORD = 'new-client-password';
const NEXT_KEY = '2.bmV3LWtleQ==|bmV3LWtleQ==|bmV3LWtleQ==';
const NEXT_PRIVATE_KEY = '2.bmV3LXByaXZhdGU=|bmV3LXByaXZhdGU=|bmV3LXByaXZhdGU=';

test('a pending profile save cannot restore password/key material, API keys or cleared factors', async (t) => {
  const env = await createTestEnv({ ADMIN_EMAILS: 'portal@x.io' });
  const portalAuth = await signInToAdminPortal(env, 'portal@x.io');
  const user = await seedUser(env, {
    masterPasswordHash: await hashPassword(PASSWORD), apiKey: 'old-api-key',
    totpSecret: 'JBSWY3DPEHPK3PXP', totpRecoveryCode: 'OLD-RECOVERY', yubikeyKey1: 'cccccccccccc',
  });
  const oldJwt = await new AuthService(env).generateAccessToken(user);
  const storage = new StorageService(env.DB);
  const saveUser = StorageService.prototype.saveUser;
  let interrupted = false;
  let securityState: User;
  t.mock.method(StorageService.prototype, 'saveUser', async function (this: StorageService, snapshot: User, fields?: Parameters<StorageService['saveUser']>[1], originalStamp?: string) {
    if (!interrupted && snapshot.masterPasswordHint === 'Pending profile') {
      interrupted = true;
      const password = await authedFetch(env, {
        method: 'POST', path: '/api/accounts/password', userId: user.id,
        body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: NEXT_PASSWORD, key: NEXT_KEY, encryptedPrivateKey: NEXT_PRIVATE_KEY, publicKey: 'new-public-key' },
      });
      assert.equal(password.status, 200);
      const apiKey = await authedFetch(env, { method: 'POST', path: '/api/accounts/rotate-api-key', userId: user.id, body: { masterPasswordHash: NEXT_PASSWORD } });
      assert.equal(apiKey.status, 200);
      const reset = await portalFetch(env, {
        method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: portalAuth.cookie,
        form: { csrf: portalAuth.csrf, confirmation: user.email },
      });
      assert.equal(reset.status, 303);
      securityState = (await storage.getUserById(user.id))!;
    }
    return saveUser.call(this, snapshot, fields, originalStamp);
  });
  const profile = await authedFetch(env, { method: 'PUT', path: '/api/accounts/profile', userId: user.id, body: { masterPasswordHint: 'Pending profile' } });
  assert.equal(profile.status, 400);
  assert.equal(interrupted, true);
  const current = (await storage.getUserById(user.id))!;
  assert.equal(current.masterPasswordHint, user.masterPasswordHint);
  for (const field of ['masterPasswordHash', 'key', 'privateKey', 'publicKey', 'apiKey', 'securityStamp', 'totpSecret', 'totpRecoveryCode', 'yubikeyKey1'] as const) {
    assert.equal(current[field], securityState![field], field);
  }
  assert.equal(current.key, NEXT_KEY);
  assert.equal(current.privateKey, NEXT_PRIVATE_KEY);
  assert.equal(current.totpSecret, null);
  assert.equal(current.totpRecoveryCode, null);
  assert.notEqual(current.apiKey, user.apiKey);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldJwt}` } })).status, 401);
  for (const [password, status] of [[PASSWORD, 400], [NEXT_PASSWORD, 200]] as const) {
    const login = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password } });
    assert.equal(login.status, status);
  }
  await drainWaitUntil();
});

test('a pending profile save cannot resurrect a deleted account and account creation never overwrites one', async (t) => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const storage = new StorageService(env.DB);
  await assert.rejects(storage.createUser({ ...user, name: 'Duplicate account' }));
  assert.equal((await storage.getUserById(user.id))?.name, user.name);
  const oldJwt = await new AuthService(env).generateAccessToken(user);
  const saveUser = StorageService.prototype.saveUser;
  t.mock.method(StorageService.prototype, 'saveUser', async function (this: StorageService, snapshot: User, fields?: Parameters<StorageService['saveUser']>[1], originalStamp?: string) {
    const deleted = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body: { masterPasswordHash: user.masterPasswordHash } });
    assert.equal(deleted.status, 200);
    return saveUser.call(this, snapshot, fields, originalStamp);
  });
  const profile = await authedFetch(env, { method: 'PUT', path: '/api/accounts/profile', userId: user.id, body: { masterPasswordHint: 'After deletion' } });
  assert.equal(profile.status, 400);
  assert.equal(await storage.getUserById(user.id), null);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldJwt}` } })).status, 401);
  await drainWaitUntil();
});

test('an API-key request authorized against an old password cannot write after a password change', async (t) => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), apiKey: 'existing-api-key' });
  const verifyPassword = AuthService.prototype.verifyPassword;
  let interrupted = false;
  t.mock.method(AuthService.prototype, 'verifyPassword', async function (this: AuthService, ...args: Parameters<AuthService['verifyPassword']>) {
    if (!interrupted && args[0] === PASSWORD) {
      interrupted = true;
      const changed = await authedFetch(env, {
        method: 'POST', path: '/api/accounts/password', userId: user.id,
        body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: NEXT_PASSWORD, key: NEXT_KEY },
      });
      assert.equal(changed.status, 200);
    }
    return verifyPassword.apply(this, args);
  });
  const delayed = await authedFetch(env, { method: 'POST', path: '/api/accounts/rotate-api-key', userId: user.id, body: { masterPasswordHash: PASSWORD } });
  assert.equal(interrupted, true);
  assert.equal(delayed.status, 400);
  assert.equal((await delayed.json() as { error: string }).error, 'User verification failed.');
  assert.equal((await new StorageService(env.DB).getUserById(user.id))?.apiKey, 'existing-api-key');
});
