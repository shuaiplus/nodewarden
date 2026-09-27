import assert from 'node:assert/strict';
import test from 'node:test';
import { AuthService } from '../src/services/auth';
import { hashPassword } from '../src/services/auth-password';
import { ensureTwoFactorRecoveryCode } from '../src/services/two-factor-providers';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import type { Env, User } from '../src/types';
import * as passkeyRepo from '../src/services/storage-account-passkey-repo';
import * as deviceRepo from '../src/services/storage-device-repo';
import * as sessionRepo from '../src/services/storage-session-repo';
import * as userRepo from '../src/services/storage-user-repo';

const PASSWORD = 'recovery-client-password';
const RECOVERY = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';
const TOTP = 'JBSWY3DPEHPK3PXP';
const recoveryRequest = (env: Env, user: User, login: boolean) => authedFetch(env, {
  method: 'POST', path: login ? '/identity/connect/token' : '/identity/accounts/recover-2fa',
  body: login ? { grant_type: 'password', username: user.email, password: PASSWORD, twoFactorProvider: '8', twoFactorToken: RECOVERY }
    : { email: user.email, masterPasswordHash: PASSWORD, recoveryCode: RECOVERY },
});

for (const login of [false, true]) {
  test(`${login ? 'login' : 'endpoint'} recovery verified before an administrator reset cannot clear current factors or sessions`, async (t) => {
    const env = await createTestEnv({ ADMIN_EMAILS: 'portal@x.io' });
    const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, totpRecoveryCode: RECOVERY });
    const portal = await signInToAdminPortal(env, 'portal@x.io');
    const verify = AuthService.prototype.verifyPassword;
    let interrupted = false;
    let current: User;
    t.mock.method(AuthService.prototype, 'verifyPassword', async function(this: AuthService, ...args: Parameters<AuthService['verifyPassword']>) {
      const valid = await verify.apply(this, args);
      if (!interrupted && args[0] === PASSWORD) {
        interrupted = true;
        const reset = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: portal.cookie, form: { csrf: portal.csrf, confirmation: user.email } });
        assert.equal(reset.status, 303);
        current = (await userRepo.getUserById(env.DB, user.id))!;
        current.totpRecoveryCode = await ensureTwoFactorRecoveryCode(env.DB, user.id, current.securityStamp);
        current.totpSecret = TOTP;
        await userRepo.saveUser(env.DB, current, ['totpSecret']);
        await env.DB.prepare("INSERT INTO webauthn_credentials (id,user_id,purpose,name,public_key,credential_id,created_at,updated_at) VALUES (?,?, 'twoFactor','current','cHVibGlj',?,?,?)")
          .bind('current-key', user.id, 'current-key', current.createdAt, current.updatedAt).run();
        await deviceRepo.saveTrustedTwoFactorDeviceToken(env.DB, 'current-remember', user.id, 'current-device', Date.now() + 60000);
        await sessionRepo.saveRefreshToken(env.DB, 'current-session', user.id);
      }
      return valid;
    });
    const response = await recoveryRequest(env, user, login);
    assert.equal(response.status, 400);
    assert.equal(interrupted, true);
    const after = (await userRepo.getUserById(env.DB, user.id))!;
    for (const field of ['securityStamp', 'totpSecret', 'totpRecoveryCode'] as const) assert.equal(after[field], current![field], field);
    assert.equal(await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor'), 1);
    assert.equal(await deviceRepo.getTrustedTwoFactorDeviceTokenUserId(env.DB, 'current-remember', 'current-device'), user.id);
    assert.equal(await sessionRepo.getRefreshTokenUserId(env.DB, 'current-session'), user.id);
    await drainWaitUntil();
  });
}

test('the same recovery code can complete only one of two concurrent login/endpoint requests', async (t) => {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, { email: `recovery@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, totpRecoveryCode: RECOVERY });
  const verify = AuthService.prototype.verifyPassword;
  let arrivals = 0;
  let release!: () => void;
  const ready = new Promise<void>(resolve => { release = resolve; });
  t.mock.method(AuthService.prototype, 'verifyPassword', async function(this: AuthService, ...args: Parameters<AuthService['verifyPassword']>) {
    const valid = await verify.apply(this, args);
    if (++arrivals === 2) release();
    await ready;
    return valid;
  });
  const responses = await Promise.all([recoveryRequest(env, user, false), recoveryRequest(env, user, true)]);
  assert.deepEqual(responses.map(response => response.status).sort(), [200, 400]);
  await drainWaitUntil();
  assert.equal(mail.sent.filter(message => message.subject === 'NodeWarden two-step login was recovered').length, 1);
  const loginResponse = await responses[1].json() as { access_token?: string };
  if (responses[1].status === 200) assert.ok(await new AuthService(env).verifyAccessTokenWithUser(`Bearer ${loginResponse.access_token}`));
  else assert.equal(loginResponse.access_token, undefined);
});
