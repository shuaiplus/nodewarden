import assert from 'node:assert/strict';
import test from 'node:test';

import { AuthService } from '../src/services/auth';
import { upsertTwoFactorSecret } from '../src/services/auth-accounts';
import { hashPassword } from '../src/services/auth-password';
import { StorageService } from '../src/services/storage';
import type { Env, User } from '../src/types';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, portalFetch, seedUser, signInToAdminPortal } from './support/env';

const ADMIN = 'portal@x.io';
const TOTP = 'JBSWY3DPEHPK3PXP';
const PASSWORD = 'test-client-hash';

async function passkey(env: Env, user: User, purpose: 'login' | 'twoFactor') {
  const id = crypto.randomUUID();
  await env.DB.prepare(`INSERT INTO webauthn_credentials
    (id, user_id, purpose, name, public_key, credential_id, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, user.id, purpose, purpose, 'cHVibGlj', id, user.createdAt, user.updatedAt).run();
  return id;
}

test('portal reset clears every factor and revocation token atomically, keeps login passkeys, and sends one administrator notice', async () => {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { email: `factor@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, totpRecoveryCode: 'RECOVERY', twoFactorEmail: `factor-2fa@${MAILABLE_DOMAIN}`, yubikeyKey1: '', yubikeyKey2: 'cccccccccccc' });
  const storage = new StorageService(env.DB);
  const loginPasskey = await passkey(env, user, 'login');
  await passkey(env, user, 'twoFactor');
  await upsertTwoFactorSecret(env.DB, user.id, TOTP, 'RECOVERY');
  await storage.saveTrustedTwoFactorDeviceToken('old-remember', user.id, 'device', Date.now() + 60000);
  await storage.saveRefreshToken('old-session', user.id);
  const oldJwt = await new AuthService(env).generateAccessToken(user);
  const view = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: auth.cookie });
  assert.match(await view.text(), /Authenticator, Email, YubiKey, WebAuthn/);
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 303);
  assert.match(response.headers.get('Location')!, /m=two-factor-reset/);
  const updated = (await storage.getUserById(user.id))!;
  assert.equal(updated.totpSecret, null);
  assert.equal(updated.totpRecoveryCode, null);
  assert.equal(updated.twoFactorEmail, null);
  assert.equal(updated.yubikeyKey2, null);
  assert.notEqual(updated.securityStamp, user.securityStamp);
  for (const table of ['two_factor', 'trusted_two_factor_device_tokens', 'session']) {
    assert.equal(await env.DB.prepare(`SELECT count(*) AS n FROM ${table} WHERE user_id=?`).bind(user.id).first('n'), 0);
  }
  assert.deepEqual((await storage.getAccountPasskeyCredentialsByUserId(user.id)).map(key => key.id), [loginPasskey]);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldJwt}` } })).status, 401);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 1);
  assert.match(String(mail.sent[0].text), /An administrator removed two-step login/);
  assert.doesNotMatch(String(mail.sent[0].text), /203\.0\.113|portal@x\.io|IP address|recovery code/i);
  const audit = await env.DB.prepare("SELECT actor_user_id,metadata FROM audit_logs WHERE action='admin.portal.user.two_factor.reset'").first<{ actor_user_id: string | null; metadata: string }>();
  assert.equal(audit?.actor_user_id, null);
  assert.equal(JSON.parse(audit!.metadata).adminEmail, ADMIN);

  await storage.saveUser({ ...updated, totpSecret: TOTP }, ['totpSecret']);
  const remembered = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password: PASSWORD, deviceIdentifier: 'device', twoFactorProvider: '5', twoFactorToken: 'old-remember' } });
  assert.equal(remembered.status, 400);
  assert.deepEqual((await remembered.json() as { TwoFactorProviders: string[] }).TwoFactorProviders, ['0']);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 1);
});

test('nothing-to-reset leaves account, audit, budgets and mail untouched', async (t) => {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env);
  await passkey(env, user, 'login');
  const batch = t.mock.method(env.DB, 'batch');
  const before = await env.DB.prepare('SELECT count(*) AS n FROM rate_limit_buckets').first('n');
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 303);
  assert.match(response.headers.get('Location')!, /m=nothing-to-reset/);
  assert.equal(batch.mock.callCount(), 0);
  assert.equal((await new StorageService(env.DB).getUserById(user.id))?.securityStamp, user.securityStamp);
  assert.equal(await env.DB.prepare('SELECT count(*) AS n FROM audit_logs').first('n'), 0);
  assert.equal(await env.DB.prepare('SELECT count(*) AS n FROM rate_limit_buckets').first('n'), before);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 0);
});

test('reset refuses missing CSRF, wrong email, stale step-up and the 21st sensitive action', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: ADMIN });
  let auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { totpSecret: TOTP });
  const path = `/admin/users/${user.id}/remove-2fa`;
  const post = (form: Record<string, string>) => portalFetch(env, { method: 'POST', path, cookie: auth.cookie, form });
  assert.equal((await post({ confirmation: user.email })).status, 403);
  assert.equal((await post({ csrf: auth.csrf, confirmation: 'wrong@x.io' })).status, 400);
  await env.DB.prepare("UPDATE verification SET value=json_set(value,'$.authTime',0) WHERE id LIKE 'admin-session:%'").run();
  const stale = await post({ csrf: auth.csrf, confirmation: user.email });
  assert.equal(stale.status, 303);
  assert.match(stale.headers.get('Location')!, /m=reauth/);
  auth = await signInToAdminPortal(env, ADMIN);
  for (let index = 0; index < 20; index++) {
    await env.DB.prepare('UPDATE users SET totp_secret=? WHERE id=?').bind(TOTP, user.id).run();
    assert.equal((await post({ csrf: auth.csrf, confirmation: user.email })).status, 303);
  }
  await env.DB.prepare('UPDATE users SET totp_secret=? WHERE id=?').bind(TOTP, user.id).run();
  assert.equal((await post({ csrf: auth.csrf, confirmation: user.email })).status, 429);
  assert.equal((await new StorageService(env.DB).getUserById(user.id))?.totpSecret, TOTP);
  await drainWaitUntil();
});

test('an audit failure rolls back a reset before any notification', async () => {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { email: `factor@${MAILABLE_DOMAIN}`, totpSecret: TOTP });
  await env.DB.prepare("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'audit failure'); END").run();
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 500);
  const updated = (await new StorageService(env.DB).getUserById(user.id))!;
  assert.equal(updated.totpSecret, TOTP);
  assert.equal(updated.securityStamp, user.securityStamp);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 0);
});
