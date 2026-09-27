import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, like } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { auditLogs, rateLimitBuckets, session, trustedTwoFactorDeviceTokens, users, verification, webauthnCredentials } from '../db/schema';
import { jsonSet } from '../db/sql';
import { AuthService } from '../services/auth';
import { hashPassword } from '../services/auth-password';
import type { Env, User } from '../types';
import { abortWrites, authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import * as sessionRepo from '../services/storage-session-repo';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as deviceRepo from '../services/storage-device-repo';
import * as userRepo from '../services/storage-user-repo';

const ADMIN = 'portal@x.io';
const TOTP = 'JBSWY3DPEHPK3PXP';
const PASSWORD = 'test-client-hash';

async function passkey(env: Env, user: User, purpose: 'login' | 'twoFactor') {
  const id = crypto.randomUUID();
  await getOrm(env.DB).insert(webauthnCredentials).values({
    id, userId: user.id, purpose, name: purpose, publicKey: 'cHVibGlj', credentialId: id, createdAt: user.createdAt, updatedAt: user.updatedAt,
  });
  return id;
}

test('portal reset clears every factor and revocation token atomically, keeps login passkeys, and sends one administrator notice', async () => {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { email: `factor@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP, totpRecoveryCode: 'RECOVERY', twoFactorEmail: `factor-2fa@${MAILABLE_DOMAIN}`, yubikeyKey1: '', yubikeyKey2: 'cccccccccccc' });
  const loginPasskey = await passkey(env, user, 'login');
  await passkey(env, user, 'twoFactor');
  await deviceRepo.saveTrustedTwoFactorDeviceToken(env.DB, 'old-remember', user.id, 'device', Date.now() + 60000);
  await sessionRepo.saveRefreshToken(env.DB, 'old-session', user.id);
  const oldJwt = await new AuthService(env).generateAccessToken(user);
  const view = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: auth.cookie });
  assert.match(await view.text(), /Authenticator, Email, YubiKey, WebAuthn/);
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 303);
  assert.match(response.headers.get('Location')!, /m=two-factor-reset/);
  const updated = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(updated.totpSecret, null);
  assert.equal(updated.totpRecoveryCode, null);
  assert.equal(updated.twoFactorEmail, null);
  assert.equal(updated.yubikeyKey2, null);
  assert.notEqual(updated.securityStamp, user.securityStamp);
  for (const table of [trustedTwoFactorDeviceTokens, session]) {
    assert.equal(await getOrm(env.DB).$count(table, eq(table.userId, user.id)), 0);
  }
  assert.deepEqual((await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, user.id)).map(key => key.id), [loginPasskey]);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldJwt}` } })).status, 401);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 1);
  assert.match(String(mail.sent[0].text), /An administrator removed two-step login/);
  assert.doesNotMatch(String(mail.sent[0].text), /203\.0\.113|portal@x\.io|IP address|recovery code/i);
  const audit = await getOrm(env.DB).select({ actorUserId: auditLogs.actorUserId, metadata: auditLogs.metadata }).from(auditLogs)
    .where(eq(auditLogs.action, 'admin.portal.user.two_factor.reset')).get();
  assert.equal(audit?.actorUserId, null);
  assert.equal(JSON.parse(audit!.metadata!).adminEmail, ADMIN);

  await userRepo.saveUser(env.DB, { ...updated, totpSecret: TOTP }, ['totpSecret']);
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
  const before = await getOrm(env.DB).$count(rateLimitBuckets);
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 303);
  assert.match(response.headers.get('Location')!, /m=nothing-to-reset/);
  assert.equal(batch.mock.callCount(), 0);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.securityStamp, user.securityStamp);
  assert.equal(await getOrm(env.DB).$count(auditLogs), 0);
  assert.equal(await getOrm(env.DB).$count(rateLimitBuckets), before);
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
  await getOrm(env.DB).update(verification).set({ value: jsonSet(verification.value, '$.authTime', 0) }).where(like(verification.id, 'admin-session:%'));
  const stale = await post({ csrf: auth.csrf, confirmation: user.email });
  assert.equal(stale.status, 303);
  assert.match(stale.headers.get('Location')!, /m=reauth/);
  auth = await signInToAdminPortal(env, ADMIN);
  for (let index = 0; index < 20; index++) {
    await getOrm(env.DB).update(users).set({ totpSecret: TOTP }).where(eq(users.id, user.id));
    assert.equal((await post({ csrf: auth.csrf, confirmation: user.email })).status, 303);
  }
  await getOrm(env.DB).update(users).set({ totpSecret: TOTP }).where(eq(users.id, user.id));
  assert.equal((await post({ csrf: auth.csrf, confirmation: user.email })).status, 429);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.totpSecret, TOTP);
  await drainWaitUntil();
});

test('an audit failure rolls back a reset before any notification', async () => {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { email: `factor@${MAILABLE_DOMAIN}`, totpSecret: TOTP });
  await abortWrites(env, { table: auditLogs, event: 'INSERT' }, 'audit failure');
  const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(response.status, 500);
  const updated = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(updated.totpSecret, TOTP);
  assert.equal(updated.securityStamp, user.securityStamp);
  await drainWaitUntil();
  assert.equal(mail.sent.length, 0);
});
