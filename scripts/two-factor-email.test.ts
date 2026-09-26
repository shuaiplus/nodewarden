import assert from 'node:assert/strict';
import test from 'node:test';

import { hashPassword } from '../src/services/auth-password';
import { buildBackupArchive } from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import { StorageService } from '../src/services/storage';
import type { Env, User } from '../src/types';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, seedUser } from './support/env';

const { createOwnedOrganization } = await import('../src/handlers/organizations');
const PASSWORD = 'client-master-password-hash';
const FACTOR_EMAIL = `factor@${MAILABLE_DOMAIN}`;

async function settings(env: Env, user: User) {
  const response = await authedFetch(env, { method: 'POST', path: '/api/two-factor/get-email', userId: user.id, body: { masterPasswordHash: PASSWORD } });
  assert.equal(response.status, 200);
  return response.json() as Promise<{ Email: { Enabled: boolean; Email: string | null }; UserVerificationToken: string }>;
}

async function setup() {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  const token = (await settings(env, user)).UserVerificationToken;
  const send = await authedFetch(env, { method: 'POST', path: '/api/two-factor/send-email', userId: user.id, body: { email: FACTOR_EMAIL.toUpperCase(), userVerificationToken: token } });
  assert.equal(send.status, 200);
  assert.equal(mail.sent.length, 1);
  const code = String(mail.sent[0].text).match(/\b\d{6}\b/)![0];
  assert.doesNotMatch(String(mail.sent[0].subject), /\d{6}/);
  assert.equal(mail.sent[0].to, FACTOR_EMAIL);
  return { env, user, token, mail, code };
}

function enable(env: Env, user: User, userVerificationToken: string, email: string, token: string) {
  return authedFetch(env, { method: 'PUT', path: '/api/two-factor/email', userId: user.id, body: { email, token, userVerificationToken } });
}

test('email setup requires user verification and rejects other providers, malformed addresses and unavailable mail', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  const missing = await authedFetch(env, { method: 'POST', path: '/api/two-factor/get-email', userId: user.id, body: {} });
  assert.equal(missing.status, 400);
  const current = await settings(env, user);
  assert.deepEqual(current.Email, { Enabled: false, Email: null });
  const yubikey = await authedFetch(env, { method: 'POST', path: '/api/two-factor/get-yubikey', userId: user.id, body: { masterPasswordHash: PASSWORD } }).then(response => response.json() as Promise<{ UserVerificationToken: string }>);
  for (const [email, userVerificationToken, status] of [
    [FACTOR_EMAIL, yubikey.UserVerificationToken, 400],
    ['invalid', current.UserVerificationToken, 400],
    [FACTOR_EMAIL, current.UserVerificationToken, 503],
  ] as const) {
    const response = await authedFetch(env, { method: 'POST', path: '/api/two-factor/send-email', userId: user.id, body: { email, userVerificationToken } });
    assert.equal(response.status, status);
  }
  assert.equal(await env.DB.prepare("SELECT count(*) AS n FROM verification WHERE identifier >= 'otp:' AND identifier < 'otp;'").first('n'), 0);
});

test('setup codes bind the address, enable Email consistently, survive stale saves and are single-use', async () => {
  const { env, user, token, code } = await setup();
  for (const [email, candidate] of [[`other@${MAILABLE_DOMAIN}`, code], [FACTOR_EMAIL, code === '000000' ? '111111' : '000000']]) {
    const rejected = await enable(env, user, token, email, candidate);
    assert.equal(rejected.status, 400);
    assert.deepEqual((await rejected.json() as { validationErrors: unknown }).validationErrors, { Token: ['Invalid token.'] });
  }
  const enabled = await enable(env, user, token, FACTOR_EMAIL, code);
  assert.equal(enabled.status, 200);
  assert.deepEqual(await enabled.json(), { Email: { Enabled: true, Email: FACTOR_EMAIL }, Object: 'twoFactorEmailUpdate' });
  const storage = new StorageService(env.DB);
  const updated = (await storage.getUserById(user.id))!;
  assert.equal(updated.twoFactorEmail, FACTOR_EMAIL);
  assert.ok(updated.totpRecoveryCode);
  await storage.saveUser(user);
  assert.equal((await storage.getUserById(user.id))?.twoFactorEmail, FACTOR_EMAIL);
  assert.equal((await storage.getUserById(user.id))?.totpRecoveryCode, updated.totpRecoveryCode);
  assert.equal((await enable(env, user, token, FACTOR_EMAIL, code)).status, 400);
  const providers = await authedFetch(env, { path: '/api/two-factor', userId: user.id });
  assert.deepEqual((await providers.json() as { Data: { Type: number }[] }).Data.map(provider => provider.Type), [1]);
  const profile = await authedFetch(env, { path: '/api/accounts/profile', userId: user.id });
  assert.equal((await profile.json() as { twoFactorEnabled: boolean }).twoFactorEnabled, true);
  const org = await createOwnedOrganization(env, updated, { name: 'Email factor', key: '4.dGVzdA==' });
  const members = await authedFetch(env, { path: `/api/organizations/${org.id}/users`, userId: user.id });
  assert.equal((await members.json() as { data: { twoFactorEnabled: boolean }[] }).data[0].twoFactorEnabled, true);
});

test('enabling Email creates a working recovery code which clears the factor', async () => {
  const { env, user, token, code } = await setup();
  assert.equal((await enable(env, user, token, FACTOR_EMAIL, code)).status, 200);
  const storage = new StorageService(env.DB);
  const recoveryCode = (await storage.getUserById(user.id))!.totpRecoveryCode;
  assert.ok(recoveryCode);
  const response = await authedFetch(env, { method: 'POST', path: '/identity/accounts/recover-2fa', body: { email: user.email, masterPasswordHash: PASSWORD, recoveryCode } });
  assert.equal(response.status, 200);
  assert.equal((await storage.getUserById(user.id))?.twoFactorEmail, null);
  const rotatedCode = (await storage.getUserById(user.id))!.totpRecoveryCode;
  await storage.saveUser({ ...user, totpRecoveryCode: recoveryCode });
  assert.equal((await storage.getUserById(user.id))?.totpRecoveryCode, rotatedCode);
  assert.notEqual(rotatedCode, recoveryCode);
  await drainWaitUntil();
});

test('Email remains enforced with mail disabled, but settings and both removal routes still work', async () => {
  for (const legacy of [false, true]) {
    const env = await createTestEnv();
    const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: FACTOR_EMAIL, totpRecoveryCode: 'RECOVERY' });
    const login = () => authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password: PASSWORD } });
    const required = await login();
    assert.equal(required.status, 400);
    assert.deepEqual((await required.json() as { TwoFactorProviders: string[] }).TwoFactorProviders, ['1']);
    const current = await settings(env, user);
    assert.equal(current.Email.Enabled, true);
    const removed = await authedFetch(env, {
      method: legacy ? 'POST' : 'DELETE', path: legacy ? '/api/two-factor/disable' : '/api/two-factor/email', userId: user.id,
      body: legacy ? { type: 1, masterPasswordHash: PASSWORD } : { userVerificationToken: current.UserVerificationToken },
    });
    assert.equal(removed.status, legacy ? 200 : 204);
    assert.equal((await new StorageService(env.DB).getUserById(user.id))?.twoFactorEmail, null);
    assert.equal((await login()).status, 200);
    await drainWaitUntil();
  }
});

test('backup restore preserves the enrolled Email address', async () => {
  const { env, user, token, code } = await setup();
  assert.equal((await enable(env, user, token, FACTOR_EMAIL, code)).status, 200);
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });
  const restored = await createTestEnv();
  await importBackupArchiveBytes(archive.bytes, restored, user.id, false);
  assert.equal((await new StorageService(restored.DB).getUserById(user.id))?.twoFactorEmail, FACTOR_EMAIL);
});
