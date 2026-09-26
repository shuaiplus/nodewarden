import assert from 'node:assert/strict';
import test from 'node:test';

import { createSsoEmail2faSessionToken, signHs256Jwt } from '../src/utils/jwt';
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

function passwordLogin(env: Env, user: User, extra: Record<string, string> = {}) {
  return authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: {
    grant_type: 'password', username: user.email, password: PASSWORD, deviceIdentifier: 'email-device', ...extra,
  } });
}

function sendLoginCode(env: Env, body: Record<string, unknown>) {
  return authedFetch(env, { method: 'POST', path: '/api/two-factor/send-email-login', body });
}

test('Email challenges mask the factor address and carry the send-only session token in both response levels', async () => {
  for (const [local, masked] of [['ab', '**'], ['abcd', 'a***'], ['abcdef', 'ab****']]) {
    const mail = captureEmail();
    const env = await createTestEnv(mail.overrides);
    const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: `${local}@${MAILABLE_DOMAIN}` });
    const response = await passwordLogin(env, user);
    assert.equal(response.status, 400);
    const body = await response.json() as Record<string, any>;
    for (const challenge of [body, body.CustomResponse]) {
      assert.deepEqual(challenge.TwoFactorProviders, ['1']);
      assert.deepEqual(challenge.TwoFactorProviders2['1'], { Email: `${masked}@${MAILABLE_DOMAIN}` });
      assert.equal(challenge.Email, user.email);
      assert.equal(challenge.SsoEmail2faSessionToken, body.SsoEmail2faSessionToken);
      assert.ok(challenge.SsoEmail2faSessionToken);
    }
    assert.equal(mail.sent.length, 0);
  }
});

test('master password and session-token sending target the factor address; login codes are single-use and remember-device works', async () => {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, { email: `account@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: FACTOR_EMAIL });
  const challenge = await passwordLogin(env, user).then(response => response.json() as Promise<{ SsoEmail2faSessionToken: string }>);
  assert.equal((await sendLoginCode(env, { email: user.email, masterPasswordHash: PASSWORD })).status, 200);
  assert.equal((await sendLoginCode(env, { Email: user.email, SsoEmail2FaSessionToken: challenge.SsoEmail2faSessionToken, masterPasswordHash: 'wrong' })).status, 200);
  assert.equal(mail.sent.length, 2);
  assert.ok(mail.sent.every(message => message.to === FACTOR_EMAIL));
  const code = String(mail.sent[1].text).match(/\b\d{6}\b/)![0];
  assert.doesNotMatch(String(mail.sent[1].subject), /\d{6}/);
  const success = await passwordLogin(env, user, { twoFactorProvider: '1', twoFactorToken: code, twoFactorRemember: '1' });
  assert.equal(success.status, 200);
  const tokens = await success.json() as { access_token: string; TwoFactorToken: string };
  assert.ok(tokens.access_token);
  assert.ok(tokens.TwoFactorToken);
  assert.equal((await passwordLogin(env, user, { twoFactorProvider: '1', twoFactorToken: code })).status, 400);
  assert.equal((await passwordLogin(env, user, { twoFactorProvider: '5', twoFactorToken: tokens.TwoFactorToken })).status, 200);
  await drainWaitUntil();
  assert.equal(mail.sent.filter(message => String(message.subject).includes('Unsuccessful')).length, 1);
});

test('public code sending has exclusive auth branches and uniform credential failures before mail availability', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: FACTOR_EMAIL });
  const other = await seedUser(env, { twoFactorEmail: FACTOR_EMAIL });
  const foreign = await createSsoEmail2faSessionToken(env, other);
  const expired = await signHs256Jwt({ iss: 'nodewarden|sso_email_2fa', sub: user.id, email: user.email, exp: Math.floor(Date.now() / 1000) - 1 }, env.JWT_SECRET);
  const noExpiry = await signHs256Jwt({ iss: 'nodewarden|sso_email_2fa', sub: user.id, email: user.email }, env.JWT_SECRET);
  let failure: unknown;
  for (const body of [
    { email: 'unknown@x.io', masterPasswordHash: PASSWORD },
    { email: user.email, masterPasswordHash: 'wrong' },
    { email: user.email, masterPasswordHash: PASSWORD, ssoEmail2FaSessionToken: 123 },
    ...[foreign, expired, noExpiry, 'garbage'].map(ssoEmail2FaSessionToken => ({ email: user.email, masterPasswordHash: PASSWORD, ssoEmail2FaSessionToken })),
    { email: user.email, masterPasswordHash: PASSWORD, authRequestId: 'missing', authRequestAccessCode: 'wrong' },
  ]) {
    const response = await sendLoginCode(env, body);
    assert.equal(response.status, 400);
    const payload = await response.json();
    failure ??= payload;
    assert.deepEqual(payload, failure);
  }
  const disabled = await sendLoginCode(env, { email: user.email, masterPasswordHash: PASSWORD });
  assert.equal(disabled.status, 503);
  const challenge = await passwordLogin(env, user).then(response => response.json() as Promise<{ TwoFactorProviders: string[] }>);
  assert.deepEqual(challenge.TwoFactorProviders, ['1']);
});

test('an approved auth request may send a code only while unconsumed, and invalid access codes never fall through', async () => {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: FACTOR_EMAIL });
  const id = crypto.randomUUID();
  const accessCode = 'approved-device-access';
  await env.DB.prepare(`INSERT INTO auth_requests
    (id,user_id,type,request_device_identifier,request_device_type,access_code,public_key,key,approved,creation_date,response_date)
    VALUES (?,?,0,'approved-device',9,?,'public-key','2.key|key|key',1,?,?)`)
    .bind(id, user.id, accessCode, user.createdAt, user.createdAt).run();
  const body = { email: user.email, authRequestId: id, authRequestAccessCode: accessCode, ssoEmail2FaSessionToken: await createSsoEmail2faSessionToken(env, user), masterPasswordHash: PASSWORD };
  assert.equal((await sendLoginCode(env, { ...body, authRequestAccessCode: 'wrong' })).status, 400);
  assert.equal(mail.sent.length, 0);
  assert.equal((await sendLoginCode(env, body)).status, 200);
  assert.equal(mail.sent.length, 1);
  const code = String(mail.sent[0].text).match(/\b\d{6}\b/)![0];
  const response = await passwordLogin(env, user, { password: accessCode, authRequest: id, twoFactorProvider: '1', twoFactorToken: code });
  assert.equal(response.status, 200);
  assert.equal((await sendLoginCode(env, body)).status, 400);
  await drainWaitUntil();
});

test('password changes invalidate pending login codes and the sixth redemption attempt is refused', async () => {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), twoFactorEmail: FACTOR_EMAIL });
  assert.equal((await sendLoginCode(env, { email: user.email, masterPasswordHash: PASSWORD })).status, 200);
  const oldCode = String(mail.sent[0].text).match(/\b\d{6}\b/)![0];
  const changed = await authedFetch(env, { method: 'POST', path: '/api/accounts/password', userId: user.id, body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: 'new-password-hash', key: user.key } });
  assert.equal(changed.status, 200);
  assert.equal((await passwordLogin(env, user, { password: 'new-password-hash', twoFactorProvider: '1', twoFactorToken: oldCode })).status, 400);
  assert.equal((await sendLoginCode(env, { email: user.email, masterPasswordHash: 'new-password-hash' })).status, 200);
  const latest = mail.sent.filter(message => String(message.subject).includes('sign-in code')).at(-1)!;
  const code = String(latest.text).match(/\b\d{6}\b/)![0];
  const wrong = code === '000000' ? '111111' : '000000';
  for (let attempt = 1; attempt < 5; attempt++) {
    assert.equal((await passwordLogin(env, user, { password: 'new-password-hash', twoFactorProvider: '1', twoFactorToken: wrong })).status, 400);
  }
  assert.equal((await passwordLogin(env, user, { password: 'new-password-hash', twoFactorProvider: '1', twoFactorToken: code })).status, 400);
  await drainWaitUntil();
});
