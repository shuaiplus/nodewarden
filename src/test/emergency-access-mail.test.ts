import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../config/limits';
import * as emergencyRepo from '../services/storage-emergency-repo';
import { EmergencyAccessStatus as Status } from '../services/storage-emergency-repo';
import type { Env, User } from '../types';
import { createEmergencyAccessInviteToken, createRegisterVerifyToken, signHs256Jwt } from '../utils/jwt';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, failingEmail, MAILABLE_DOMAIN, seedUser, type SentEmail } from './support/env';
import * as userRepo from '../services/storage-user-repo';

const { approveExpiredEmergencyAccess, remindPendingEmergencyAccess } = await import('../handlers/emergency-access');

const ENCRYPTED = '2.YQ==|Yg==|Yw==';
const DAY = 86_400_000;

async function setup(overrides: Partial<Env> = {}) {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ...overrides });
  const grantor = await seedUser(env, { email: `grantor-${crypto.randomUUID()}@${MAILABLE_DOMAIN}`, name: '<Grantor> https://x.y @home\r\n\u202E' });
  const grantee = await seedUser(env, { email: `grantee-${crypto.randomUUID()}@${MAILABLE_DOMAIN}` });
  return { env, grantor, grantee, sent: capture.sent };
}

function invite(env: Env, user: User, email: string, waitTimeDays = 7) {
  return authedFetch(env, { method: 'POST', path: '/api/emergency-access/invite', userId: user.id, body: { email, type: 0, waitTimeDays }, headers: { 'X-Forwarded-Host': 'evil.test' } });
}

async function action(env: Env, user: User, id: string, name: string, body: unknown = {}) {
  const response = await authedFetch(env, { method: 'POST', path: `/api/emergency-access/${id}/${name}`, userId: user.id, body });
  await drainWaitUntil();
  return response;
}

function inviteParams(message: SentEmail): URLSearchParams {
  const link = message.text.match(/https:\/\/\S+\/accept-emergency\?\S+/)?.[0];
  assert.ok(link);
  assert.equal(new URL(link).origin, 'https://web.example.test');
  return new URLSearchParams(link.slice(link.indexOf('?') + 1));
}

async function invited(f: Awaited<ReturnType<typeof setup>>) {
  assert.equal((await invite(f.env, f.grantor, f.grantee.email)).status, 200);
  const record = await emergencyRepo.findInvite(f.env.DB, f.grantor.id, f.grantee.email);
  assert.ok(record);
  return record;
}

test('EA invitations remain Invited for existing users and reinvite mails a fresh configured-origin link', async (t) => {
  const f = await setup();
  const record = await invited(f);
  assert.equal(record.status, Status.Invited);
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].to, f.grantee.email);
  const params = inviteParams(f.sent[0]);
  assert.equal(params.get('id'), record.id);
  assert.equal(params.get('name'), f.grantor.name);
  assert.equal(params.get('email'), f.grantor.email);
  assert.match(f.sent[0].html, /&lt;Grantor&gt; x\[dot\]y \[at\]home/);
  assert.doesNotMatch(f.sent[0].subject, /eyJ|[\r\n\u202E]/);
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() + 1000 });
  assert.equal((await action(f.env, f.grantor, record.id, 'reinvite')).status, 200);
  assert.equal(f.sent.length, 2);
  assert.notEqual(inviteParams(f.sent[1]).get('token'), params.get('token'));
});

test('EA invite rejects invalid email, failed delivery and misconfiguration without saving a row', async () => {
  const f = await setup();
  for (const email of ['a@x.io, b@y.io', 'a@x', `${'x'.repeat(260)}@x.io`]) {
    const response = await invite(f.env, f.grantor, email);
    assert.equal(response.status, 400);
    assert.match(await response.text(), /Email is not valid/);
  }
  f.env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
  const failed = await invite(f.env, f.grantor, f.grantee.email);
  assert.equal(failed.status, 502);
  assert.doesNotMatch(await failed.text(), new RegExp(`${f.grantee.email}|E_RECIPIENT`));
  f.env.EMAIL_FROM = 'invalid';
  assert.equal((await invite(f.env, f.grantor, f.grantee.email)).status, 503);
  assert.deepEqual(await emergencyRepo.listByGrantor(f.env.DB, f.grantor.id), []);
});

test('EA invitations spend one grantor budget across recipients', async () => {
  const f = await setup();
  for (let i = 0; i < LIMITS.mail.emergencyAccessInvitesPerGrantorPerHour; i++) {
    assert.equal((await invite(f.env, f.grantor, `invite-${i}@${MAILABLE_DOMAIN}`)).status, 200);
  }
  const blocked = await invite(f.env, f.grantor, f.grantee.email);
  assert.equal(blocked.status, 429);
  assert.ok(Number(blocked.headers.get('Retry-After')) > 0);
  assert.equal(await emergencyRepo.findInvite(f.env.DB, f.grantor.id, f.grantee.email), null);
});

test('EA accept requires the unexpired dedicated token bound to this record and email', async () => {
  const f = await setup();
  const record = await invited(f);
  const invalid = [
    '',
    await createRegisterVerifyToken(f.env.JWT_SECRET, f.grantee.email, null),
    await createEmergencyAccessInviteToken(f.env.JWT_SECRET, crypto.randomUUID(), f.grantee.email),
    await createEmergencyAccessInviteToken(f.env.JWT_SECRET, record.id, f.grantor.email),
    await signHs256Jwt({ iss: 'nodewarden|emergency_access_invite', sub: record.id, email: f.grantee.email, exp: Math.floor(Date.now() / 1000) - 1 }, f.env.JWT_SECRET),
  ];
  for (const token of invalid) {
    assert.equal((await action(f.env, f.grantee, record.id, 'accept', { token })).status, 400);
    assert.equal((await emergencyRepo.getEmergencyAccess(f.env.DB, record.id))?.status, Status.Invited);
  }
  const token = inviteParams(f.sent[0]).get('token');
  assert.equal((await action(f.env, f.grantee, record.id, 'accept', { token })).status, 200);
  assert.equal((await emergencyRepo.getEmergencyAccess(f.env.DB, record.id))?.status, Status.Accepted);
  assert.equal((await action(f.env, f.grantee, record.id, 'accept', { token })).status, 400);
});

test('EA finish-signup still needs open registration and leaves the invitation pending acceptance', async () => {
  const f = await setup();
  const email = `new-${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  assert.equal((await invite(f.env, f.grantor, email)).status, 200);
  const params = inviteParams(f.sent[0]);
  const id = params.get('id')!;
  const token = params.get('token');
  const body = { email, masterPasswordHash: 'master-password-hash', key: ENCRYPTED, encryptedPrivateKey: ENCRYPTED, publicKey: 'YQ==', acceptEmergencyAccessInviteToken: token, acceptEmergencyAccessId: id };
  const finish = () => authedFetch(f.env, { method: 'POST', path: '/identity/accounts/register/finish', body });
  assert.equal((await finish()).status, 403);
  f.env.ALLOW_OPEN_REGISTRATION = '1';
  assert.equal((await finish()).status, 200);
  assert.equal((await emergencyRepo.getEmergencyAccess(f.env.DB, id))?.status, Status.Invited);
  const user = await userRepo.getUser(f.env.DB, email);
  assert.ok(user);
  assert.equal((await action(f.env, user, id, 'accept', { token })).status, 200);
});

test('EA no-mail or no-vault-origin fallback still auto-accepts existing users', async () => {
  for (const overrides of [{ EMAIL: undefined }, { WEB_VAULT_ORIGINS: undefined }]) {
    const f = await setup(overrides);
    assert.equal((await invite(f.env, f.grantor, f.grantee.email)).status, 200);
    assert.equal((await emergencyRepo.findInvite(f.env.DB, f.grantor.id, f.grantee.email))?.status, Status.Accepted);
    assert.equal(f.sent.length, 0);
  }
});

test('EA transitions mail each affected party once and sanitize names with an email fallback', async () => {
  const f = await setup();
  await userRepo.saveUser(f.env.DB, { ...f.grantee, name: null });
  const record = await invited(f);
  const token = inviteParams(f.sent[0]).get('token');
  f.sent.length = 0;
  assert.equal((await action(f.env, f.grantee, record.id, 'accept', { token })).status, 200);
  assert.equal(f.sent[0].to, f.grantor.email);
  assert.match(f.sent[0].text, /grantee-.*\[at\]stevefan1999\[dot\]tech accepted/);
  assert.equal((await action(f.env, f.grantor, record.id, 'confirm', { key: ENCRYPTED })).status, 200);
  assert.equal(f.sent[1].to, f.grantee.email);
  assert.match(f.sent[1].html, /&lt;Grantor&gt; x\[dot\]y \[at\]home/);
  assert.equal((await action(f.env, f.grantee, record.id, 'initiate')).status, 200);
  assert.equal(f.sent[2].to, f.grantor.email);
  assert.match(f.sent[2].text, /view your vault/);
  assert.match(f.sent[2].text, /7 days/);
  assert.equal((await action(f.env, f.grantor, record.id, 'approve')).status, 200);
  assert.equal(f.sent[3].to, f.grantee.email);
  assert.equal((await action(f.env, f.grantor, record.id, 'reject')).status, 200);
  assert.equal(f.sent[4].to, f.grantee.email);
  assert.deepEqual(f.sent.map((mail) => mail.subject), [
    'Emergency contact accepted your invitation', 'Emergency access confirmed', 'Emergency access requested',
    'Emergency access approved', 'Emergency access request rejected',
  ]);
  for (const [user, name] of [[f.grantee, 'confirm'], [f.grantor, 'initiate'], [f.grantor, 'approve'], [f.grantor, 'reject']] as const) {
    assert.equal((await action(f.env, user, record.id, name, { key: ENCRYPTED })).status, 400);
  }
  assert.equal(f.sent.length, 5);
});

async function confirmed(f: Awaited<ReturnType<typeof setup>>, waitTimeDays = 7) {
  const now = new Date().toISOString();
  const record: emergencyRepo.EmergencyAccessRecord = {
    id: crypto.randomUUID(), grantorId: f.grantor.id, granteeId: f.grantee.id, email: null,
    keyEncrypted: ENCRYPTED, type: 1, status: Status.Confirmed, waitTimeDays,
    recoveryInitiatedAt: null, lastNotificationAt: null, createdAt: now, updatedAt: now,
  };
  await emergencyRepo.saveEmergencyAccess(f.env.DB, record);
  return record;
}

test('EA wait-zero initiation sends Initiated to the grantor and Approved to the grantee', async () => {
  const f = await setup();
  const record = await confirmed(f, 0);
  assert.equal((await action(f.env, f.grantee, record.id, 'initiate')).status, 200);
  assert.deepEqual(f.sent.map(({ to, subject }) => [to, subject]), [
    [f.grantor.email, 'Emergency access requested'], [f.grantee.email, 'Emergency access approved'],
  ]);
  assert.match(f.sent[0].text, /take over your account/);
});

test('EA timeout approval mails TimedOut to the grantor and Approved to the grantee', async () => {
  const f = await setup();
  const record = await confirmed(f);
  await emergencyRepo.saveEmergencyAccess(f.env.DB, { ...record, status: Status.RecoveryInitiated, recoveryInitiatedAt: new Date(Date.now() - 8 * DAY).toISOString() });
  await approveExpiredEmergencyAccess(f.env);
  assert.equal((await emergencyRepo.getEmergencyAccess(f.env.DB, record.id))?.status, Status.RecoveryApproved);
  assert.deepEqual(f.sent.map(({ to, subject }) => [to, subject]), [
    [f.grantor.email, 'Emergency access waiting period ended'], [f.grantee.email, 'Emergency access approved'],
  ]);
  await approveExpiredEmergencyAccess(f.env);
  assert.equal(f.sent.length, 2);
});

test('EA notice delivery failure does not roll back a valid transition', async () => {
  const f = await setup();
  const record = await confirmed(f);
  f.env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
  assert.equal((await action(f.env, f.grantee, record.id, 'initiate')).status, 200);
  assert.equal((await emergencyRepo.getEmergencyAccess(f.env.DB, record.id))?.status, Status.RecoveryInitiated);
});

test('EA reminder sends once on the final day, even with overlapping cron runs', async (t) => {
  const f = await setup();
  const record = await confirmed(f);
  const started = Date.now();
  t.mock.timers.enable({ apis: ['Date'], now: started });
  await emergencyRepo.saveEmergencyAccess(f.env.DB, {
    ...record, status: Status.RecoveryInitiated, recoveryInitiatedAt: new Date(started).toISOString(), lastNotificationAt: new Date(started).toISOString(),
  });
  for (let day = 1; day <= 5; day++) {
    t.mock.timers.tick(DAY);
    await remindPendingEmergencyAccess(f.env);
    assert.equal(f.sent.length, 0, `no reminder on day ${day}`);
  }
  t.mock.timers.tick(DAY);
  await Promise.all([remindPendingEmergencyAccess(f.env), remindPendingEmergencyAccess(f.env)]);
  assert.equal(f.sent.length, 1);
  assert.equal(f.sent[0].to, f.grantor.email);
  assert.match(f.sent[0].text, /in 1 day/);
  await remindPendingEmergencyAccess(f.env);
  assert.equal(f.sent.length, 1);
  t.mock.timers.tick(DAY);
  await remindPendingEmergencyAccess(f.env);
  assert.equal(f.sent.length, 1, 'expired recovery is handled by timeout approval, not another reminder');
});

test('EA reminders skip other statuses, missing notification dates and newly notified requests', async () => {
  const f = await setup();
  const record = await confirmed(f);
  const started = new Date(Date.now() - 6 * DAY).toISOString();
  for (const [status, lastNotificationAt] of [
    [Status.Confirmed, started], [Status.RecoveryApproved, started],
    [Status.RecoveryInitiated, null], [Status.RecoveryInitiated, new Date().toISOString()],
  ] as const) {
    await emergencyRepo.saveEmergencyAccess(f.env.DB, { ...record, status, recoveryInitiatedAt: started, lastNotificationAt });
    await remindPendingEmergencyAccess(f.env);
  }
  assert.equal(f.sent.length, 0);
});
