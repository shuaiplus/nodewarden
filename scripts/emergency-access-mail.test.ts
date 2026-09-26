import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../src/config/limits';
import { StorageService } from '../src/services/storage';
import * as emergencyRepo from '../src/services/storage-emergency-repo';
import { EmergencyAccessStatus as Status } from '../src/services/storage-emergency-repo';
import type { Env, User } from '../src/types';
import { createEmergencyAccessInviteToken, createRegisterVerifyToken, signHs256Jwt } from '../src/utils/jwt';
import { authedFetch, captureEmail, createTestEnv, failingEmail, MAILABLE_DOMAIN, seedUser, type SentEmail } from './support/env';

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

function action(env: Env, user: User, id: string, name: string, body: unknown = {}) {
  return authedFetch(env, { method: 'POST', path: `/api/emergency-access/${id}/${name}`, userId: user.id, body });
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
  const user = await new StorageService(f.env.DB).getUser(email);
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
