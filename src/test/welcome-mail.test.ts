import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env } from '../types';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, failingEmail, MAILABLE_DOMAIN, seedUser } from './support/env';
import * as adminRepo from '../services/storage-admin-repo';
import * as userRepo from '../services/storage-user-repo';

const ENCRYPTED = '2.YQ==|Yg==|Yw==';

async function register(env: Env, email: string, extra: Record<string, unknown> = {}, path = '/identity/accounts/register/finish') {
  const response = await authedFetch(env, {
    method: 'POST', path,
    body: { email, name: '<New> https://x.y @home', masterPasswordHash: 'master-password-hash', key: ENCRYPTED, encryptedPrivateKey: ENCRYPTED, publicKey: 'YQ==', ...extra },
  });
  await drainWaitUntil();
  return response;
}

test('first administrator, invite-code signup and open signup each receive one welcome mail', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const firstEmail = `first@${MAILABLE_DOMAIN}`;
  const first = await register(env, firstEmail);
  assert.equal(first.status, 200);
  assert.equal((await first.json() as { role: string }).role, 'admin');
  const admin = await userRepo.getUser(env.DB, firstEmail);
  assert.ok(admin);
  await adminRepo.createInvite(env.DB, { code: 'welcome-invite', createdBy: admin.id, usedBy: null, status: 'active', createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
  const invitedEmail = `invited@${MAILABLE_DOMAIN}`;
  assert.equal((await register(env, invitedEmail, { inviteCode: 'welcome-invite' }, '/api/accounts/register')).status, 200);
  env.ALLOW_OPEN_REGISTRATION = '1';
  const openEmail = `open@${MAILABLE_DOMAIN}`;
  assert.equal((await register(env, openEmail)).status, 200);
  assert.deepEqual(capture.sent.map(({ to, subject }) => [to, subject]), [firstEmail, invitedEmail, openEmail].map((email) => [email, 'Welcome to NodeWarden']));
  for (const mail of capture.sent) {
    assert.match(mail.html, /&lt;New&gt; x\[dot\]y \[at\]home/);
    assert.match(mail.text, /https:\/\/web.example.test\//);
    assert.doesNotMatch(mail.text, /master-password-hash/);
  }

});

test('duplicate email, invalid invite and documentation addresses send no welcome mail', async () => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ALLOW_OPEN_REGISTRATION: '1' });
  const existing = await seedUser(env, { email: `existing@${MAILABLE_DOMAIN}` });
  assert.equal((await register(env, existing.email)).status, 409);
  assert.equal((await register(env, `invalid@${MAILABLE_DOMAIN}`, { inviteCode: 'invalid' })).status, 403);
  assert.equal((await register(env, 'reserved@example.test')).status, 200);
  assert.equal(capture.sent.length, 0);
});

test('welcome mail delivery failure or missing vault origin leaves account creation successful', async () => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, EMAIL: failingEmail('E_RECIPIENT_SUPPRESSED'), ALLOW_OPEN_REGISTRATION: '1' });
  const email = `failure@${MAILABLE_DOMAIN}`;
  assert.equal((await register(env, email)).status, 200);
  assert.ok(await userRepo.getUser(env.DB, email));
  env.EMAIL = capture.overrides.EMAIL;
  env.WEB_VAULT_ORIGINS = undefined;
  assert.equal((await register(env, `no-origin@${MAILABLE_DOMAIN}`)).status, 200);
  assert.equal(capture.sent.length, 1);
  assert.doesNotMatch(capture.sent[0].html, /<a /);
});
