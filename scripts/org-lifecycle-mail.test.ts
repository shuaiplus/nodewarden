import assert from 'node:assert/strict';
import test from 'node:test';

import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { createOrgInviteToken } from '../src/utils/jwt';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, failingEmail, MAILABLE_DOMAIN, seedUser } from './support/env';

const { createOwnedOrganization } = await import('../src/handlers/organizations');
const KEY = '4.dGVzdA==';

async function setup() {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env, { email: `owner-${crypto.randomUUID()}@${MAILABLE_DOMAIN}` });
  const org = await createOwnedOrganization(env, owner, { name: '<Org> https://x.y @home', key: KEY });
  return { env, owner, org, sent: capture.sent };
}

async function member(env: Env, orgId: string, type: number, status: number) {
  const user = await seedUser(env, { email: `member-${crypto.randomUUID()}@${MAILABLE_DOMAIN}` });
  const now = new Date().toISOString();
  const record = {
    id: crypto.randomUUID(), orgId, userId: status === 0 ? null : user.id,
    email: user.email, invitedByEmail: null, status, type, accessAll: true, key: KEY,
    permissions: null, resetPasswordKey: null, externalId: null, createdAt: now, updatedAt: now,
  };
  await orgRepo.saveMembership(env.DB, record);
  return { user, record };
}

async function post(env: Env, user: User, orgId: string, suffix: string, body: unknown) {
  const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${suffix}`, userId: user.id, body });
  await drainWaitUntil();
  return response;
}

test('organization acceptance mails each other confirmed Owner and Admin only', async () => {
  const f = await setup();
  const admin = await member(f.env, f.org.id, 1, 2);
  const anotherOwner = await member(f.env, f.org.id, 0, 2);
  await member(f.env, f.org.id, 1, 0);
  await member(f.env, f.org.id, 2, 2);
  const acceptingOwner = await member(f.env, f.org.id, 0, 0);
  const token = await createOrgInviteToken(f.env.JWT_SECRET, acceptingOwner.record.id, acceptingOwner.user.email);

  assert.equal((await post(f.env, acceptingOwner.user, f.org.id, `${acceptingOwner.record.id}/accept`, { token })).status, 200);
  assert.deepEqual(f.sent.map(({ to }) => to).sort(), [f.owner.email, admin.user.email, anotherOwner.user.email].sort());
  for (const mail of f.sent) {
    assert.equal(mail.subject, 'Organization invitation accepted');
    assert.match(mail.html, /&lt;Org&gt; x\[dot\]y \[at\]home/);
  }
});

test('organization confirmation and bulk confirmation mail only members who succeeded', async () => {
  const f = await setup();
  const single = await member(f.env, f.org.id, 2, 1);
  assert.equal((await post(f.env, f.owner, f.org.id, `${single.record.id}/confirm`, { key: KEY })).status, 200);
  assert.deepEqual(f.sent.map(({ to }) => to), [single.user.email]);
  assert.match(f.sent[0].text, /https:\/\/web.example.test\//);

  const accepted = await member(f.env, f.org.id, 2, 1);
  const invited = await member(f.env, f.org.id, 2, 0);
  const invalidKey = await member(f.env, f.org.id, 2, 1);
  const response = await post(f.env, f.owner, f.org.id, 'confirm', { keys: [
    { id: accepted.record.id, key: KEY }, { id: invited.record.id, key: KEY },
    { id: invalidKey.record.id, key: 'invalid' }, { id: crypto.randomUUID(), key: KEY },
  ] });
  assert.equal(response.status, 200);
  assert.deepEqual(f.sent.map(({ to }) => to), [single.user.email, accepted.user.email]);
  assert.ok(f.sent.every(({ subject }) => subject === 'Organization membership confirmed'));
});

test('organization notices failing delivery leave acceptance and confirmation successful', async () => {
  const f = await setup();
  const invited = await member(f.env, f.org.id, 2, 0);
  f.env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
  const token = await createOrgInviteToken(f.env.JWT_SECRET, invited.record.id, invited.user.email);
  assert.equal((await post(f.env, invited.user, f.org.id, `${invited.record.id}/accept`, { token })).status, 200);
  assert.equal((await orgRepo.getMembership(f.env.DB, invited.record.id))?.status, 1);
  assert.equal((await post(f.env, f.owner, f.org.id, `${invited.record.id}/confirm`, { key: KEY })).status, 200);
  assert.equal((await orgRepo.getMembership(f.env.DB, invited.record.id))?.status, 2);
});
