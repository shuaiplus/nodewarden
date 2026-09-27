import assert from 'node:assert/strict';
import test from 'node:test';
import { EventType } from '../src/services/events';
import { EMPTY_PERMISSIONS, MembershipStatus, MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
const { createOwnedOrganization } = await import('../src/handlers/organizations');

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const ORG_KEY = '4.dGVzdA==';
type EventRow = { type: number; sendId: string | null; actingUserId: string | null; userId: string | null; organizationId: string | null };

async function setup() {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const org = await createOwnedOrganization(env, owner, { name: 'Send audit', key: ORG_KEY });
  await env.DB.prepare('DELETE FROM events').run();
  const call = (method: string, path: string, body?: unknown, userId: string | undefined = owner.id) =>
    authedFetch(env, { method, path, body, userId, headers: { 'Device-Type': '8' } });
  const deletionDate = new Date(Date.now() + 86_400_000).toISOString();
  const textSend = { type: 0, name: ENCRYPTED, key: ENCRYPTED, deletionDate, text: { text: ENCRYPTED, hidden: false } };
  return { env, owner, org, call, deletionDate, textSend };
}

async function list(call: (method: string, path: string) => Promise<Response>, path: string): Promise<EventRow[]> {
  const response = await call('GET', path);
  assert.equal(response.status, 200, path);
  return (await response.json() as { data: EventRow[] }).data;
}

async function member(env: Env, orgId: string, user: User, accessEventLogs: boolean): Promise<void> {
  const now = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, { id: crypto.randomUUID(), orgId, userId: user.id, email: user.email, invitedByEmail: null,
    status: MembershipStatus.Confirmed, type: MembershipType.Custom, accessAll: false, key: ORG_KEY,
    permissions: { ...EMPTY_PERMISSIONS, accessEventLogs }, resetPasswordKey: null, externalId: null, createdAt: now, updatedAt: now });
}

test('Send create, edit and delete reach the personal log and every confirmed organization of the owner', async () => {
  const { env, owner, org, call, deletionDate, textSend } = await setup();
  const created = await call('POST', '/api/sends', { ...textSend, password: 'correct horse battery' });
  assert.equal(created.status, 200);
  const { id } = await created.json() as { id: string };
  assert.equal((await call('PUT', `/api/sends/${id}`, textSend)).status, 200);
  assert.equal((await call('PUT', `/api/sends/${id}/remove-password`)).status, 200);
  assert.equal((await call('DELETE', `/api/sends/${id}`)).status, 200);
  const file = await call('POST', '/api/sends/file/v2', { type: 1, name: ENCRYPTED, key: ENCRYPTED, deletionDate, file: { fileName: ENCRYPTED }, fileLength: 4 });
  assert.equal(file.status, 200);
  const { sendResponse: { id: fileId } } = await file.json() as { sendResponse: { id: string } };

  const history = await list(call, `/api/organizations/${org.id}/sends/${id}/events`);
  assert.deepEqual(history.map(row => row.type).sort(), [EventType.SendCreatedTextWithPasswordProtection, EventType.SendEditedText, EventType.SendEditedText, EventType.SendDeletedText].sort());
  assert.ok(history.every(row => row.sendId === id && row.organizationId === org.id && row.actingUserId === owner.id && row.userId === owner.id));
  assert.deepEqual((await list(call, `/api/organizations/${org.id}/sends/${fileId}/events`)).map(row => row.type), [EventType.SendCreatedFile]);
  const personal = await list(call, '/api/events');
  assert.equal(personal.filter(row => row.sendId === id).length, 4);
  assert.ok(personal.every(row => row.organizationId === null));
  const stored = JSON.stringify((await env.DB.prepare('SELECT * FROM events').all()).results);
  assert.ok(!stored.includes(ENCRYPTED) && !stored.includes('correct horse'));
});

test('an external Send access is attributed to nobody in the organization and the route stays gated', async () => {
  const { env, owner, org, call, textSend } = await setup();
  const created = await call('POST', '/api/sends', textSend);
  const { id, accessId } = await created.json() as { id: string; accessId: string };
  assert.equal((await call('POST', `/api/sends/access/${accessId}`, {}, undefined)).status, 200);
  const rows = await env.DB.prepare('SELECT organization_id, acting_user_id, user_id FROM events WHERE type = ?').bind(EventType.SendAccessedText)
    .all<{ organization_id: string | null; acting_user_id: string | null; user_id: string }>();
  assert.deepEqual(rows.results.map(row => [row.organization_id, row.acting_user_id, row.user_id]).sort(),
    [[null, owner.id, owner.id], [org.id, null, owner.id]].sort());

  const reader = await seedUser(env);
  await member(env, org.id, reader, false);
  const outsider = await seedUser(env);
  for (const userId of [reader.id, outsider.id]) {
    assert.equal((await call('GET', `/api/organizations/${org.id}/sends/${id}/events`, undefined, userId)).status, 404);
  }
  const auditor = await seedUser(env);
  await member(env, org.id, auditor, true);
  assert.ok((await (await call('GET', `/api/organizations/${org.id}/sends/${id}/events`, undefined, auditor.id)).json() as { data: EventRow[] })
    .data.some(row => row.type === EventType.SendAccessedText));
  const outsiderSend = await call('POST', '/api/sends', textSend, outsider.id);
  assert.equal(outsiderSend.status, 200);
  const count = await env.DB.prepare('SELECT count(*) AS n FROM events WHERE organization_id = ? AND type = ?').bind(org.id, EventType.SendCreatedText).first<number>('n');
  assert.equal(count, 1, "a non-member's Send never reaches the organization log");
});
