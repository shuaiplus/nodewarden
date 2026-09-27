import assert from 'node:assert/strict';
import test from 'node:test';
import { EventType } from '../src/services/events';
import { MembershipType } from '../src/services/org-types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMember } from './support/sm';
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

  const { user: reader } = await seedMember(env, org.id, { type: MembershipType.Custom, permissions: { accessEventLogs: false } });
  const outsider = await seedUser(env);
  for (const userId of [reader.id, outsider.id]) {
    assert.equal((await call('GET', `/api/organizations/${org.id}/sends/${id}/events`, undefined, userId)).status, 404);
  }
  const { user: auditor } = await seedMember(env, org.id, { type: MembershipType.Custom, permissions: { accessEventLogs: true } });
  assert.ok((await (await call('GET', `/api/organizations/${org.id}/sends/${id}/events`, undefined, auditor.id)).json() as { data: EventRow[] })
    .data.some(row => row.type === EventType.SendAccessedText));
  const outsiderSend = await call('POST', '/api/sends', textSend, outsider.id);
  assert.equal(outsiderSend.status, 200);
  const count = await env.DB.prepare('SELECT count(*) AS n FROM events WHERE organization_id = ? AND type = ?').bind(org.id, EventType.SendCreatedText).first<number>('n');
  assert.equal(count, 1, "a non-member's Send never reaches the organization log");
});

test('bulk Send deletion records every Send with one membership read and one insert statement', async (t) => {
  const { env, org, call, textSend } = await setup();
  const ids: string[] = [];
  for (let created = 0; created < 3; created++) ids.push((await (await call('POST', '/api/sends', textSend)).json() as { id: string }).id);
  await env.DB.prepare('DELETE FROM events').run();
  const prepare = env.DB.prepare.bind(env.DB);
  const statements: string[] = [];
  t.mock.method(env.DB, 'prepare', (query: string) => { statements.push(query); return prepare(query); });
  assert.equal((await call('POST', '/api/sends/delete', { ids })).status, 200);
  t.mock.restoreAll();
  assert.equal(statements.filter(query => /from "organization_memberships"/i.test(query)).length, 1);
  assert.equal(statements.filter(query => /insert into "events"/i.test(query)).length, 1, 'six rows fit one statement under the parameter cap');
  const rows = await env.DB.prepare('SELECT organization_id, resource_id FROM events WHERE type = ?').bind(EventType.SendDeletedText)
    .all<{ organization_id: string | null; resource_id: string }>();
  assert.deepEqual(rows.results.map(row => `${row.organization_id ?? 'personal'}:${row.resource_id}`).sort(),
    ids.flatMap(id => [`personal:${id}`, `${org.id}:${id}`]).sort());
});
