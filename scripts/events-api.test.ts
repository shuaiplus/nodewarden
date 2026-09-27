import assert from 'node:assert/strict';
import test from 'node:test';
import { createTestEnv, authedFetch, seedUser } from './support/env';
import { EventType, recordEvents, pruneEvents } from '../src/services/events';
import { StorageService } from '../src/services/storage';
import { saveAuditLogSettings } from '../src/services/audit-events';
import { EMPTY_PERMISSIONS } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
const { createOwnedOrganization } = await import('../src/handlers/organizations');
const ENC = '2.dGVzdA==|dGVzdA==|dGVzdA==';

async function setup() {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const org = await createOwnedOrganization(env, owner, { name: 'Event test', key: '4.dGVzdA==' });
  await env.DB.prepare('DELETE FROM events').run();
  return { env, owner, org };
}
async function member(env: Env, orgId: string, user: User, accessEventLogs: boolean) {
  const id = crypto.randomUUID();
  await orgRepo.saveMembership(env.DB, { id, orgId, userId: user.id, email: user.email, invitedByEmail: null, status: 2, type: 4, accessAll: false, key: '4.dGVzdA==', permissions: { ...EMPTY_PERMISSIONS, accessEventLogs }, resetPasswordKey: null, externalId: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  return id;
}
async function cipher(env: Env, owner: User, orgId: string | null) {
  const id = crypto.randomUUID();
  await new StorageService(env.DB).saveCipher({ id, userId: owner.id, organizationId: orgId, type: 1, folderId: null, name: ENC, notes: null, favorite: false, data: '{}', key: null, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(), deletedAt: null });
  return id;
}
const count = (env: Env) => env.DB.prepare('SELECT count(*) AS n FROM events').first<number>('n');
type EventRow = { type: number; date: string; actingUserId: string | null; userId: string | null; organizationId: string | null; cipherId: string | null; ipAddress: string | null; deviceType: number | null };
type EventPage = { data: EventRow[]; continuationToken: string | null; object: string };

test('event queries page equal timestamps without loss and validate dates and URL-safe cursors', async () => {
  const { env, owner, org } = await setup();
  const date = new Date().toISOString();
  const resources = Array.from({ length: 63 }, () => crypto.randomUUID());
  await recordEvents(env, new Request('https://vault.test', { headers: { 'CF-Connecting-IP': '203.0.113.77', 'Device-Type': '9' } }), { userId: owner.id }, resources.map(resourceId => ({ type: EventType.CipherCreated, organizationId: org.id, resourceType: 'cipher', resourceId, date })));
  const path = `/api/organizations/${org.id}/events`;
  const first = await authedFetch(env, { path, userId: owner.id });
  assert.equal(first.status, 200);
  const page1 = await first.json() as EventPage;
  assert.equal(page1.object, 'list'); assert.equal(page1.data.length, 50); assert.match(page1.continuationToken!, /^[A-Za-z0-9_-]+$/);
  assert.equal(page1.data[0].ipAddress, '203.0.113.77'); assert.equal(page1.data[0].deviceType, 9);
  const page2 = await (await authedFetch(env, { path: `${path}?continuationToken=${page1.continuationToken}`, userId: owner.id })).json() as EventPage;
  assert.equal(page2.data.length, 13); assert.equal(page2.continuationToken, null);
  assert.deepEqual(new Set([...page1.data, ...page2.data].map(event => event.cipherId)), new Set(resources));
  for (const query of ['start=bad', 'start=2020-01-01&end=2026-01-01', 'continuationToken=bad!', 'continuationToken=W10']) assert.equal((await authedFetch(env, { path: `${path}?${query}`, userId: owner.id })).status, 400, query);
  const yesterday = new Date(Date.now() - 86_400_000).toISOString();
  const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
  assert.equal(((await (await authedFetch(env, { path: `${path}?start=${tomorrow}&end=${yesterday}`, userId: owner.id })).json()) as EventPage).data.length, 50);
});

test('event scope is immutable across moves/deletion; membership filters use the actor and permissions remain tenant-bound', async () => {
  const { env, owner, org } = await setup();
  const otherOwner = await seedUser(env);
  const other = await createOwnedOrganization(env, otherOwner, { name: 'Other', key: '4.dGVzdA==' });
  const actor = await seedUser(env);
  const actorMembership = await member(env, org.id, actor, true);
  const ordinary = await seedUser(env);
  await member(env, org.id, ordinary, false);
  const id = await cipher(env, owner, org.id);
  await env.DB.prepare('DELETE FROM events').run();
  await recordEvents(env, null, { userId: actor.id }, [{ type: 1100, organizationId: org.id, resourceType: 'cipher', resourceId: id }]);
  await recordEvents(env, null, { userId: owner.id }, [{ type: 1500, organizationId: org.id, resourceType: 'organizationUser', resourceId: actorMembership, userId: actor.id }]);
  const memberEvents = await (await authedFetch(env, { path: `/api/organizations/${org.id}/users/${actorMembership}/events`, userId: owner.id })).json() as EventPage;
  assert.deepEqual(memberEvents.data.map(event => event.type), [1100]);
  assert.equal((await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: actor.id })).status, 200, 'event permission is independent of vault-item read permission');
  assert.equal((await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: ordinary.id })).status, 404);
  assert.equal((await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: otherOwner.id })).status, 404);
  await env.DB.prepare('UPDATE ciphers SET organization_id=? WHERE id=?').bind(other.id, id).run();
  assert.equal((await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: actor.id })).status, 404);
  const moved = await (await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: otherOwner.id })).json() as EventPage;
  assert.equal(moved.data.length, 0, 'new owner does not inherit previous organization history');
  await env.DB.prepare('DELETE FROM ciphers WHERE id=?').bind(id).run();
  await env.DB.prepare('DELETE FROM users WHERE id=?').bind(actor.id).run();
  const history = await (await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: owner.id })).json() as EventPage;
  assert.equal(history.data.find(event => event.type === 1100)?.actingUserId, actor.id);
  assert.equal(history.data.find(event => event.type === 1100)?.cipherId, id);
  await orgRepo.deleteOrganization(env.DB, org.id);
  assert.equal(await count(env), 0, 'organization deletion removes its event scope');
});

test('collector records authorized client actions, derives actor/scope and hides unknown versus foreign IDs', async () => {
  const { env, owner, org } = await setup();
  const otherOwner = await seedUser(env);
  const other = await createOwnedOrganization(env, otherOwner, { name: 'Other', key: '4.dGVzdA==' });
  const id = await cipher(env, owner, org.id);
  const foreign = await cipher(env, otherOwner, other.id);
  const personal = await cipher(env, owner, null);
  await env.DB.prepare('DELETE FROM events').run();
  const date = new Date().toISOString();
  const post = (body: unknown, userId = owner.id) => authedFetch(env, { method: 'POST', path: '/events/collect', userId, body, headers: { 'CF-Connecting-IP': '203.0.113.77', 'Device-Type': '9' } });
  assert.equal((await post([{ type: 1107, cipherId: id, date, actingUserId: otherOwner.id, ipAddress: 'FAKE', name: 'PLAINTEXT MUST NOT STORE' }])).status, 200);
  const row = await env.DB.prepare('SELECT * FROM events').first<Record<string, unknown>>();
  assert.equal(row?.organization_id, org.id); assert.equal(row?.acting_user_id, owner.id); assert.equal(row?.ip_address, '203.0.113.77');
  assert.ok(!JSON.stringify(row).includes('PLAINTEXT'));
  for (const entry of [{ type: 1100, cipherId: id }, { type: 1107, cipherId: foreign }, { type: 1107, cipherId: crypto.randomUUID() }, { type: 1107, cipherId: personal }, { type: 1107, cipherId: id, organizationId: other.id }]) {
    const response = await post([{ ...entry, date }]); assert.equal(response.status, 200); assert.equal(await response.text(), '');
  }
  assert.equal(await count(env), 1);
  const reader = await seedUser(env); await member(env, org.id, reader, true);
  assert.equal((await post([{ type: 1107, cipherId: id, date }], reader.id)).status, 200);
  assert.equal(await count(env), 1, 'log readers cannot claim actions on inaccessible ciphers');
  assert.equal((await post(Array.from({ length: 100 }, () => ({ type: 1111, cipherId: id, date })))).status, 200);
  assert.equal(await count(env), 101);
  for (const body of [[], Array.from({ length: 101 }, () => ({ type: 1107, cipherId: id, date })), [{ type: 1107, cipherId: id, date: 'bad' }]]) assert.equal((await post(body)).status, 400);
});

test('event cleanup reuses audit retention and deletes at most 1000 rows using receipt time', async () => {
  const { env, owner, org } = await setup();
  await recordEvents(env, null, { userId: owner.id }, Array.from({ length: 1005 }, () => ({ type: 1600, organizationId: org.id, date: '2099-01-01T00:00:00.000Z' })));
  await env.DB.prepare("UPDATE events SET recorded_at='2000-01-01T00:00:00.000Z'").run();
  await pruneEvents(env); assert.equal(await count(env), 5);
  await pruneEvents(env); assert.equal(await count(env), 0);
});

test('a row-cap audit setting never lets one account flood out another organization history', async () => {
  const { env, owner, org } = await setup();
  const storage = new StorageService(env.DB);
  const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  await recordEvents(env, null, { userId: owner.id }, Array.from({ length: 5 }, () => ({ type: 1600, organizationId: org.id })));
  await env.DB.prepare('UPDATE events SET recorded_at=?').bind(daysAgo(10)).run();
  const outsider = await seedUser(env);
  await recordEvents(env, null, { userId: outsider.id }, Array.from({ length: 1005 }, () => ({ type: EventType.UserClientExportedVault, organizationId: null, userId: outsider.id })));
  await saveAuditLogSettings(storage, { retentionDays: null, maxEntries: 1000 });
  await pruneEvents(env);
  assert.equal(await count(env), 1010, 'recent rows are kept whatever their volume');
  await env.DB.prepare('UPDATE events SET recorded_at=? WHERE organization_id=?').bind(daysAgo(91), org.id).run();
  await pruneEvents(env);
  assert.equal(await count(env), 1005, 'row-cap mode still expires events at the default retention age');
  await saveAuditLogSettings(storage, { retentionDays: null, maxEntries: null });
  await env.DB.prepare('UPDATE events SET recorded_at=?').bind(daysAgo(4000)).run();
  await pruneEvents(env);
  assert.equal(await count(env), 1005, 'disabled retention keeps every event');
});

test('committed server changes survive event-store failure, while client uploads remain retryable', async (t) => {
  t.mock.method(console, 'error', () => {});
  const { env, owner, org } = await setup();
  const id = await cipher(env, owner, org.id);
  const prepare = env.DB.prepare.bind(env.DB);
  t.mock.method(env.DB, 'prepare', (query: string) => {
    if (/insert into "events"/i.test(query)) throw new Error('Event storage unavailable');
    return prepare(query);
  });
  const password = await authedFetch(env, { method: 'POST', path: '/api/accounts/password', userId: owner.id,
    body: { masterPasswordHash: owner.masterPasswordHash, newMasterPasswordHash: 'replacement-password', key: ENC } });
  assert.equal(password.status, 200);
  const deleted = await authedFetch(env, { method: 'DELETE', path: `/api/ciphers/${id}`, userId: owner.id });
  assert.equal(deleted.status, 200);
  assert.ok((await new StorageService(env.DB).getCipher(id))?.deletedAt);
  const collected = await authedFetch(env, { method: 'POST', path: '/events/collect', userId: owner.id,
    body: [{ type: 1007, date: new Date().toISOString() }] });
  assert.equal(collected.status, 500);
  assert.equal(await count(env), 0);
});
