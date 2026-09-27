import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { events } from '../db/schema';
import { EventType } from '../services/events';
import { MembershipStatus } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import type { Env } from '../types';
import { authedFetch, captureEmail, createTestEnv, MAILABLE_DOMAIN, seedUser } from './support/env';
import { seedMember } from './support/sm';
const { createOwnedOrganization } = await import('../handlers/organizations');

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const ORG_KEY = '4.dGVzdA==';
const CLIENT_IP = '203.0.113.10';

async function setup() {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const owner = await seedUser(env);
  const org = await createOwnedOrganization(env, owner, { name: 'Private organization', key: ORG_KEY });
  const [collection] = await orgRepo.listCollectionsByOrg(env.DB, org.id);
  const call = (method: string, path: string, body?: unknown, actor = owner) => authedFetch(env, {
    method, path, body, userId: actor.id, headers: { 'Device-Type': '8' },
  });
  return { env, owner, org, collection, call };
}

async function rows(env: Env, orgId: string) {
  return getOrm(env.DB).select().from(events).where(eq(events.organizationId, orgId));
}

async function assertTypes(env: Env, orgId: string, expected: number[]) {
  assert.deepEqual((await rows(env, orgId)).map(row => row.type).sort(), expected.toSorted());
}

test('organization cipher events retain immutable scope through deletion and skip personal, denied and idempotent operations', async () => {
  const { env, owner, org, collection, call } = await setup();
  const stranger = await seedUser(env);
  const body = { type: 1, name: ENCRYPTED, organizationId: org.id, collectionIds: [collection.id], login: { username: ENCRYPTED } };
  const created = await call('POST', '/api/ciphers', body);
  assert.equal(created.status, 200);
  const { id, revisionDate } = await created.json() as { id: string; revisionDate: string };
  assert.equal((await call('PUT', `/api/ciphers/${id}`, { ...body, lastKnownRevisionDate: revisionDate })).status, 200);
  await assertTypes(env, org.id, [1100]);
  assert.equal((await call('PUT', `/api/ciphers/${id}`, { ...body, name: '2.changed|changed|changed' })).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}`, body, stranger)).status, 404);
  assert.equal((await call('PUT', `/api/ciphers/${id}/collections-admin`, { collectionIds: [collection.id] })).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/collections-admin`, { collectionIds: [] })).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/collections-admin`, { collectionIds: [] })).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/restore`)).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/delete`)).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/delete`)).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/restore`)).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${id}/restore`)).status, 200);
  assert.equal((await call('DELETE', `/api/ciphers/${id}/delete`)).status, 204);
  assert.equal((await call('DELETE', `/api/ciphers/${id}/delete`)).status, 404);

  const personal = await call('POST', '/api/ciphers', { type: 1, name: ENCRYPTED });
  const { id: personalId } = await personal.json() as { id: string };
  assert.equal((await call('PUT', `/api/ciphers/${personalId}`, { name: '2.changed|changed|changed' })).status, 200);
  assert.equal((await call('PUT', `/api/ciphers/${personalId}/delete`)).status, 200);
  assert.equal((await call('DELETE', `/api/ciphers/${personalId}`)).status, 204);
  await assertTypes(env, org.id, [1100, 1101, 1106, 1115, 1116, 1102]);
  const saved = await rows(env, org.id);
  assert.ok(saved.every(row => row.resourceId === id && row.resourceType === 'cipher' && row.actingUserId === owner.id));
  assert.ok(saved.every(row => row.deviceType === 8 && row.ipAddress === CLIENT_IP));
  assert.ok(!JSON.stringify(saved).includes(ENCRYPTED));
  assert.equal((await getOrm(env.DB).select().from(events)).length, saved.length);
});

test('share and attachment events record only successful organization mutations, including bulk share once per id', async () => {
  const { env, org, collection, call } = await setup();
  const create = async () => {
    const response = await call('POST', '/api/ciphers', { type: 1, name: ENCRYPTED });
    assert.equal(response.status, 200);
    return (await response.json() as { id: string }).id;
  };
  const id = await create();
  const secondId = await create();
  const cipher = { id, type: 1, organizationId: org.id, name: ENCRYPTED };
  assert.equal((await call('PUT', `/api/ciphers/${id}/share`, { cipher, collectionIds: [] })).status, 400);
  await assertTypes(env, org.id, []);
  assert.equal((await call('PUT', '/api/ciphers/share', { ciphers: [cipher, cipher, { ...cipher, id: secondId }], collectionIds: [collection.id] })).status, 200);
  assert.equal((await call('POST', `/api/ciphers/${id}/attachment/v2`, {})).status, 400);
  const attachment = await call('POST', `/api/ciphers/${id}/attachment/v2`, { fileName: ENCRYPTED, key: ENCRYPTED, fileSize: 4 });
  assert.equal(attachment.status, 200);
  const { attachmentId } = await attachment.json() as { attachmentId: string };
  assert.equal((await call('DELETE', `/api/ciphers/${id}/attachment/${attachmentId}`)).status, 200);
  assert.equal((await call('DELETE', `/api/ciphers/${id}/attachment/${attachmentId}`)).status, 404);
  // Bulk delete/restore routes are personal-vault-only; naming org IDs cannot produce events.
  for (const action of ['delete', 'restore', 'delete-permanent']) {
    assert.equal((await call('POST', `/api/ciphers/${action}`, { ids: [id, secondId] })).status, 204);
  }
  await assertTypes(env, org.id, [1105, 1105, 1103, 1104]);
  const saved = await rows(env, org.id);
  assert.deepEqual(saved.filter(row => row.type === EventType.CipherShared).map(row => row.resourceId).sort(), [id, secondId].sort());
  assert.ok(saved.filter(row => row.type !== EventType.CipherShared).every(row => row.resourceId === id));
});

test('collections, groups, settings and policies emit changed events without encrypted content or foreign-org rows', async () => {
  const { env, owner, org, call } = await setup();
  const foreign = await createOwnedOrganization(env, owner, { name: 'Other', key: ORG_KEY });
  const base = `/api/organizations/${org.id}`;
  const collection = await call('POST', `${base}/collections`, { name: ENCRYPTED });
  assert.equal(collection.status, 200);
  const { id: collectionId } = await collection.json() as { id: string };
  assert.equal((await call('PUT', `${base}/collections/${collectionId}`, { name: ENCRYPTED, users: [], groups: [] })).status, 200);
  assert.equal((await call('PUT', `${base}/collections/${collectionId}`, { name: '2.changed|changed|changed' })).status, 200);
  assert.equal((await call('DELETE', `/api/organizations/${foreign.id}/collections/${collectionId}`)).status, 404);
  assert.equal((await call('DELETE', `${base}/collections/${collectionId}`)).status, 200);
  assert.equal((await call('DELETE', `${base}/collections/${collectionId}`)).status, 404);
  const group = await call('POST', `${base}/groups`, { name: 'Private group' });
  assert.equal(group.status, 200);
  const { id: groupId } = await group.json() as { id: string };
  assert.equal((await call('PUT', `${base}/groups/${groupId}`, { name: 'Private group' })).status, 200);
  assert.equal((await call('PUT', `${base}/groups/${groupId}`, { name: 'Renamed group' })).status, 200);
  assert.equal((await call('DELETE', `${base}/groups/${groupId}`)).status, 200);
  assert.equal((await call('PUT', base, { name: org.name })).status, 200);
  assert.equal((await call('PUT', base, { name: 'Renamed organization' })).status, 200);
  const policy = { policy: { enabled: true, data: { minimumLength: 15 } } };
  assert.equal((await call('PUT', `${base}/policies/5`, policy)).status, 200);
  assert.equal((await call('PUT', `${base}/policies/5`, policy)).status, 200);
  await assertTypes(env, org.id, [1300, 1301, 1302, 1400, 1401, 1402, 1600, 1700]);
  await assertTypes(env, foreign.id, []);
  const saved = await rows(env, org.id);
  assert.ok(saved.filter(row => [1300, 1301, 1302].includes(row.type)).every(row => row.resourceId === collectionId));
  assert.ok(saved.filter(row => [1400, 1401, 1402].includes(row.type)).every(row => row.resourceId === groupId));
  assert.ok(!JSON.stringify(saved).includes(ENCRYPTED));
  assert.ok(!JSON.stringify(saved).includes('Renamed'));
  assert.ok(saved.every(row => row.deviceType === 8 && row.ipAddress === CLIENT_IP), 'every admin change keeps its client and address');
});

test('membership events cover actual transitions and preserve the affected account after removal or leaving', async () => {
  const { env, owner, org, call } = await setup();
  const foreign = await createOwnedOrganization(env, owner, { name: 'Other', key: ORG_KEY });
  const target = await seedMember(env, org.id, { status: MembershipStatus.Accepted });
  const other = await seedMember(env, foreign.id, { status: MembershipStatus.Accepted });
  const base = `/api/organizations/${org.id}`;
  const inviteEmail = `invite-${crypto.randomUUID()}@${MAILABLE_DOMAIN}`;
  assert.equal((await call('POST', `${base}/users/invite`, { emails: [inviteEmail], type: 2 })).status, 200);
  assert.equal((await call('POST', `${base}/users/invite`, { emails: [inviteEmail], type: 2 })).status, 200);
  const invite = (await orgRepo.listMembershipsByOrg(env.DB, org.id)).find(member => member.email === inviteEmail)!;
  const confirm = { keys: [{ id: target.memberId, key: ORG_KEY }, { id: other.memberId, key: ORG_KEY }, { id: invite.id, key: ORG_KEY }] };
  assert.equal((await call('POST', `${base}/users/confirm`, confirm)).status, 200);
  assert.equal((await call('POST', `${base}/users/confirm`, confirm)).status, 200);
  assert.equal((await call('PUT', `${base}/users/${target.memberId}`, { type: 1 })).status, 200);
  assert.equal((await call('PUT', `${base}/users/${target.memberId}`, { type: 1 })).status, 200);
  const group = await call('POST', `${base}/groups`, { name: 'Private group', users: [target.memberId] });
  const { id: groupId } = await group.json() as { id: string };
  assert.equal((await call('PUT', `${base}/groups/${groupId}`, { users: [target.memberId] })).status, 200);
  assert.equal((await call('PUT', `${base}/users/${target.memberId}`, { type: 1, groups: [] })).status, 200);
  assert.equal((await call('PUT', `${base}/users/${target.memberId}`, { type: 1, groups: [] })).status, 200);
  const ids = [target.memberId, other.memberId, crypto.randomUUID()];
  assert.equal((await call('PUT', `${base}/users/revoke`, { ids })).status, 200);
  assert.equal((await call('PUT', `${base}/users/revoke`, { ids })).status, 200);
  assert.equal((await call('PUT', `${base}/users/restore`, { ids })).status, 200);
  assert.equal((await call('PUT', `${base}/users/restore`, { ids })).status, 200);
  assert.equal((await call('DELETE', `${base}/users`, { ids })).status, 200);
  const departing = await seedMember(env, org.id);
  assert.equal((await call('POST', `${base}/leave`, undefined, departing.user)).status, 200);
  const saved = await rows(env, org.id);
  assert.deepEqual(saved.filter(row => row.resourceId === target.memberId).map(row => row.type).sort(), [1501, 1502, 1502, 1504, 1511, 1512, 1503].sort());
  assert.ok(saved.filter(row => row.resourceId === target.memberId).every(row => row.userId === target.user.id && row.actingUserId === owner.id));
  assert.deepEqual(saved.filter(row => row.resourceId === invite.id).map(row => row.type), [1500]);
  assert.equal(saved.find(row => row.type === 1516)?.userId, departing.user.id);
  assert.equal(saved.find(row => row.type === 1516)?.actingUserId, departing.user.id);
  await assertTypes(env, foreign.id, []);
  assert.ok(!saved.some(row => row.resourceId === other.memberId));
  assert.ok(!JSON.stringify(saved).includes(inviteEmail));
  assert.ok(saved.every(row => row.deviceType === 8 && row.ipAddress === CLIENT_IP), 'leave keeps its client and address');
});

test('single-member revoke, restore and remove record the acting client and address', async () => {
  const { env, org, call } = await setup();
  const { memberId } = await seedMember(env, org.id);
  const base = `/api/organizations/${org.id}/users/${memberId}`;
  assert.equal((await call('PUT', `${base}/revoke`)).status, 200);
  assert.equal((await call('PUT', `${base}/restore`)).status, 200);
  assert.equal((await call('DELETE', base)).status, 200);
  const saved = await rows(env, org.id);
  assert.deepEqual(saved.map(row => row.type).sort(), [EventType.OrganizationUserRevoked, EventType.OrganizationUserRestored, EventType.OrganizationUserRemoved].sort());
  assert.ok(saved.every(row => row.deviceType === 8 && row.ipAddress === CLIENT_IP && row.resourceId === memberId));
});
