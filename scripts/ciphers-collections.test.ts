import assert from 'node:assert/strict';
import test from 'node:test';

import { D1_MAX_BOUND_PARAMETERS } from '../src/db/client';
import { createOwnedOrganization } from '../src/handlers/organizations';
import { EMPTY_PERMISSIONS, MembershipStatus, MembershipType, type CollectionAccess, type OrgPermissions } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// Official clients change an org item's collections with a call separate from PUT /ciphers/{id}:
// the cipher form, "Assign to collections" and `bw edit item-collections` send
// PUT /ciphers/{id}/collections_v2, and the admin console PUT /ciphers/{id}/collections-admin
// (api.service.ts putCipherCollections / putCipherCollectionsAdmin, cipher.service.ts
// saveCollectionsWithServer[Admin]). Upstream CiphersController.PutCollections_vNext /
// PutCollectionsAdmin and CollectionCipher_UpdateCollections[Admin] @ v2026.9.1, plus 1aed7ce03.
const ORG_KEY = '4.dGVzdA==';
const ORG_ENCRYPTED = '2.b3Jn|b3Jn|b3Jn';
const LOGIN_TYPE = 1;
const NO_EDIT = 'You do not have permissions to edit this.';

interface CipherBody {
  id: string;
  object: string;
  collectionIds: string[];
}

interface OptionalCipherBody {
  object: string;
  unavailable: boolean;
  cipher: CipherBody | null;
}

interface Fixture {
  env: Env;
  owner: User;
  orgId: string;
  collectionA: string;
  collectionB: string;
  collectionC: string;
}

async function createCollection(env: Env, owner: User, orgId: string): Promise<string> {
  const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/collections`, body: { name: '2.c|c|c' }, userId: owner.id });
  assert.equal(response.status, 200);
  return ((await response.json()) as { id: string }).id;
}

async function setup(): Promise<Fixture> {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: ORG_KEY })).id;
  const [collectionA, collectionB, collectionC] = [
    await createCollection(env, owner, orgId),
    await createCollection(env, owner, orgId),
    await createCollection(env, owner, orgId),
  ];
  return { env, owner, orgId, collectionA, collectionB, collectionC };
}

function access(collectionId: string, overrides: Partial<CollectionAccess> = {}): CollectionAccess {
  return { collectionId, readOnly: false, hidePasswords: false, manage: false, ...overrides };
}

// A confirmed member holding direct access to the given collections.
async function addMember(
  env: Env, orgId: string, collections: CollectionAccess[], type: number = MembershipType.User, permissions: OrgPermissions | null = null
): Promise<User> {
  const user = await seedUser(env);
  const now = new Date().toISOString();
  await orgRepo.saveMembershipWithAccess(env.DB, {
    id: crypto.randomUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: false,
    key: ORG_KEY,
    status: MembershipStatus.Confirmed,
    type,
    permissions,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  }, { collections });
  return user;
}

function postCipher(env: Env, user: User, organizationId: string | null, collectionIds: string[]): Promise<Response> {
  return authedFetch(env, {
    method: 'POST',
    path: '/api/ciphers/create',
    body: { cipher: { type: LOGIN_TYPE, organizationId, name: ORG_ENCRYPTED, login: { username: ORG_ENCRYPTED } }, collectionIds },
    userId: user.id,
  });
}

async function createCipher(env: Env, user: User, organizationId: string | null, collectionIds: string[]): Promise<string> {
  const response = await postCipher(env, user, organizationId, collectionIds);
  assert.equal(response.status, 200);
  return ((await response.json()) as CipherBody).id;
}

function putCollections(
  env: Env, user: User, cipherId: string, route: 'collections_v2' | 'collections-admin', body: unknown, method = 'PUT'
): Promise<Response> {
  return authedFetch(env, { method, path: `/api/ciphers/${cipherId}/${route}`, body, userId: user.id });
}

async function storedCollectionIds(env: Env, cipherId: string): Promise<string[]> {
  return (await orgRepo.listCipherCollectionIds(env.DB, cipherId)).sort();
}

async function syncedCollectionIds(env: Env, user: User, cipherId: string): Promise<string[] | undefined> {
  const response = await authedFetch(env, { path: '/api/sync', userId: user.id });
  assert.equal(response.status, 200);
  const ciphers = ((await response.json()) as { ciphers: CipherBody[] }).ciphers;
  return ciphers.find((cipher) => cipher.id === cipherId)?.collectionIds.sort();
}

test('PUT /ciphers/{id}/collections_v2 moves an org cipher and answers with optionalCipherDetails', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const member = await addMember(env, orgId, [access(collectionA), access(collectionB)]);
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);
  // Prime both users' cached sync: a missed revision bump would keep serving collection A.
  assert.deepEqual(await syncedCollectionIds(env, owner, cipherId), [collectionA]);
  assert.deepEqual(await syncedCollectionIds(env, member, cipherId), [collectionA]);

  const response = await putCollections(env, owner, cipherId, 'collections_v2', { collectionIds: [collectionB] });

  assert.equal(response.status, 200);
  const body = await response.json() as OptionalCipherBody;
  assert.equal(body.object, 'optionalCipherDetails');
  assert.equal(body.unavailable, false);
  assert.equal(body.cipher?.id, cipherId);
  assert.deepEqual(body.cipher?.collectionIds, [collectionB]);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionB]);
  assert.deepEqual(await syncedCollectionIds(env, owner, cipherId), [collectionB]);
  assert.deepEqual(await syncedCollectionIds(env, member, cipherId), [collectionB]);
});

test('POST /ciphers/{id}/collections_v2 is the deprecated alias', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);

  assert.equal((await putCollections(env, owner, cipherId, 'collections_v2', { collectionIds: [collectionA, collectionB] }, 'POST')).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA, collectionB].sort());
});

test('collections_v2 touches only the member\'s writable collections and reports an item it can no longer see', async () => {
  const { env, owner, orgId, collectionA, collectionB, collectionC } = await setup();
  const member = await addMember(env, orgId, [access(collectionB), access(collectionC)]);
  const cipherId = await createCipher(env, owner, orgId, [collectionA, collectionB]);

  // A is outside the member's access, so asking to drop it (by omission) keeps it.
  const moved = await putCollections(env, member, cipherId, 'collections_v2', { collectionIds: [collectionC] });
  assert.equal(moved.status, 200);
  assert.equal(((await moved.json()) as OptionalCipherBody).unavailable, false);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA, collectionC].sort());

  // Dropping the member's last collection leaves the item only in A: the client deletes it locally.
  const dropped = await putCollections(env, member, cipherId, 'collections_v2', { collectionIds: [] });
  assert.equal(dropped.status, 200);
  assert.deepEqual(await dropped.json(), { object: 'optionalCipherDetails', unavailable: true, cipher: null });
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA]);
});

test('collections_v2 honours write access granted through a group and keeps read-only collections', async () => {
  const { env, owner, orgId, collectionA, collectionB, collectionC } = await setup();
  // A is read-only to the member; B and C are writable only through its group.
  const member = await addMember(env, orgId, [access(collectionA, { readOnly: true })]);
  const membership = await orgRepo.getMembershipByUserAndOrg(env.DB, member.id, orgId);
  assert.ok(membership);
  const now = new Date().toISOString();
  const groupId = crypto.randomUUID();
  await orgRepo.saveGroup(env.DB, { id: groupId, orgId, name: 'Editors', accessAll: false, externalId: null, createdAt: now, updatedAt: now });
  await orgRepo.replaceGroupMembers(env.DB, groupId, [membership.id]);
  await Promise.all([collectionB, collectionC].map((collectionId) =>
    orgRepo.replaceCollectionAccess(env.DB, collectionId, { groups: [{ groupId, readOnly: false, hidePasswords: false, manage: false }] })));
  const cipherId = await createCipher(env, owner, orgId, [collectionA, collectionC]);

  assert.equal((await putCollections(env, member, cipherId, 'collections_v2', { collectionIds: [collectionB] })).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA, collectionB].sort());
});

test('collections_v2 refuses personal items, outsiders, hidden passwords and read-only members', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const outsider = await seedUser(env);
  const hiddenMember = await addMember(env, orgId, [access(collectionA, { hidePasswords: true })]);
  const readOnlyMember = await addMember(env, orgId, [access(collectionA, { readOnly: true })]);
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);
  const personalCipherId = await createCipher(env, owner, null, []);
  const request = { collectionIds: [collectionB] };

  assert.equal((await putCollections(env, owner, personalCipherId, 'collections_v2', request)).status, 404);
  assert.equal((await putCollections(env, outsider, cipherId, 'collections_v2', request)).status, 404);
  assert.equal((await putCollections(env, hiddenMember, cipherId, 'collections_v2', request)).status, 404);
  const readOnly = await putCollections(env, readOnlyMember, cipherId, 'collections_v2', request);
  assert.equal(readOnly.status, 400);
  assert.equal(((await readOnly.json()) as { error: string }).error, NO_EDIT);
  assert.equal((await putCollections(env, owner, cipherId, 'collections_v2', {})).status, 400);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA]);
});

test('PUT /ciphers/{id}/collections-admin reassigns any org collection and answers with cipherMiniDetails', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);

  const response = await putCollections(env, owner, cipherId, 'collections-admin', { collectionIds: [collectionA, collectionB] });

  assert.equal(response.status, 200);
  const body = await response.json() as CipherBody;
  assert.equal(body.object, 'cipherMiniDetails');
  assert.equal(body.id, cipherId);
  assert.deepEqual(body.collectionIds.sort(), [collectionA, collectionB].sort());
  assert.deepEqual(await syncedCollectionIds(env, owner, cipherId), [collectionA, collectionB].sort());

  assert.equal((await putCollections(env, owner, cipherId, 'collections-admin', { collectionIds: [collectionB] }, 'POST')).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionB]);
});

test('collections-admin admits a custom member with editAnyCollection', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const collectionEditor = await addMember(env, orgId, [], MembershipType.Custom, { ...EMPTY_PERMISSIONS, editAnyCollection: true });
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);

  assert.equal((await putCollections(env, collectionEditor, cipherId, 'collections-admin', { collectionIds: [collectionB] })).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionB]);
});

test('collections-admin refuses non-admins, another org\'s collections and personal items', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const member = await addMember(env, orgId, [access(collectionA), access(collectionB)]);
  const outsider = await seedUser(env);
  const otherOrgId = (await createOwnedOrganization(env, outsider, { name: 'Other', key: ORG_KEY })).id;
  const otherOrgCollectionId = await createCollection(env, outsider, otherOrgId);
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);
  const personalCipherId = await createCipher(env, owner, null, []);

  assert.equal((await putCollections(env, member, cipherId, 'collections-admin', { collectionIds: [collectionB] })).status, 404);
  assert.equal((await putCollections(env, outsider, cipherId, 'collections-admin', { collectionIds: [otherOrgCollectionId] })).status, 404);
  assert.equal((await putCollections(env, owner, cipherId, 'collections-admin', { collectionIds: [collectionB, otherOrgCollectionId] })).status, 404);
  assert.equal((await putCollections(env, owner, personalCipherId, 'collections-admin', { collectionIds: [collectionB] })).status, 404);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA]);
});

test('creating an org cipher refuses it whole unless the member can write every posted collection', async () => {
  const { env, owner, orgId, collectionA, collectionB } = await setup();
  const member = await addMember(env, orgId, [access(collectionA), access(collectionB, { readOnly: true })]);
  const outsider = await seedUser(env);
  const otherOrgId = (await createOwnedOrganization(env, outsider, { name: 'Other', key: ORG_KEY })).id;
  const otherOrgCollectionId = await createCollection(env, outsider, otherOrgId);

  // One writable id must not carry a read-only or foreign one along; even full access stays in its org.
  // A 400, not a 403: official clients log out on an authenticated 403.
  const readOnlyMix = await postCipher(env, member, orgId, [collectionA, collectionB]);
  assert.equal(readOnlyMix.status, 400);
  assert.equal(((await readOnlyMix.json()) as { error: string }).error, NO_EDIT);
  assert.equal((await postCipher(env, member, orgId, [collectionA, otherOrgCollectionId])).status, 400);
  assert.equal((await postCipher(env, owner, orgId, [collectionA, otherOrgCollectionId])).status, 400);
  // An item in no collection would be invisible to a member without full access.
  assert.equal((await postCipher(env, member, orgId, [])).status, 400);
  assert.equal(await env.DB.prepare('SELECT count(*) AS total FROM ciphers').first('total'), 0);

  const cipherId = await createCipher(env, member, orgId, [collectionA]);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA]);
});

test('collection changes stay within the D1 bound-parameter limit however many collections move', async () => {
  const { env, owner, orgId, collectionA } = await setup();
  const cipherId = await createCipher(env, owner, orgId, [collectionA]);
  const now = new Date().toISOString();
  // One delete of this many ids plus the cipher id would bind one parameter too many.
  const manyCollectionIds = Array.from({ length: D1_MAX_BOUND_PARAMETERS }, () => crypto.randomUUID());
  for (const id of manyCollectionIds) {
    await orgRepo.saveCollection(env.DB, { id, orgId, name: ORG_ENCRYPTED, externalId: null, createdAt: now, updatedAt: now });
  }

  assert.equal((await putCollections(env, owner, cipherId, 'collections-admin', { collectionIds: manyCollectionIds })).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [...manyCollectionIds].sort());
  assert.equal((await putCollections(env, owner, cipherId, 'collections_v2', { collectionIds: [collectionA] })).status, 200);
  assert.deepEqual(await storedCollectionIds(env, cipherId), [collectionA]);
});
