import assert from 'node:assert/strict';
import test from 'node:test';

import { getColumns } from 'drizzle-orm';

import { D1_MAX_BOUND_PARAMETERS } from '../src/db/client';
import { collectionGroups } from '../src/db/schema';
import { MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMember } from './support/sm';

const { createOwnedOrganization } = await import('../src/handlers/organizations');

// Official web's collection dialog builds its Access tab from GET /organizations/{orgId}/collections/details
// and saves the whole list back, so a details row without users and groups made every save wipe the
// collection's access. Upstream CollectionsController serves CollectionAccessDetailsResponseModel on
// /details, /{id}/details (which `bw get org-collection` reads), POST and PUT, and a bare
// SelectionReadOnlyResponseModel array on /{id}/users.
const MEMBER_KEY = '4.dGVzdA==';
const COLLECTION_NAME = '2.c|c|c';
const INVITED_EMAIL = 'invitee@example.test';
const ACCESS_DETAILS_KEYS = [
  'assigned', 'defaultUserCollectionEmail', 'externalId', 'groups', 'hidePasswords', 'id', 'manage',
  'name', 'object', 'organizationId', 'readOnly', 'type', 'unmanaged', 'users',
];
const SELECTION_KEYS = ['hidePasswords', 'id', 'manage', 'readOnly'];

interface Selection {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

interface AccessDetails {
  id: string;
  name: string;
  externalId: string | null;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
  assigned: boolean;
  unmanaged: boolean;
  users: Selection[] | null;
  groups: Selection[] | null;
  object: string;
}

const manageAccess = (id: string): Selection => ({ id, readOnly: false, hidePasswords: false, manage: true });
const editAccess = (id: string): Selection => ({ id, readOnly: false, hidePasswords: false, manage: false });
const viewAccess = (id: string): Selection => ({ id, readOnly: true, hidePasswords: false, manage: false });
const byId = (left: { id: string }, right: { id: string }) => left.id.localeCompare(right.id);
const sorted = (selections: Selection[] | null) => [...(selections ?? [])].sort(byId);

async function createOrg(env: Env, owner: User): Promise<string> {
  return (await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY })).id;
}

async function ownerMemberId(env: Env, owner: User, orgId: string): Promise<string> {
  return (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!.id;
}

function collectionsPath(orgId: string, suffix = ''): string {
  return `/api/organizations/${orgId}/collections${suffix}`;
}

async function createCollection(env: Env, actor: User, orgId: string, access: Record<string, unknown> = {}): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: collectionsPath(orgId), body: { name: COLLECTION_NAME, ...access }, userId: actor.id });
}

async function createCollectionId(env: Env, owner: User, orgId: string): Promise<string> {
  const response = await createCollection(env, owner, orgId);
  assert.equal(response.status, 200);
  return ((await response.json()) as { id: string }).id;
}

async function createGroup(env: Env, owner: User, orgId: string): Promise<string> {
  const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/groups`, body: { name: 'Group' }, userId: owner.id });
  assert.equal(response.status, 200);
  return ((await response.json()) as { id: string }).id;
}

function putCollection(env: Env, actor: User, orgId: string, collectionId: string, body: Record<string, unknown>): Promise<Response> {
  return authedFetch(env, { method: 'PUT', path: collectionsPath(orgId, `/${collectionId}`), body: { name: COLLECTION_NAME, ...body }, userId: actor.id });
}

function get(env: Env, actor: User, path: string): Promise<Response> {
  return authedFetch(env, { path, userId: actor.id });
}

async function listDetails(env: Env, actor: User, orgId: string): Promise<AccessDetails[]> {
  const response = await get(env, actor, collectionsPath(orgId, '/details'));
  assert.equal(response.status, 200);
  return ((await response.json()) as { data: AccessDetails[] }).data;
}

async function singleDetails(env: Env, actor: User, orgId: string, collectionId: string): Promise<AccessDetails> {
  const response = await get(env, actor, collectionsPath(orgId, `/${collectionId}/details`));
  assert.equal(response.status, 200);
  return await response.json() as AccessDetails;
}

test('the collection dialog opens with every grant and saving it back keeps them', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollectionId(env, owner, orgId);
  const [alice, bob] = [await seedMember(env, orgId), await seedMember(env, orgId)];
  const groupId = await createGroup(env, owner, orgId);
  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: [editAccess(alice.memberId)], groups: [manageAccess(groupId)] })).status, 200);
  // An invited member's grant waits in pending_collection_users until accept.
  const invited = await authedFetch(env, {
    method: 'POST',
    path: `/api/organizations/${orgId}/users/invite`,
    body: { emails: [INVITED_EMAIL], type: MembershipType.User, collections: [{ ...viewAccess(collectionId) }] },
    userId: owner.id,
  });
  assert.equal(invited.status, 200);
  const invitedId = (await orgRepo.listMembershipsByOrg(env.DB, orgId)).find((row) => row.email === INVITED_EMAIL)!.id;

  const opened = (await listDetails(env, owner, orgId)).find((collection) => collection.id === collectionId)!;
  assert.deepEqual(sorted(opened.users), sorted([editAccess(alice.memberId), viewAccess(invitedId)]));
  assert.deepEqual(opened.groups, [manageAccess(groupId)]);

  // The dialog posts back what it opened with, plus the member the admin added.
  const saved = await putCollection(env, owner, orgId, collectionId, {
    name: opened.name,
    externalId: opened.externalId,
    users: [...opened.users!, editAccess(bob.memberId)],
    groups: opened.groups,
  });
  assert.equal(saved.status, 200);
  const reopened = await singleDetails(env, owner, orgId, collectionId);
  assert.deepEqual(sorted(reopened.users), sorted([editAccess(alice.memberId), viewAccess(invitedId), editAccess(bob.memberId)]));
  assert.deepEqual(reopened.groups, [manageAccess(groupId)]);
  assert.deepEqual(await orgRepo.listUserCollectionAccess(env.DB, alice.user.id, orgId), [
    { collectionId, readOnly: false, hidePasswords: false, manage: false },
  ]);
});

// The dialog posts every group back, so one more grant than a single collection_groups INSERT can bind
// must still save, and never after its old grants were deleted.
test('saving the dialog keeps more group grants than one statement can bind', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollectionId(env, owner, orgId);
  const groupCount = Math.floor(D1_MAX_BOUND_PARAMETERS / Object.keys(getColumns(collectionGroups)).length) + 1;
  const groupIds = await Promise.all(Array.from({ length: groupCount }, () => createGroup(env, owner, orgId)));
  const grants = groupIds.map(editAccess).sort(byId);
  assert.equal((await putCollection(env, owner, orgId, collectionId, { groups: grants })).status, 200);

  const opened = await singleDetails(env, owner, orgId, collectionId);
  assert.deepEqual(sorted(opened.groups), grants);
  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: opened.users, groups: opened.groups })).status, 200);
  assert.deepEqual(sorted((await singleDetails(env, owner, orgId, collectionId)).groups), grants);
});

// Upstream ReplaceAsync: an omitted list leaves that access as is, and an empty one removes it all.
test('saving the dialog with an empty list removes those grants and an omitted list keeps them', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollectionId(env, owner, orgId);
  const alice = await seedMember(env, orgId);
  const groupId = await createGroup(env, owner, orgId);
  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: [editAccess(alice.memberId)], groups: [manageAccess(groupId)] })).status, 200);

  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: [] })).status, 200);
  const details = await singleDetails(env, owner, orgId, collectionId);
  assert.deepEqual(details.users, []);
  assert.deepEqual(details.groups, [manageAccess(groupId)]);
  assert.deepEqual(await orgRepo.listUserCollectionAccess(env.DB, alice.user.id, orgId), []);
});

test('single collection details is one object in the shape `bw get org-collection` reads', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollectionId(env, owner, orgId);
  const alice = await seedMember(env, orgId);

  const unmanaged = await singleDetails(env, owner, orgId, collectionId);
  assert.equal(Array.isArray(unmanaged), false);
  assert.deepEqual(Object.keys(unmanaged).sort(), ACCESS_DETAILS_KEYS);
  assert.equal(unmanaged.id, collectionId);
  assert.equal(unmanaged.name, COLLECTION_NAME);
  assert.equal(unmanaged.object, 'collectionAccessDetails');
  assert.deepEqual({ users: unmanaged.users, groups: unmanaged.groups, unmanaged: unmanaged.unmanaged }, { users: [], groups: [], unmanaged: true });

  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: [manageAccess(alice.memberId)] })).status, 200);
  const managed = await singleDetails(env, owner, orgId, collectionId);
  assert.equal(managed.unmanaged, false);
  assert.deepEqual(managed.users, [manageAccess(alice.memberId)]);
  managed.users!.forEach((selection) => assert.deepEqual(Object.keys(selection).sort(), SELECTION_KEYS));

  const users = await get(env, owner, collectionsPath(orgId, `/${collectionId}/users`));
  assert.equal(users.status, 200);
  assert.deepEqual(await users.json(), [manageAccess(alice.memberId)]);

  const missing = await get(env, owner, collectionsPath(orgId, `/${crypto.randomUUID()}/details`));
  assert.equal(missing.status, 404);
});

// Official web keeps the saved collection in its local store only when the response says assigned.
test('create and update answer with the saved collection access details', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const ownerId = await ownerMemberId(env, owner, orgId);

  const created = await createCollection(env, owner, orgId, { users: [manageAccess(ownerId)], groups: [] });
  assert.equal(created.status, 200);
  const createdBody = await created.json() as AccessDetails;
  assert.deepEqual(Object.keys(createdBody).sort(), ACCESS_DETAILS_KEYS);
  assert.deepEqual(
    { object: createdBody.object, assigned: createdBody.assigned, users: createdBody.users, groups: createdBody.groups },
    { object: 'collectionAccessDetails', assigned: true, users: [manageAccess(ownerId)], groups: [] },
  );

  const updated = await putCollection(env, owner, orgId, createdBody.id, { users: [editAccess(ownerId)] });
  assert.equal(updated.status, 200);
  const updatedBody = await updated.json() as AccessDetails;
  assert.deepEqual(
    { object: updatedBody.object, assigned: updatedBody.assigned, users: updatedBody.users, unmanaged: updatedBody.unmanaged },
    { object: 'collectionAccessDetails', assigned: true, users: [editAccess(ownerId)], unmanaged: true },
  );

  // A creator that may not read access gets upstream's bare response: no grants and every flag false.
  const creator = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { createNewCollections: true } });
  const bare = await createCollection(env, creator.user, orgId, { users: [editAccess(creator.memberId)] });
  assert.equal(bare.status, 200);
  const bareBody = await bare.json() as AccessDetails;
  assert.deepEqual(Object.keys(bareBody).sort(), ACCESS_DETAILS_KEYS);
  assert.deepEqual(
    { object: bareBody.object, assigned: bareBody.assigned, manage: bareBody.manage, users: bareBody.users, groups: bareBody.groups },
    { object: 'collectionAccessDetails', assigned: false, manage: false, users: null, groups: null },
  );
});

// Upstream CollectionAuthorizationHandler.ReadAllWithAccess lists every collection's access to Owners,
// Admins and editAnyCollection, deleteAnyCollection, manageUsers or manageGroups members, and only the
// collections they manage to everyone else. BulkCollectionAuthorizationHandler admits one collection's
// details (ReadWithAccess) without manageGroups, and its /users (ReadAccess) without manageUsers either.
test('access details are served only to members who may read that access', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const outsider = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const [managed, other] = [await createCollectionId(env, owner, orgId), await createCollectionId(env, owner, orgId)];
  const manager = await seedMember(env, orgId);
  const editor = await seedMember(env, orgId);
  const userManager = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { manageUsers: true } });
  const groupManager = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { manageGroups: true } });
  const grants = { users: [manageAccess(manager.memberId), editAccess(editor.memberId)] };
  assert.equal((await putCollection(env, owner, orgId, managed, grants)).status, 200);
  const status = async (actor: User, suffix: string) => (await get(env, actor, collectionsPath(orgId, suffix))).status;
  const listedIds = async (actor: User) => (await listDetails(env, actor, orgId)).map(({ id }) => id).sort();

  // createOwnedOrganization also makes a default collection, which nobody manages.
  const everyCollection = (await orgRepo.listCollectionsByOrg(env.DB, orgId)).map(({ id }) => id).sort();
  assert.deepEqual(await listedIds(owner), everyCollection);
  assert.deepEqual(await listedIds(manager.user), [managed]);
  assert.deepEqual(await listedIds(editor.user), []);
  assert.deepEqual(await listedIds(userManager.user), everyCollection);
  assert.deepEqual(await listedIds(groupManager.user), everyCollection);
  assert.equal(await status(outsider, '/details'), 404);

  assert.equal(await status(manager.user, `/${managed}/details`), 200);
  assert.equal(await status(manager.user, `/${other}/details`), 404);
  assert.equal(await status(editor.user, `/${managed}/details`), 404);
  assert.equal(await status(userManager.user, `/${other}/details`), 200);
  assert.equal(await status(groupManager.user, `/${other}/details`), 404);

  assert.equal(await status(manager.user, `/${managed}/users`), 200);
  assert.equal(await status(editor.user, `/${managed}/users`), 404);
  assert.equal(await status(userManager.user, `/${other}/users`), 404);

  // Upstream takes the reader's own flags from its grants, so one holding none gets every flag false.
  const unassigned = await singleDetails(env, userManager.user, orgId, other);
  assert.deepEqual(
    { assigned: unassigned.assigned, readOnly: unassigned.readOnly, hidePasswords: unassigned.hidePasswords, manage: unassigned.manage },
    { assigned: false, readOnly: false, hidePasswords: false, manage: false },
  );

  // Another organization's collection is not found under this one, even for its Owner.
  const foreignCollection = await createCollectionId(env, outsider, await createOrg(env, outsider));
  assert.equal(await status(owner, `/${foreignCollection}/details`), 404);
  assert.equal(await status(owner, `/${foreignCollection}/users`), 404);
});

// Upstream CanUpdateCollectionAsync: Owners, Admins and editAnyCollection members update any collection,
// anyone else only one it holds with Manage. "Can edit" alone would let a member rewrite the access list,
// so the manage flag the member reads in details and sync must not offer it either.
test('only members who manage a collection may update it', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollectionId(env, owner, orgId);
  const manager = await seedMember(env, orgId);
  const editor = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { manageUsers: true } });
  const collectionEditor = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { editAnyCollection: true } });
  const grants = [manageAccess(manager.memberId), editAccess(editor.memberId)].sort(byId);
  assert.equal((await putCollection(env, owner, orgId, collectionId, { users: grants })).status, 200);

  assert.equal((await singleDetails(env, editor.user, orgId, collectionId)).manage, false);
  const synced = await get(env, editor.user, '/api/sync');
  const syncedCollections = ((await synced.json()) as { collections: AccessDetails[] }).collections;
  assert.equal(syncedCollections.find(({ id }) => id === collectionId)!.manage, false);
  assert.equal((await putCollection(env, editor.user, orgId, collectionId, { users: [manageAccess(editor.memberId)] })).status, 404);
  assert.deepEqual(sorted((await singleDetails(env, owner, orgId, collectionId)).users), grants);
  assert.equal((await putCollection(env, manager.user, orgId, collectionId, { users: grants })).status, 200);
  assert.equal((await putCollection(env, collectionEditor.user, orgId, collectionId, { users: grants })).status, 200);
});
