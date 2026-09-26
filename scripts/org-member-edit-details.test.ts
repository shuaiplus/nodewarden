import assert from 'node:assert/strict';
import test from 'node:test';

import { createOwnedOrganization } from '../src/handlers/organizations';
import { hasFullCollectionAccess } from '../src/services/org-authz';
import { EMPTY_PERMISSIONS, MembershipStatus, MembershipType, type OrgPermissions } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { createOrgInviteToken } from '../src/utils/jwt';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// Official web's edit-member dialog loads GET /organizations/{orgId}/users/{id}?includeGroups=true
// (UserAdminService.get) and saves the full OrganizationUserUpdateRequest. Upstream
// OrganizationUserValidationService.CanManageRoleChange keeps Admins and Custom manageUsers
// members from granting or touching Owner, and Custom members from granting what they lack.
const MEMBER_KEY = '4.dGVzdA==';
const ONLY_OWNERS = "Only an Owner can manage another Owner's account.";
// Upstream invite still runs the v1 OrganizationService check, which words the Owner case differently.
const ONLY_OWNERS_INVITE = "Only an Owner can configure another Owner's account.";
const CUSTOM_NOT_ADMINS = 'Custom users can not manage Admins or Owners.';
const CUSTOM_OWN_PERMISSIONS = 'Custom users can only grant the same custom permissions that they have.';
const LAST_OWNER = 'Organization must have at least one confirmed owner.';
const MANAGE_EXCLUSIVE = 'The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true.';
const RESOURCE_NOT_FOUND = 'Resource not found.';
const SELF_COLLECTION = 'You cannot add yourself to a collection.';
// A collection access row binds 5 parameters and D1 allows 100 per statement, so this needs two INSERTs.
const MANY_COLLECTIONS = 30;
// Likewise more members than one multi-row INSERT of collection access holds.
const MANY_MEMBERS = 30;

interface MemberDetails {
  id: string;
  userId: string | null;
  type: number;
  status: number;
  permissions: OrgPermissions | null;
  collections: Array<{ id: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>;
  groups?: string[];
  hasMasterPassword: boolean;
  object: string;
}

async function errorMessage(response: Response): Promise<string> {
  return ((await response.json()) as { error: string }).error;
}

async function createOrg(env: Env, owner: User): Promise<string> {
  return (await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY })).id;
}

// Seeds a confirmed member directly, since the invite flow itself is covered elsewhere.
async function addMember(env: Env, orgId: string, type: number, permissions: Partial<OrgPermissions> | null = null) {
  const user = await seedUser(env);
  const now = new Date().toISOString();
  const membership = {
    id: crypto.randomUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: false,
    key: MEMBER_KEY,
    status: MembershipStatus.Confirmed,
    type,
    permissions: permissions ? { ...EMPTY_PERMISSIONS, ...permissions } : null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo.saveMembership(env.DB, membership);
  return { user, memberId: membership.id };
}

function putMember(env: Env, actor: User, orgId: string, memberId: string, body: Record<string, unknown>): Promise<Response> {
  return authedFetch(env, { method: 'PUT', path: `/api/organizations/${orgId}/users/${memberId}`, body, userId: actor.id });
}

function invite(env: Env, actor: User, orgId: string, body: Record<string, unknown>): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/invite`, body, userId: actor.id });
}

async function details(env: Env, actor: User, orgId: string, memberId: string, query = '?includeGroups=true'): Promise<MemberDetails> {
  const response = await authedFetch(env, { path: `/api/organizations/${orgId}/users/${memberId}${query}`, userId: actor.id });
  assert.equal(response.status, 200);
  return await response.json() as MemberDetails;
}

async function expectRejected(response: Promise<Response>, status: number, message: string): Promise<void> {
  const settled = await response;
  assert.equal(settled.status, status);
  assert.equal(await errorMessage(settled), message);
}

async function createCollection(env: Env, owner: User, orgId: string): Promise<string> {
  const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/collections`, body: { name: '2.c|c|c' }, userId: owner.id });
  assert.equal(response.status, 200);
  return ((await response.json()) as { id: string }).id;
}

async function createGroup(env: Env, owner: User, orgId: string): Promise<string> {
  const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/groups`, body: { name: 'Group' }, userId: owner.id });
  assert.equal(response.status, 200);
  return ((await response.json()) as { id: string }).id;
}

function manageAccess(id: string) {
  return { id, readOnly: false, hidePasswords: false, manage: true };
}

function viewAccess(id: string) {
  return { id, readOnly: true, hidePasswords: false, manage: false };
}

function editAccess(id: string) {
  return { id, readOnly: false, hidePasswords: false, manage: false };
}

const byId = (left: { id: string }, right: { id: string }) => left.id.localeCompare(right.id);

test('an Admin can neither grant Owner nor edit or demote an Owner, on PUT or invite', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const ownerMemberId = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!.id;
  const admin = await addMember(env, orgId, MembershipType.Admin);
  const member = await addMember(env, orgId, MembershipType.User);

  await expectRejected(putMember(env, admin.user, orgId, member.memberId, { type: MembershipType.Owner }), 400, ONLY_OWNERS);
  await expectRejected(putMember(env, admin.user, orgId, admin.memberId, { type: MembershipType.Owner }), 400, ONLY_OWNERS);
  await expectRejected(putMember(env, admin.user, orgId, ownerMemberId, { type: MembershipType.User }), 400, ONLY_OWNERS);
  await expectRejected(invite(env, admin.user, orgId, { emails: ['new@example.test'], type: MembershipType.Owner }), 400, ONLY_OWNERS_INVITE);

  assert.equal((await details(env, owner, orgId, member.memberId)).type, MembershipType.User);
  assert.equal((await details(env, owner, orgId, admin.memberId)).type, MembershipType.Admin);
  assert.equal((await details(env, owner, orgId, ownerMemberId)).type, MembershipType.Owner);
  // Admins may still manage non-owners.
  assert.equal((await putMember(env, admin.user, orgId, member.memberId, { type: MembershipType.Admin })).status, 200);
});

test('a Custom manageUsers member only manages Users and Custom members with permissions it holds', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const custom = await addMember(env, orgId, MembershipType.Custom, { manageUsers: true, accessReports: true });
  const member = await addMember(env, orgId, MembershipType.User);
  const admin = await addMember(env, orgId, MembershipType.Admin);

  await expectRejected(putMember(env, custom.user, orgId, member.memberId, { type: MembershipType.Admin }), 400, CUSTOM_NOT_ADMINS);
  await expectRejected(putMember(env, custom.user, orgId, admin.memberId, { type: MembershipType.User }), 400, CUSTOM_NOT_ADMINS);
  await expectRejected(putMember(env, custom.user, orgId, member.memberId, { type: MembershipType.Owner }), 400, ONLY_OWNERS);
  await expectRejected(invite(env, custom.user, orgId, { emails: ['new@example.test'], type: MembershipType.Admin }), 400, CUSTOM_NOT_ADMINS);
  const escalated = { type: MembershipType.Custom, permissions: { manageUsers: true, managePolicies: true } };
  await expectRejected(putMember(env, custom.user, orgId, member.memberId, escalated), 400, CUSTOM_OWN_PERMISSIONS);
  await expectRejected(putMember(env, custom.user, orgId, custom.memberId, escalated), 400, CUSTOM_OWN_PERMISSIONS);
  await expectRejected(invite(env, custom.user, orgId, { emails: ['new@example.test'], ...escalated }), 400, CUSTOM_OWN_PERMISSIONS);

  assert.equal((await details(env, owner, orgId, member.memberId)).type, MembershipType.User);
  const granted = { type: MembershipType.Custom, permissions: { accessReports: true } };
  assert.equal((await putMember(env, custom.user, orgId, member.memberId, granted)).status, 200);
  const saved = await details(env, owner, orgId, member.memberId);
  assert.equal(saved.type, MembershipType.Custom);
  assert.deepEqual(saved.permissions, { ...EMPTY_PERMISSIONS, accessReports: true });
});

test('PUT requires a real member type and keeps a confirmed owner', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const ownerMemberId = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!.id;
  const admin = await addMember(env, orgId, MembershipType.Admin);

  await expectRejected(putMember(env, owner, orgId, admin.memberId, {}), 400, 'The Type field is required.');
  await expectRejected(putMember(env, owner, orgId, admin.memberId, { type: MembershipType.Manager }), 400, 'The field Type is invalid.');
  await expectRejected(putMember(env, owner, orgId, ownerMemberId, { type: MembershipType.Admin }), 400, LAST_OWNER);

  assert.equal((await putMember(env, owner, orgId, admin.memberId, { type: MembershipType.Owner })).status, 200);
  assert.equal((await putMember(env, owner, orgId, ownerMemberId, { type: MembershipType.Admin })).status, 200);
  assert.equal((await details(env, admin.user, orgId, ownerMemberId)).type, MembershipType.Admin);
});

// The org creator is stored with accessAll, which official web's update request never sends, so
// PUT must not let that grant outlive a demotion the dialog cannot show or undo.
test('demoting the organization creator drops the full collection access it was created with', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const creatorMemberId = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!.id;
  const secondOwner = await addMember(env, orgId, MembershipType.Owner);

  const demotion = { type: MembershipType.User, collections: [], groups: [], accessSecretsManager: false, accessPam: false };
  assert.equal((await putMember(env, secondOwner.user, orgId, creatorMemberId, demotion)).status, 200);
  assert.equal(hasFullCollectionAccess((await orgRepo.getMembership(env.DB, creatorMemberId))!), false);
});

// Upstream invite and update requests carry no AccessAll, and here it grants every collection
// permission, so a Custom manageUsers member must not be able to hand it out past the role guard.
test('accessAll in an invite or PUT body grants no full collection access', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const custom = await addMember(env, orgId, MembershipType.Custom, { manageUsers: true });
  const selfEdit = { type: MembershipType.Custom, permissions: { manageUsers: true }, accessAll: true };
  assert.equal((await putMember(env, custom.user, orgId, custom.memberId, selfEdit)).status, 200);
  const email = 'alt@example.test';
  assert.equal((await invite(env, custom.user, orgId, { emails: [email], type: MembershipType.User, accessAll: true })).status, 200);

  const stored = await orgRepo.listMembershipsByOrg(env.DB, orgId);
  assert.equal(hasFullCollectionAccess(stored.find((row) => row.id === custom.memberId)!), false);
  // An invited member is not active yet, so check the flag it would carry into confirmation.
  assert.equal(stored.find((row) => row.email === email)!.accessAll, false);
});

// Upstream Invite and GetAuthorizedCollectionsToSaveAsync need ModifyUserAccess on every posted
// collection. With allowAdminAccessToAllCollectionItems off, which NodeWarden applies to Custom
// members, a manageUsers member without editAnyCollection holds it only where it manages.
test('a Custom manageUsers member grants only collections it manages, and never widens its own access', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const ownerMemberId = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!.id;
  const [managed, unmanaged] = [await createCollection(env, owner, orgId), await createCollection(env, owner, orgId)];
  const custom = await addMember(env, orgId, MembershipType.Custom, { manageUsers: true });
  const member = await addMember(env, orgId, MembershipType.User);
  const customBody = { type: MembershipType.Custom, permissions: { manageUsers: true } };
  assert.equal((await putMember(env, owner, orgId, custom.memberId, { ...customBody, collections: [manageAccess(managed)] })).status, 200);

  const grant = [manageAccess(managed), manageAccess(unmanaged)];
  const email = 'accomplice@example.test';
  await expectRejected(putMember(env, custom.user, orgId, custom.memberId, { ...customBody, collections: grant }), 400, SELF_COLLECTION);
  await expectRejected(putMember(env, custom.user, orgId, member.memberId, { type: MembershipType.User, collections: grant }), 404, RESOURCE_NOT_FOUND);
  await expectRejected(invite(env, custom.user, orgId, { emails: [email], type: MembershipType.User, collections: grant }), 404, RESOURCE_NOT_FOUND);
  assert.deepEqual((await details(env, owner, orgId, custom.memberId)).collections, [manageAccess(managed)]);
  assert.deepEqual((await details(env, owner, orgId, member.memberId)).collections, []);
  assert.equal((await orgRepo.listMembershipsByOrg(env.DB, orgId)).some((row) => row.email === email), false);

  // A group grant is collection access too, so upstream's restricted self-edit leaves groups as they are.
  const groupId = await createGroup(env, owner, orgId);
  const collectionPath = `/api/organizations/${orgId}/collections/${unmanaged}`;
  const groupGrant = await authedFetch(env, { method: 'PUT', path: collectionPath, body: { name: '2.c|c|c', groups: [manageAccess(groupId)] }, userId: owner.id });
  assert.equal(groupGrant.status, 200);
  const selfEdit = { ...customBody, collections: [manageAccess(managed)], groups: [groupId] };
  assert.equal((await putMember(env, custom.user, orgId, custom.memberId, selfEdit)).status, 200);
  assert.deepEqual((await details(env, owner, orgId, custom.memberId)).groups, []);

  // Managed collections stay grantable, as does any collection for editAnyCollection members and Owners.
  assert.equal((await putMember(env, custom.user, orgId, member.memberId, { type: MembershipType.User, collections: [manageAccess(managed)] })).status, 200);
  const editor = await addMember(env, orgId, MembershipType.Custom, { manageUsers: true, editAnyCollection: true });
  assert.equal((await invite(env, editor.user, orgId, { emails: [email], type: MembershipType.User, collections: grant })).status, 200);
  assert.equal((await putMember(env, owner, orgId, ownerMemberId, { type: MembershipType.Owner, collections: grant })).status, 200);
});

// Official web posts only the collections the actor can see, each as editable, so PUT keeps the
// member's access to the rest and accepts an unchanged entry it re-posts, but refuses to change it.
// Upstream CanManageCollectionsAsync reads only the stored Manage flag, so "Can edit" is not Manage.
test('PUT keeps member access to collections the actor cannot manage', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const [managed, editable, hidden] = [
    await createCollection(env, owner, orgId),
    await createCollection(env, owner, orgId),
    await createCollection(env, owner, orgId),
  ];
  const custom = await addMember(env, orgId, MembershipType.Custom, { manageUsers: true });
  const member = await addMember(env, orgId, MembershipType.User);
  const customBody = { type: MembershipType.Custom, permissions: { manageUsers: true }, collections: [manageAccess(managed), editAccess(editable)] };
  assert.equal((await putMember(env, owner, orgId, custom.memberId, customBody)).status, 200);
  assert.equal((await putMember(env, owner, orgId, member.memberId, { type: MembershipType.User, collections: [viewAccess(editable), viewAccess(hidden)] })).status, 200);

  const changed = { type: MembershipType.User, collections: [editAccess(editable)] };
  await expectRejected(putMember(env, custom.user, orgId, member.memberId, changed), 404, RESOURCE_NOT_FOUND);
  const selfManage = { ...customBody, collections: [manageAccess(managed), manageAccess(editable)] };
  await expectRejected(putMember(env, custom.user, orgId, custom.memberId, selfManage), 404, RESOURCE_NOT_FOUND);
  const resaved = { type: MembershipType.User, collections: [viewAccess(editable), viewAccess(managed)] };
  assert.equal((await putMember(env, custom.user, orgId, member.memberId, resaved)).status, 200);
  assert.deepEqual(
    (await details(env, owner, orgId, member.memberId)).collections.sort(byId),
    [viewAccess(managed), viewAccess(editable), viewAccess(hidden)].sort(byId)
  );

  assert.equal((await putMember(env, custom.user, orgId, member.memberId, { type: MembershipType.User, collections: [] })).status, 200);
  assert.deepEqual((await details(env, owner, orgId, member.memberId)).collections.sort(byId), [viewAccess(editable), viewAccess(hidden)].sort(byId));
});

test('member details round-trip the permissions, collections and groups that invite and PUT send', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const invitee = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const [readOnlyCollection, editableCollection] = [await createCollection(env, owner, orgId), await createCollection(env, owner, orgId)];
  const groupId = await createGroup(env, owner, orgId);
  const otherOrgId = await createOrg(env, owner);
  const foreignCollection = await createCollection(env, owner, otherOrgId);
  const foreignGroup = await createGroup(env, owner, otherOrgId);

  const readOnlyAccess = { id: readOnlyCollection, readOnly: true, hidePasswords: false, manage: false };
  const inviteBody = {
    emails: [invitee.email],
    type: MembershipType.Custom,
    permissions: { accessReports: true },
    collections: [readOnlyAccess],
    groups: [groupId],
    accessSecretsManager: false,
  };
  await expectRejected(invite(env, owner, orgId, { ...inviteBody, collections: [{ ...readOnlyAccess, id: foreignCollection }] }), 404, 'Resource not found.');
  await expectRejected(invite(env, owner, orgId, { ...inviteBody, groups: [foreignGroup] }), 404, 'Resource not found.');
  // A repeated id is stored once rather than failing the whole invite on the primary key.
  assert.equal((await invite(env, owner, orgId, { ...inviteBody, groups: [groupId, groupId] })).status, 200);

  const listed = await authedFetch(env, { path: `/api/organizations/${orgId}/users`, userId: owner.id });
  const memberId = ((await listed.json()) as { data: Array<{ id: string; email: string }> }).data
    .find((member) => member.email === invitee.email)!.id;
  const invited = await details(env, owner, orgId, memberId);
  assert.equal(invited.object, 'organizationUserDetails');
  assert.equal(invited.status, MembershipStatus.Invited);
  assert.equal(invited.type, MembershipType.Custom);
  assert.deepEqual(invited.permissions, { ...EMPTY_PERMISSIONS, accessReports: true });
  assert.deepEqual(invited.collections, [readOnlyAccess]);
  assert.deepEqual(invited.groups, [groupId]);
  assert.equal('groups' in await details(env, owner, orgId, memberId, ''), false);

  // Collection access chosen at invite follows the invitee once accept binds the account.
  const token = await createOrgInviteToken(env.JWT_SECRET, memberId, invitee.email);
  const accepted = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/accept`, body: { token }, userId: invitee.id });
  assert.equal(accepted.status, 200);
  const bound = await details(env, owner, orgId, memberId);
  assert.equal(bound.userId, invitee.id);
  assert.equal(bound.hasMasterPassword, true);
  assert.deepEqual(bound.collections, [readOnlyAccess]);

  const editableAccess = { id: editableCollection, readOnly: false, hidePasswords: true, manage: false };
  const updateBody = { type: MembershipType.User, permissions: { accessReports: true }, collections: [editableAccess], groups: [], accessSecretsManager: false, accessPam: false };
  await expectRejected(putMember(env, owner, orgId, memberId, { ...updateBody, collections: [{ ...editableAccess, id: foreignCollection }] }), 404, 'Resource not found.');
  await expectRejected(putMember(env, owner, orgId, memberId, { ...updateBody, groups: [foreignGroup] }), 404, 'Resource not found.');
  await expectRejected(putMember(env, owner, orgId, memberId, { ...updateBody, collections: [{ ...editableAccess, manage: true }] }), 400, MANAGE_EXCLUSIVE);
  assert.equal((await putMember(env, owner, orgId, memberId, { ...updateBody, collections: [editableAccess, editableAccess] })).status, 200);
  const updated = await details(env, owner, orgId, memberId);
  assert.equal(updated.type, MembershipType.User);
  assert.equal(updated.permissions, null);
  assert.deepEqual(updated.collections, [editableAccess]);
  assert.deepEqual(updated.groups, []);
});

test('member details are only served to member managers of the same organization', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const member = await addMember(env, orgId, MembershipType.User);
  const otherOrgId = await createOrg(env, owner);

  const forbidden = await authedFetch(env, { path: `/api/organizations/${orgId}/users/${member.memberId}`, userId: member.user.id });
  assert.equal(forbidden.status, 403);
  const crossOrg = await authedFetch(env, { path: `/api/organizations/${otherOrgId}/users/${member.memberId}`, userId: owner.id });
  assert.equal(crossOrg.status, 404);
});

test('collection access larger than one D1 statement is saved in chunks for invited and bound members', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const member = await addMember(env, orgId, MembershipType.User);
  const now = new Date().toISOString();
  const collectionIds = Array.from({ length: MANY_COLLECTIONS }, () => crypto.randomUUID());
  for (const id of collectionIds) {
    await orgRepo.saveCollection(env.DB, { id, orgId, name: '2.c|c|c', externalId: null, createdAt: now, updatedAt: now });
  }
  const collections = collectionIds.map((id) => ({ id, readOnly: false, hidePasswords: false, manage: true }));

  assert.equal((await putMember(env, owner, orgId, member.memberId, { type: MembershipType.User, collections })).status, 200);
  assert.deepEqual((await details(env, owner, orgId, member.memberId)).collections.sort(byId), [...collections].sort(byId));

  const email = 'bulk@example.test';
  assert.equal((await invite(env, owner, orgId, { emails: [email], type: MembershipType.User, collections })).status, 200);
  const invited = (await orgRepo.listMembershipsByOrg(env.DB, orgId)).find((row) => row.email === email)!;
  assert.deepEqual((await details(env, owner, orgId, invited.id)).collections.sort(byId), [...collections].sort(byId));
});

test('collection access saved for an invited member waits for accept like invite-time access', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const invitee = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollection(env, owner, orgId);
  assert.equal((await invite(env, owner, orgId, { emails: [invitee.email], type: MembershipType.User })).status, 200);
  const memberId = (await orgRepo.listMembershipsByOrg(env.DB, orgId)).find((row) => row.email === invitee.email)!.id;

  const access = { id: collectionId, readOnly: true, hidePasswords: false, manage: false };
  const collectionPath = `/api/organizations/${orgId}/collections/${collectionId}`;
  const saved = await authedFetch(env, { method: 'PUT', path: collectionPath, body: { name: '2.c|c|c', users: [{ ...access, id: memberId }] }, userId: owner.id });
  assert.equal(saved.status, 200);
  assert.deepEqual((await details(env, owner, orgId, memberId)).collections, [access]);

  const token = await createOrgInviteToken(env.JWT_SECRET, memberId, invitee.email);
  const accepted = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/accept`, body: { token }, userId: invitee.id });
  assert.equal(accepted.status, 200);
  assert.deepEqual((await details(env, owner, orgId, memberId)).collections, [access]);
});

test('saving a collection for many members writes their access in multi-row statements', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollection(env, owner, orgId);
  const members = await Promise.all(Array.from({ length: MANY_MEMBERS }, () => addMember(env, orgId, MembershipType.User)));
  // D1 counts every statement in a batch toward the per-invocation query limit.
  const batchSizes: number[] = [];
  const runBatch = env.DB.batch.bind(env.DB);
  env.DB.batch = <T>(statements: D1PreparedStatement[]) => {
    batchSizes.push(statements.length);
    return runBatch<T>(statements);
  };

  const users = members.map(({ memberId }) => ({ id: memberId, readOnly: true, hidePasswords: false, manage: false }));
  const collectionPath = `/api/organizations/${orgId}/collections/${collectionId}`;
  const saved = await authedFetch(env, { method: 'PUT', path: collectionPath, body: { name: '2.c|c|c', users }, userId: owner.id });
  assert.equal(saved.status, 200);
  assert.ok(Math.max(...batchSizes) < MANY_MEMBERS, `batch sizes ${batchSizes.join(', ')}`);
  assert.equal((await orgRepo.listCollectionUsers(env.DB, collectionId)).length, MANY_MEMBERS);
});

// collection_users is keyed by user, so removing a member leaves its rows behind for accept to clear.
test('accepting a new invite drops collection access left from an earlier membership', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = await createOrg(env, owner);
  const collectionId = await createCollection(env, owner, orgId);
  const former = await addMember(env, orgId, MembershipType.User);
  const access = { id: collectionId, readOnly: true, hidePasswords: false, manage: false };
  assert.equal((await putMember(env, owner, orgId, former.memberId, { type: MembershipType.User, collections: [access] })).status, 200);
  const removed = await authedFetch(env, { method: 'DELETE', path: `/api/organizations/${orgId}/users/${former.memberId}`, userId: owner.id });
  assert.equal(removed.status, 200);

  assert.equal((await invite(env, owner, orgId, { emails: [former.user.email], type: MembershipType.User, collections: [access] })).status, 200);
  const memberId = (await orgRepo.listMembershipsByOrg(env.DB, orgId)).find((row) => row.email === former.user.email)!.id;
  const token = await createOrgInviteToken(env.JWT_SECRET, memberId, former.user.email);
  const accepted = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/${memberId}/accept`, body: { token }, userId: former.user.id });
  assert.equal(accepted.status, 200);
  assert.deepEqual((await details(env, owner, orgId, memberId)).collections, [access]);
});
