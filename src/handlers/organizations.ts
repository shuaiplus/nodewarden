import type { Env, User } from '../types';
import { LIMITS } from '../config/limits';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import {
  acceptInviteCheck,
  canCreateCollection,
  canDeleteOrganization,
  canManageGroups,
  canManageMembers,
  canManagePolicies,
  canManageScim,
  canActOnCollection,
  type CollectionOperation,
  confirmMemberCheck,
  hasFullCollectionAccess,
  isActiveMember,
  type MemberCheck,
  memberCollectionsCheck,
  memberRemovalCheck,
  memberRoleChangeCheck,
  resolveCollectionPermission,
  resolvePermissions,
  restrictsEditingSelf,
} from '../services/org-authz';
import {
  clientMembershipType,
  EMPTY_PERMISSIONS,
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type CollectionRecord,
  type MembershipRecord,
  type OrgPermissions,
  publicMembershipStatus,
  revokeStatus,
  restoreStatus,
} from '../services/org-types';
import { deleteCiphersByOrganization } from '../services/storage-cipher-repo';
import * as orgRepo from '../services/storage-org-repo';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { organizationResponse, policyResponse } from '../utils/org-response';
import { enterprisePlansResponse } from '../services/enterprise-license';
import { publishPlatformEvent } from '../services/queue-publisher';
import { RateLimitService } from '../services/ratelimit';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { createOrgInviteToken, verifyOrgInviteToken } from '../utils/jwt';
import {
  getEmailSender,
  isReservedDocumentationEmail,
  organizationInviteVaultOrigin,
  sendOrganizationInviteEmail,
} from '../services/mail';

// Official clients always wrap a member's org key with that member's RSA public key (EncString
// types 3-6). Any other type, such as a symmetric type 2, leaves the member unable to decrypt.
const MEMBER_ORG_KEY_PATTERN = /^[3-6]\./;

// Upstream StrictEmailAddressListAttribute on OrganizationUserInviteRequestModel.Emails. Every
// invite sends mail from EMAIL_FROM, so the batch is capped and bad addresses are rejected before
// any row is written.
const MAX_INVITE_EMAILS = 20;
const MAX_INVITE_EMAIL_LENGTH = 256;
// Upstream EmailValidation.IsValidEmail: a local part of printable ASCII other than "@", one "@",
// and a dotted host that ends in a letter.
const INVITE_EMAIL_PATTERN = /^[\x21-\x3f\x41-\x7e]+@[^\s@]+\.\p{L}+$/u;

type MessageCheck = { ok: true } | { ok: false; message: string };
// Failures carry the status and headers every caller answers with, such as Retry-After on a 429.
type StatusCheck = { ok: true } | { ok: false; status: number; message: string; headers: Record<string, string> };

function inviteEmailsCheck(emails: string[]): MessageCheck {
  if (!emails.length) return { ok: false, message: 'An email is required.' };
  if (emails.length > MAX_INVITE_EMAILS) {
    return { ok: false, message: `You can only submit up to ${MAX_INVITE_EMAILS} emails at a time.` };
  }
  // Upstream reports the first failing address, checking its format before its length.
  const [message] = emails.flatMap((email, index) => {
    if (!INVITE_EMAIL_PATTERN.test(email)) return [`Email #${index + 1} is not valid.`];
    if (email.length > MAX_INVITE_EMAIL_LENGTH) return [`Email #${index + 1} is longer than ${MAX_INVITE_EMAIL_LENGTH} characters.`];
    return [];
  });
  return message ? { ok: false, message } : { ok: true };
}

function readBody(source: Record<string, unknown>, names: string[]): unknown {
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(source, name)) return source[name];
  }
  return undefined;
}

function asString(value: unknown): string {
  return String(value || '').trim();
}

function asBoolean(value: unknown, fallback = false): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' ? value as Record<string, unknown> : {};
}

async function requireMember(
  db: D1Database,
  userId: string,
  orgId: string
): Promise<MembershipRecord | Response> {
  const member = await orgRepo.getMembershipByUserAndOrg(db, userId, orgId);
  if (!isActiveMember(member)) return errorResponse('Organization not found', 404);
  return member;
}

// Upstream HasConfirmedOwnersExceptAsync: whether a confirmed Owner other than this member remains.
async function hasOtherConfirmedOwner(db: D1Database, membership: MembershipRecord): Promise<boolean> {
  const isConfirmedOwner = membership.type === MembershipType.Owner && membership.status === MembershipStatus.Confirmed;
  return (await orgRepo.countConfirmedOwners(db, membership.orgId)) > (isConfirmedOwner ? 1 : 0);
}

async function parseJsonBody(request: Request): Promise<Record<string, unknown> | Response> {
  try {
    const body = await request.json() as Record<string, unknown>;
    return body && typeof body === 'object' ? body : {};
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
}

export async function createOwnedOrganization(
  env: Env,
  user: User,
  input: {
    name: string;
    billingEmail?: string;
    collectionName?: string;
    key: string;
    publicKey?: string | null;
    privateKey?: string | null;
    identifier?: string | null;
  }
) {
  const now = new Date().toISOString();
  const orgId = generateUUID();
  const org = {
    id: orgId,
    name: input.name,
    billingEmail: input.billingEmail || user.email,
    identifier: input.identifier || null,
    privateKey: input.privateKey || null,
    publicKey: input.publicKey || null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo.insertOrganization(env.DB, org);
  await orgRepo.saveMembership(env.DB, {
    id: generateUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: true,
    key: input.key,
    status: MembershipStatus.Confirmed,
    type: MembershipType.Owner,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  await orgRepo.saveCollection(env.DB, {
    id: generateUUID(),
    orgId,
    name: input.collectionName || 'Default Collection',
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  await publishPlatformEvent(env, { type: 'org.revision', orgId, actorUserId: user.id });
  return org;
}

export async function handleCreateOrganization(request: Request, env: Env, user: User): Promise<Response> {
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;

  const name = asString(readBody(body, ['name', 'Name']));
  const key = asString(readBody(body, ['key', 'Key']));
  const keys = (readBody(body, ['keys', 'Keys']) || {}) as Record<string, unknown>;
  if (!name || !key) return errorResponse('Name and key are required', 400);

  const org = await createOwnedOrganization(env, user, {
    name,
    billingEmail: asString(readBody(body, ['billingEmail', 'BillingEmail'])) || user.email,
    collectionName: asString(readBody(body, ['collectionName', 'CollectionName'])) || 'Default Collection',
    key,
    identifier: asString(readBody(body, ['identifier', 'Identifier'])) || null,
    privateKey: asString(readBody(keys, ['encryptedPrivateKey', 'EncryptedPrivateKey'])) || null,
    publicKey: asString(readBody(keys, ['publicKey', 'PublicKey'])) || null,
  });
  return jsonResponse(organizationResponse(org));
}

export async function handleGetOrganization(_request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  return jsonResponse(organizationResponse(org));
}

export async function handleUpdateOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse('Access denied', 403);
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  org.name = asString(readBody(body, ['name', 'Name'])) || org.name;
  org.billingEmail = asString(readBody(body, ['billingEmail', 'BillingEmail'])) || org.billingEmail;
  org.updatedAt = new Date().toISOString();
  await orgRepo.updateOrganization(env.DB, org);
  return jsonResponse(organizationResponse(org));
}

export async function handleDeleteOrganization(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canDeleteOrganization(member)) return errorResponse('Only an owner can delete the organization', 403);
  await deleteCiphersByOrganization(env.DB, orgId);
  await orgRepo.deleteOrganization(env.DB, orgId);
  return jsonResponse({});
}

export async function handleLeaveOrganization(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type === MembershipType.Owner && (await orgRepo.countConfirmedOwners(env.DB, orgId)) <= 1) {
    return errorResponse('The last owner cannot leave', 400);
  }
  await orgRepo.deleteMembership(env.DB, member.id);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handlePostOrganizationKeys(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse('Access denied', 403);
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  org.publicKey = asString(readBody(body, ['publicKey', 'PublicKey'])) || org.publicKey;
  org.privateKey = asString(readBody(body, ['encryptedPrivateKey', 'EncryptedPrivateKey'])) || org.privateKey;
  org.updatedAt = new Date().toISOString();
  await orgRepo.updateOrganization(env.DB, org);
  return jsonResponse({ publicKey: org.publicKey, privateKey: org.privateKey, object: 'organizationKeys' });
}

export async function handleGetOrganizationKeys(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  return jsonResponse({ publicKey: org.publicKey, privateKey: org.privateKey, object: 'organizationKeys' });
}

function collectionJson(collection: Awaited<ReturnType<typeof orgRepo.getCollection>>, extra?: Record<string, unknown>) {
  if (!collection) return null;
  return {
    id: collection.id,
    organizationId: collection.orgId,
    name: collection.name,
    externalId: collection.externalId,
    type: 0,
    defaultUserCollectionEmail: null,
    object: extra ? 'collectionDetails' : 'collection',
    ...extra,
  };
}

export async function handleListAllCollections(env: Env, userId: string): Promise<Response> {
  const memberships = await orgRepo.listMembershipsByUser(env.DB, userId);
  const data = [];
  for (const member of memberships) {
    if (!isActiveMember(member)) continue;
    const collections = await orgRepo.listCollectionsByOrg(env.DB, member.orgId);
    const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, member.orgId);
    const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
    for (const collection of collections) {
      const permission = resolveCollectionPermission(member, assignedMap.get(collection.id) || null);
      if (!permission.canView && !hasFullCollectionAccess(member)) continue;
      data.push(collectionJson(collection, {
        readOnly: permission.readOnly,
        hidePasswords: permission.hidePasswords,
        manage: permission.manage,
      }));
    }
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

export async function handleListOrgCollections(env: Env, userId: string, orgId: string): Promise<Response> {
  if (!orgId) return handleListAllCollections(env, userId);
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collections = await orgRepo.listCollectionsByOrg(env.DB, orgId);
  const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, orgId);
  const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
  const visible = collections.filter((collection) => hasFullCollectionAccess(member) || assignedMap.has(collection.id));
  return jsonResponse({
    data: visible.map((collection) => collectionJson(collection)),
    object: 'list',
    continuationToken: null,
  });
}

const NO_ACCESS_GRANTS: orgRepo.CollectionAccessGrants = { users: [], groups: [] };
const NO_ACTOR_FLAGS = { readOnly: false, hidePasswords: false, manage: false };

// Upstream CollectionAccessDetailsResponseModel: the collection with the actor's own access and
// every member and group grant, which official web's collection dialog opens with and saves back
// whole. NodeWarden's sync lists every collection to Owners and Admins, so assigned and the actor's
// flags follow resolveCollectionPermission: the web drops a saved collection that is not assigned
// from the local store that sync fills.
function collectionAccessDetailsJson(
  collection: CollectionRecord,
  member: MembershipRecord,
  access: CollectionAccess | null,
  grants: orgRepo.CollectionAccessGrants
) {
  const permission = resolveCollectionPermission(member, access);
  // Upstream aggregates the actor's own grants, so a reader holding none gets every flag false.
  const { readOnly, hidePasswords, manage } = permission.canView ? permission : NO_ACTOR_FLAGS;
  return collectionJson(collection, {
    readOnly,
    hidePasswords,
    manage,
    assigned: permission.canView,
    // As upstream, no member (invited ones included) or group holds Manage on the collection.
    unmanaged: ![...grants.users, ...grants.groups].some(({ manage }) => manage),
    users: grants.users,
    groups: grants.groups,
    object: 'collectionAccessDetails',
  });
}

async function actorCollectionAccess(db: D1Database, userId: string, orgId: string, collectionId: string): Promise<CollectionAccess | null> {
  return (await orgRepo.listUserCollectionAccess(db, userId, orgId)).find((item) => item.collectionId === collectionId) || null;
}

// Upstream GetManyWithDetails: every collection for those who may read all access, otherwise only
// the collections the member manages.
export async function handleListOrgCollectionDetails(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collections = await orgRepo.listCollectionsByOrg(env.DB, orgId);
  const accessById = new Map((await orgRepo.listUserCollectionAccess(env.DB, userId, orgId)).map((item) => [item.collectionId, item]));
  const grants = await orgRepo.listCollectionAccessGrants(env.DB, orgId);
  const data = collections
    .filter((collection) => canActOnCollection(member, accessById.get(collection.id) || null, 'readAllWithAccess'))
    .map((collection) => collectionAccessDetailsJson(collection, member, accessById.get(collection.id) || null, grants.get(collection.id) || NO_ACCESS_GRANTS));
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// Upstream answers a missing collection and one the actor may not read or update with the same 404.
async function authorizedCollection(
  db: D1Database,
  userId: string,
  orgId: string,
  collectionId: string,
  operation: CollectionOperation
): Promise<{ member: MembershipRecord; collection: CollectionRecord; access: CollectionAccess | null } | Response> {
  const member = await requireMember(db, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo.getCollection(db, collectionId);
  const access = await actorCollectionAccess(db, userId, orgId, collectionId);
  if (!collection || collection.orgId !== orgId || !canActOnCollection(member, access, operation)) {
    return errorResponse('Collection not found', 404);
  }
  return { member, collection, access };
}

async function collectionGrants(db: D1Database, orgId: string, collectionId: string): Promise<orgRepo.CollectionAccessGrants> {
  return (await orgRepo.listCollectionAccessGrants(db, orgId, collectionId)).get(collectionId) || NO_ACCESS_GRANTS;
}

export async function handleGetOrgCollectionDetails(env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const target = await authorizedCollection(env.DB, userId, orgId, collectionId, 'readWithAccess');
  if (target instanceof Response) return target;
  const grants = await collectionGrants(env.DB, orgId, collectionId);
  return jsonResponse(collectionAccessDetailsJson(target.collection, target.member, target.access, grants));
}

// Upstream GetUsers: a bare SelectionReadOnlyResponseModel array, not a list envelope.
export async function handleListOrgCollectionUsers(env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const target = await authorizedCollection(env.DB, userId, orgId, collectionId, 'readAccess');
  if (target instanceof Response) return target;
  return jsonResponse((await collectionGrants(env.DB, orgId, collectionId)).users);
}

// Upstream Post and Put answer with the saved collection's fresh access details when the actor may
// read them, and otherwise with the bare Collection constructor: no grants and every flag false.
async function savedCollectionJson(db: D1Database, userId: string, member: MembershipRecord, collection: CollectionRecord) {
  const access = await actorCollectionAccess(db, userId, collection.orgId, collection.id);
  if (canActOnCollection(member, access, 'readWithAccess')) {
    return collectionAccessDetailsJson(collection, member, access, await collectionGrants(db, collection.orgId, collection.id));
  }
  return collectionJson(collection, {
    ...NO_ACTOR_FLAGS,
    assigned: false,
    unmanaged: false,
    users: null,
    groups: null,
    object: 'collectionAccessDetails',
  });
}

export async function handleCreateOrgCollection(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canCreateCollection(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const collection = {
    id: generateUUID(),
    orgId,
    name: asString(readBody(body, ['name', 'Name'])),
    externalId: asString(readBody(body, ['externalId', 'ExternalId'])) || null,
    createdAt: now,
    updatedAt: now,
  };
  if (!collection.name) return errorResponse('Name is required', 400);
  await orgRepo.saveCollection(env.DB, collection);
  await applyCollectionAccess(env.DB, orgId, collection.id, body);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(await savedCollectionJson(env.DB, userId, member, collection));
}

export async function handleUpdateOrgCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const target = await authorizedCollection(env.DB, userId, orgId, collectionId, 'update');
  if (target instanceof Response) return target;
  const { member, collection } = target;
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  collection.name = asString(readBody(body, ['name', 'Name'])) || collection.name;
  collection.externalId = asString(readBody(body, ['externalId', 'ExternalId'])) || collection.externalId;
  collection.updatedAt = new Date().toISOString();
  await orgRepo.saveCollection(env.DB, collection);
  await applyCollectionAccess(env.DB, collection.orgId, collection.id, body);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(await savedCollectionJson(env.DB, userId, member, collection));
}

export async function handleDeleteOrgCollection(env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo.getCollection(env.DB, collectionId);
  if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
  if (!hasFullCollectionAccess(member) && !resolvePermissions(member).deleteAnyCollection) {
    return errorResponse('Access denied', 403);
  }
  await orgRepo.deleteCollection(env.DB, collectionId);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

function accessFlags(entry: Record<string, unknown>) {
  return {
    readOnly: asBoolean(readBody(entry, ['readOnly', 'ReadOnly'])),
    hidePasswords: asBoolean(readBody(entry, ['hidePasswords', 'HidePasswords'])),
    manage: asBoolean(readBody(entry, ['manage', 'Manage'])),
  };
}

// Membership and group ids come straight from the request body, so each posted entry is matched
// against the organization's own records and unknown ids are skipped. An omitted list stays undefined.
function grantedSelections<T extends { id: string }, R>(entries: unknown, records: T[], grantee: (record: T) => R) {
  if (!Array.isArray(entries)) return undefined;
  const recordsById = new Map(records.map((record) => [record.id, record]));
  return entries.map(asRecord).flatMap((entry) => {
    const record = recordsById.get(asString(readBody(entry, ['id', 'Id'])));
    return record ? [{ ...grantee(record), ...accessFlags(entry) }] : [];
  });
}

// As upstream ReplaceAsync, an omitted list leaves that access as is and an empty one removes it,
// since official web's collection dialog always posts the full lists it opened with. The org's
// members and groups are read once rather than per entry, as every save posts back each grant.
async function applyCollectionAccess(
  db: D1Database,
  orgId: string,
  collectionId: string,
  body: Record<string, unknown>
): Promise<void> {
  const users = readBody(body, ['users', 'Users']);
  const groups = readBody(body, ['groups', 'Groups']);
  const [members, groupRecords] = await Promise.all([
    Array.isArray(users) ? orgRepo.listMembershipsByOrg(db, orgId) : [],
    Array.isArray(groups) ? orgRepo.listGroupsByOrg(db, orgId) : [],
  ]);
  await orgRepo.replaceCollectionAccess(db, collectionId, {
    users: grantedSelections(users, members, (member) => ({ member })),
    groups: grantedSelections(groups, groupRecords, (group) => ({ groupId: group.id })),
  });
}

// Upstream deleted Manager (3), so EnumDataType on the request's Type rejects it like any unknown value.
const ASSIGNABLE_MEMBER_TYPES: number[] = Object.values(MembershipType).filter((type) => type !== MembershipType.Manager);

type MemberChange =
  | { ok: true; type: number; permissions: OrgPermissions; collections?: CollectionAccess[]; groupIds?: string[] }
  | { ok: false; status: number; message: string };

// The role, custom permissions, collections and groups that OrganizationUserInviteRequestModel and
// OrganizationUserUpdateRequestModel share. An omitted collections or groups list leaves that access as is.
async function readMemberChange(db: D1Database, orgId: string, body: Record<string, unknown>): Promise<MemberChange> {
  const type = readBody(body, ['type', 'Type']);
  if (type == null) return { ok: false, status: 400, message: 'The Type field is required.' };
  if (typeof type !== 'number' || !ASSIGNABLE_MEMBER_TYPES.includes(type)) {
    return { ok: false, status: 400, message: 'The field Type is invalid.' };
  }
  const permissionSource = asRecord(readBody(body, ['permissions', 'Permissions']));
  const permissions: OrgPermissions = {
    ...EMPTY_PERMISSIONS,
    ...Object.fromEntries(Object.keys(EMPTY_PERMISSIONS).map((name) => [
      name,
      asBoolean(readBody(permissionSource, [name, name[0].toUpperCase() + name.slice(1)])),
    ])),
  };
  const rawCollections = readBody(body, ['collections', 'Collections']);
  const collections = Array.isArray(rawCollections)
    ? rawCollections.map(asRecord).map((entry) => ({ collectionId: asString(readBody(entry, ['id', 'Id'])), ...accessFlags(entry) }))
    : undefined;
  const rawGroups = readBody(body, ['groups', 'Groups']);
  const groupIds = Array.isArray(rawGroups) ? rawGroups.map(asString) : undefined;
  // Upstream 735cc5db4: every id must belong to this organization, and missing or foreign ids fail
  // alike so the response cannot probe other organizations.
  const orgCollectionIds = new Set((await orgRepo.listCollectionsByOrg(db, orgId)).map((collection) => collection.id));
  const orgGroupIds = new Set((await orgRepo.listGroupsByOrg(db, orgId)).map((group) => group.id));
  const foreignCollection = collections?.some(({ collectionId }) => !orgCollectionIds.has(collectionId));
  if (foreignCollection || groupIds?.some((groupId) => !orgGroupIds.has(groupId))) {
    return { ok: false, status: 404, message: 'Resource not found.' };
  }
  // Upstream CollectionAccessSelection.Valid: Manage already includes seeing and editing every item.
  if (collections?.some(({ manage, readOnly, hidePasswords }) => manage && (readOnly || hidePasswords))) {
    return {
      ok: false,
      status: 400,
      message: 'The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true.',
    };
  }
  return { ok: true, type, permissions, collections, groupIds };
}

// Loads what memberCollectionsCheck compares. An invite has no target yet, so it has no access to
// keep and no self-edit to restrict. An omitted list stays omitted.
async function authorizeMemberCollections(
  db: D1Database,
  actorUserId: string,
  actor: MembershipRecord,
  target: MembershipRecord | null,
  requested: CollectionAccess[] | undefined
): Promise<CollectionAccess[] | undefined | Response> {
  if (!requested) return undefined;
  const check = memberCollectionsCheck({
    actor,
    actorAccess: await orgRepo.listUserCollectionAccess(db, actorUserId, actor.orgId),
    requested,
    current: target ? await orgRepo.listMemberCollectionAccess(db, target) : [],
    restrictSelf: !!target && restrictsEditingSelf(actor, target),
  });
  return check.ok ? check.collections : errorResponse(check.message, check.status);
}

// Upstream stores custom permissions only for the Custom role, so a demoted member keeps no stale grants.
function storedPermissions(change: { type: number; permissions: OrgPermissions }): OrgPermissions | null {
  return change.type === MembershipType.Custom ? change.permissions : null;
}

// The OrganizationUserUserMiniDetailsResponseModel fields, which the full member listing extends.
// Named after the bound account, with the invited email standing in until an account accepts.
function memberMiniDetails(item: MembershipRecord, account: Pick<User, 'name' | 'email'> | null) {
  return {
    id: item.id,
    userId: item.userId,
    type: clientMembershipType(item.type),
    status: publicMembershipStatus(item.status),
    name: account?.name || null,
    email: account?.email || item.email,
  };
}

export async function handleListMembers(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const data = (await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId)).map(({ item, account }) => ({
    ...memberMiniDetails(item, account),
    externalId: item.externalId,
    accessAll: item.accessAll,
    twoFactorEnabled: !!(account?.totpSecret),
    resetPasswordEnrolled: !!item.resetPasswordKey,
    permissions: item.type === MembershipType.Custom ? resolvePermissions(item) : null,
    accessSecretsManager: item.type <= MembershipType.Admin,
    object: 'organizationUserUserDetails',
  }));
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// Upstream OrganizationUsersController.GetMiniDetails: open to every confirmed member because
// official web's collection, group, event log and sponsorship dialogs all look members up here,
// so it carries no keys, permissions or 2FA state.
export async function handleListMemberMiniDetails(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const data = (await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId)).map(({ item, account }) => ({
    ...memberMiniDetails(item, account),
    object: 'organizationUserUserMiniDetails',
  }));
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

// Upstream OrganizationUsersController.Get: the OrganizationUserDetailsResponseModel that official
// web's edit-member dialog loads with includeGroups=true before it can open.
export async function handleGetMember(request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const account = membership.userId ? await new StorageService(env.DB).getUserById(membership.userId) : null;
  const type = clientMembershipType(membership.type);
  const collections = await orgRepo.listMemberCollectionAccess(env.DB, membership);
  const includeGroups = new URL(request.url).searchParams.get('includeGroups') === 'true';
  return jsonResponse({
    id: membership.id,
    userId: membership.userId,
    type,
    status: publicMembershipStatus(membership.status),
    externalId: membership.externalId,
    accessSecretsManager: membership.type <= MembershipType.Admin,
    accessPam: false,
    permissions: type === MembershipType.Custom ? resolvePermissions(membership) : null,
    resetPasswordEnrolled: !!membership.resetPasswordKey,
    usesKeyConnector: false,
    hasMasterPassword: !!account?.masterPasswordHash,
    claimedByOrganization: false,
    ssoExternalId: null,
    collections: collections.map(({ collectionId, ...flags }) => ({ id: collectionId, ...flags })),
    // Upstream omits groups unless asked for them.
    ...(includeGroups ? { groups: await orgRepo.listMembershipGroupIds(env.DB, membership.id) } : {}),
    creationDate: membership.createdAt,
    object: 'organizationUserDetails',
  });
}

export async function handleInviteMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, user.id, orgId);
  if (member instanceof Response) return member;
  if (!canManageMembers(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const emails = ((readBody(body, ['emails', 'Emails']) as string[]) || []).map((email) => String(email || '').trim().toLowerCase()).filter(Boolean);
  const emailsCheck = inviteEmailsCheck(emails);
  if (!emailsCheck.ok) return errorResponse(emailsCheck.message, 400);
  const change = await readMemberChange(env.DB, orgId, body);
  if (!change.ok) return errorResponse(change.message, change.status);
  const collections = await authorizeMemberCollections(env.DB, user.id, member, null, change.collections);
  if (collections instanceof Response) return collections;
  // Upstream InviteUsersAsync runs the same role guard; an invite has no current role, so the
  // requested one stands on both sides.
  const roleCheck = memberRoleChangeCheck(member, change.type, change.type, change.permissions, 'invite');
  if (!roleCheck.ok) return errorResponse(roleCheck.message, 400);
  // Upstream InviteUsersAsync invites each distinct address once and skips any address already in the
  // org by its invited or bound account email (SelectKnownEmailsAsync), so a re-invite neither mails
  // nor adds a row that accept would refuse. Nothing left to invite still succeeds, as upstream.
  const knownEmails = new Set((await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId))
    .flatMap(({ item, account }) => [item.email?.toLowerCase(), account?.email.toLowerCase()]));
  const now = new Date().toISOString();
  // Upstream OrganizationService.InviteUsersAsync: every invite starts Invited and unbound, even for
  // an existing account, so the invitee stays hidden until they accept with the emailed token.
  const invites = [...new Set(emails)].filter((email) => !knownEmails.has(email)).map((email) => ({ id: generateUUID(), email }));
  if (!invites.length) return jsonResponse({});
  const mailed = await mailOrganizationInvites(request, env, orgId, user.id, invites);
  if (!mailed.ok) return errorResponse(mailed.message, mailed.status, mailed.headers);
  await orgRepo.insertInvitedMemberships(env.DB, invites.map(({ id, email }) => ({
    id,
    userId: null,
    orgId,
    email,
    invitedByEmail: user.email,
    // Upstream's invite request has no AccessAll either; see handleEditMember.
    accessAll: false,
    key: '',
    status: MembershipStatus.Invited,
    type: change.type,
    permissions: storedPermissions(change),
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  })), { ...change, collections });
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

// Upstream SendOrganizationInvitesCommand, shared by member invite, reinvite and SCIM provisioning:
// accept needs the emailed token, so every Invited row is mailed. Callers mail before saving, so a
// failed or refused send leaves no row behind (upstream deletes the rows it saved) and a retried
// request cannot pile up duplicates. Without mail configured the rows stay Invited and cannot be accepted yet.
// Any user can create an org and invite any address, so the mail spends a strict budget keyed by
// the inviter across all of their orgs (upstream throttles the invite endpoint per IP instead).
export async function mailOrganizationInvites(
  request: Request,
  env: Env,
  orgId: string,
  inviter: string,
  invites: Array<{ id: string; email: string }>,
): Promise<StatusCheck> {
  if (!env.EMAIL || !getEmailSender(env)) return { ok: true };
  const vaultOrigin = organizationInviteVaultOrigin(request, env);
  if (!vaultOrigin) {
    console.warn('Organization invite email skipped: WEB_VAULT_ORIGINS is not set');
    return { ok: true };
  }

  // Documentation domains bounce and hurt sender reputation, as in register verification.
  const deliverable = invites.filter(({ email }) => !isReservedDocumentationEmail(email));
  const budget = await new RateLimitService(env.DB).consumeStrictBudgetWithWindow(
    `org-invite-mail:${inviter}`,
    LIMITS.rateLimit.orgInviteEmailsPerHour,
    LIMITS.rateLimit.orgInviteEmailWindowSeconds,
    deliverable.length,
  );
  if (!budget.allowed) {
    return {
      ok: false,
      status: 429,
      message: `Rate limit exceeded. Try again in ${budget.retryAfterSeconds} seconds.`,
      headers: { 'Retry-After': String(budget.retryAfterSeconds) },
    };
  }
  const organization = await orgRepo.getOrganization(env.DB, orgId);
  const registered = await orgRepo.listRegisteredEmails(env.DB, deliverable.map(({ email }) => email));
  try {
    await Promise.all(deliverable.map(async ({ id, email }) => sendOrganizationInviteEmail(env, {
      vaultOrigin,
      organizationId: orgId,
      organizationUserId: id,
      organizationName: organization?.name ?? '',
      email,
      token: await createOrgInviteToken(env.JWT_SECRET, id, email),
      hasExistingUser: registered.has(email),
    })));
  } catch (error) {
    console.error('Organization invite email failed:', error instanceof Error ? error.message : String(error));
    return { ok: false, status: 502, message: 'Unable to send invitation email', headers: {} };
  }
  return { ok: true };
}

export async function handleAcceptInvite(request: Request, env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Organization user mismatch', 404);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  // The emailed token is the only proof that this user owns the invited mailbox (upstream
  // OrganizationUserAcceptRequestModel.Token is [Required]).
  const token = asString(readBody(body, ['token', 'Token']));
  if (!token) return errorResponse('The Token field is required.', 400);
  const tokenCheck = await verifyOrgInviteToken(token, env.JWT_SECRET, membership.id, membership.email);
  if (!tokenCheck.ok) return errorResponse(tokenCheck.message, 400);
  const organization = await orgRepo.getOrganization(env.DB, orgId);
  const check = acceptInviteCheck(
    membership,
    user.email,
    await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId),
    organization?.name ?? ''
  );
  if (!check.ok) return errorResponse(check.message, 400);
  await orgRepo.saveAcceptedMembership(env.DB, {
    ...check.member,
    userId: user.id,
    email: user.email,
    status: MembershipStatus.Accepted,
    updatedAt: new Date().toISOString(),
  });
  // The invitee now sees the org in their profile, so their cached sync must refresh.
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

// Upstream OrganizationUserBulkRequestModel.Ids is [Required, MinLength(1)] and defaults to an empty
// list, so an absent field fails MinLength and only an explicit null fails Required.
function readBulkIds(body: Record<string, unknown>): string[] | Response {
  const sentIds = readBody(body, ['ids', 'Ids']);
  const ids = sentIds === undefined ? [] : sentIds;
  if (!Array.isArray(ids)) return errorResponse('The Ids field is required.', 400);
  if (!ids.length) return errorResponse("The field Ids must be a string or array type with a minimum length of '1'.", 400);
  return ids.map(asString);
}

// Upstream OrganizationUserBulkResponseModel, whose object name is the same for every bulk member
// action. Official web counts an entry as done only when its error is the empty string.
function bulkResultsResponse(results: Array<{ id: string; error: string }>): Response {
  return jsonResponse({
    data: results.map((result) => ({ ...result, object: 'OrganizationBulkConfirmResponseModel' })),
    object: 'list',
    continuationToken: null,
  });
}

// Upstream OrganizationUsersController.UserPublicKeys: official web's bulk confirm dialog wraps the
// org key with each selected member's public key before it posts the confirm.
export async function handleListMemberPublicKeys(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const ids = readBulkIds(body);
  if (ids instanceof Response) return ids;
  const keys = await orgRepo.listAcceptedMemberPublicKeys(env.DB, orgId, ids);
  return jsonResponse({
    data: keys.map(({ publicKey, ...member }) => ({ ...member, key: publicKey, object: 'organizationUserPublicKeyResponseModel' })),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleConfirmMember(request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const check = confirmMemberCheck(await orgRepo.getMembership(env.DB, memberId), orgId);
  if (!check.ok) return errorResponse(check.message, 400);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const key = asString(readBody(body, ['key', 'Key']));
  if (!key) return errorResponse('Key is required', 400);
  const confirmed = confirmedWithKey(check, key);
  if (!confirmed.ok) return errorResponse(confirmed.message, 400);
  await orgRepo.saveMembership(env.DB, confirmed.member);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

// The row a passed confirmMemberCheck saves, once its org key is wrapped for the member.
function confirmedWithKey(check: MemberCheck, key: string): MemberCheck {
  if (!check.ok) return check;
  if (!MEMBER_ORG_KEY_PATTERN.test(key)) return { ok: false, message: 'Key is not a valid encrypted string.' };
  return { ok: true, member: { ...check.member, key, status: MembershipStatus.Confirmed, updatedAt: new Date().toISOString() } };
}

// Upstream BulkConfirm: each {id, key} entry is confirmed on its own and reports its own error, and
// the confirmed rows are saved together. Upstream drops entries it will not confirm; every entry
// gets a result here, and the org's rows are read once, so another org's member reads like an id
// that does not exist.
export async function handleBulkConfirmMembers(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const entries = readBody(body, ['keys', 'Keys']);
  if (!Array.isArray(entries)) return errorResponse('The Keys field is required.', 400);
  const membersById = new Map((await orgRepo.listMembershipsByOrg(env.DB, orgId)).map((member) => [member.id, member]));
  // Upstream's ToDictionary rejects a repeated id; here the last key sent for an id wins, so each
  // member is confirmed once.
  const keysById = new Map(entries.map(asRecord).map((entry) => [asString(readBody(entry, ['id', 'Id'])), asString(readBody(entry, ['key', 'Key']))]));
  const results = [...keysById].map(([id, key]) => ({ id, check: confirmedWithKey(confirmMemberCheck(membersById.get(id) ?? null, orgId), key) }));
  const confirmed = results.flatMap(({ check }) => (check.ok ? [check.member] : []));
  if (confirmed.length) {
    await orgRepo.saveMemberships(env.DB, confirmed);
    await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  }
  return bulkResultsResponse(results.map(({ id, check }) => ({ id, error: check.ok ? '' : check.message })));
}

// Upstream ResendOrganizationInviteCommand and BulkResendOrganizationInvitesCommand only mail
// Invited rows of the org; an accepted, confirmed, revoked or staged row is "User invalid.".
const REINVITE_INVALID = 'User invalid.';

function isReinvitable(membership: MembershipRecord | null, orgId: string): membership is MembershipRecord & { email: string } {
  return membership?.status === MembershipStatus.Invited && membership.orgId === orgId && !!membership.email;
}

// A resend mails the row a fresh token through mailOrganizationInvites, so it spends the inviter's
// budget like an invite and recovers an invite whose token has expired.
export async function handleReinviteMember(request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!isReinvitable(membership, orgId)) return errorResponse(REINVITE_INVALID, 400);
  const mailed = await mailOrganizationInvites(request, env, orgId, userId, [membership]);
  if (!mailed.ok) return errorResponse(mailed.message, mailed.status, mailed.headers);
  return jsonResponse({});
}

// Every requested id gets a result and the Invited rows go out in one budgeted send, so a batch
// over the budget mails nothing. Upstream drops missing ids and reports another org's rows; both
// read as "User invalid." here, since only the org's own rows are loaded.
export async function handleBulkReinviteMembers(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const ids = readBulkIds(body);
  if (ids instanceof Response) return ids;
  const membersById = new Map((await orgRepo.listMembershipsByOrg(env.DB, orgId)).map((member) => [member.id, member]));
  const targets = [...new Set(ids)].map((id) => ({ id, membership: membersById.get(id) ?? null }));
  const invites = targets.flatMap(({ membership }) => (isReinvitable(membership, orgId) ? [membership] : []));
  const mailed = await mailOrganizationInvites(request, env, orgId, userId, invites);
  if (!mailed.ok) return errorResponse(mailed.message, mailed.status, mailed.headers);
  return bulkResultsResponse(targets.map(({ id, membership }) => ({ id, error: isReinvitable(membership, orgId) ? '' : REINVITE_INVALID })));
}

export async function handleEditMember(request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const change = await readMemberChange(env.DB, orgId, body);
  if (!change.ok) return errorResponse(change.message, change.status);
  const collections = await authorizeMemberCollections(env.DB, userId, actor, membership, change.collections);
  if (collections instanceof Response) return collections;
  const roleCheck = memberRoleChangeCheck(actor, clientMembershipType(membership.type), change.type, change.permissions, 'update');
  if (!roleCheck.ok) return errorResponse(roleCheck.message, 400);
  // Leaving Owner must leave another confirmed owner behind.
  if (change.type !== MembershipType.Owner && !(await hasOtherConfirmedOwner(env.DB, membership))) {
    return errorResponse('Organization must have at least one confirmed owner.', 400);
  }
  membership.type = change.type;
  membership.permissions = storedPermissions(change);
  // Upstream's update request has no AccessAll: Owners and Admins get full access from their type,
  // and a body flag would let a Custom manageUsers member grant every collection permission past
  // memberRoleChangeCheck. Clearing it also stops a demoted org creator keeping full access.
  membership.accessAll = false;
  membership.updatedAt = new Date().toISOString();
  // Upstream skips groups on a restricted self-edit rather than failing it, as groups carry collection access.
  const groupIds = restrictsEditingSelf(actor, membership) ? undefined : change.groupIds;
  await orgRepo.saveMembershipWithAccess(env.DB, membership, { collections, groupIds });
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleDeleteMember(env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const removalCheck = memberRemovalCheck(actor, clientMembershipType(membership.type), 'remove');
  if (!removalCheck.ok) return errorResponse(removalCheck.message, 400);
  if (membership.type === MembershipType.Owner && !(await hasOtherConfirmedOwner(env.DB, membership))) {
    return errorResponse('Organization must have at least one confirmed owner.', 400);
  }
  await orgRepo.deleteMembership(env.DB, memberId);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleRevokeMember(env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const removalCheck = memberRemovalCheck(actor, clientMembershipType(membership.type), 'revoke');
  if (!removalCheck.ok) return errorResponse(removalCheck.message, 400);
  // Only an Owner can restore an Owner, so revoking the last confirmed one would leave nobody able to undo it.
  if (membership.type === MembershipType.Owner && !(await hasOtherConfirmedOwner(env.DB, membership))) {
    return errorResponse('Organization must have at least one confirmed owner.', 400);
  }
  membership.status = revokeStatus(membership.status);
  membership.updatedAt = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, membership);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleRestoreMember(env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const removalCheck = memberRemovalCheck(actor, clientMembershipType(membership.type), 'restore');
  if (!removalCheck.ok) return errorResponse(removalCheck.message, 400);
  membership.status = restoreStatus(membership.status);
  membership.updatedAt = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, membership);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleListGroups(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const groups = await orgRepo.listGroupsByOrg(env.DB, orgId);
  const data = [];
  for (const group of groups) {
    data.push({
      id: group.id,
      organizationId: group.orgId,
      name: group.name,
      accessAll: group.accessAll,
      externalId: group.externalId,
      collections: [],
      users: await orgRepo.listGroupMemberIds(env.DB, group.id),
      object: 'groupDetails',
    });
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

export async function handleSaveGroup(request: Request, env: Env, userId: string, orgId: string, groupId?: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageGroups(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const existing = groupId ? await orgRepo.getGroup(env.DB, groupId) : null;
  if (groupId && (!existing || existing.orgId !== orgId)) return errorResponse('Group not found', 404);
  const group = {
    id: existing?.id || generateUUID(),
    orgId,
    name: asString(readBody(body, ['name', 'Name'])) || existing?.name || 'Group',
    accessAll: asBoolean(readBody(body, ['accessAll', 'AccessAll']), existing?.accessAll || false),
    externalId: asString(readBody(body, ['externalId', 'ExternalId'])) || existing?.externalId || null,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };
  await orgRepo.saveGroup(env.DB, group);
  const users = ((readBody(body, ['users', 'Users']) as string[]) || []).map((id) => String(id));
  if (users.length || !existing) await orgRepo.replaceGroupMembers(env.DB, group.id, users);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({
    id: group.id,
    organizationId: group.orgId,
    name: group.name,
    accessAll: group.accessAll,
    externalId: group.externalId,
    object: 'group',
  });
}

export async function handleDeleteGroup(env: Env, userId: string, orgId: string, groupId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageGroups(member)) return errorResponse('Access denied', 403);
  const group = await orgRepo.getGroup(env.DB, groupId);
  if (!group || group.orgId !== orgId) return errorResponse('Group not found', 404);
  await orgRepo.deleteGroup(env.DB, groupId);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleListPolicies(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const policies = await orgRepo.listPoliciesByOrg(env.DB, orgId);
  return jsonResponse({ data: policies.map(policyResponse), object: 'list', continuationToken: null });
}

// Official web's policy drawer loads one policy here. Upstream PolicyQuery synthesizes a disabled
// status with empty data when no row exists, so the drawer opens with the toggle off.
export async function handleGetPolicy(env: Env, userId: string, orgId: string, policyType: number): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse('Access denied', 403);
  const policy = await orgRepo.getPolicy(env.DB, orgId, policyType);
  return jsonResponse(policy
    ? policyResponse(policy)
    : { organizationId: orgId, type: policyType, enabled: false, data: {}, object: 'policy' });
}

export async function handlePutPolicy(request: Request, env: Env, userId: string, orgId: string, policyType: number): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  // Official clients send SavePolicyRequest {policy:{enabled,data},metadata}; NodeWarden's webapp
  // still sends the flat policy. Metadata only feeds upstream side effects we do not run. Upstream
  // marks Policy [Required], so a malformed envelope is rejected instead of saving a disabled policy.
  const envelope = readBody(body, ['policy', 'Policy']);
  if (envelope !== undefined && (!envelope || typeof envelope !== 'object' || Array.isArray(envelope))) {
    return errorResponse('The Policy field is required.', 400);
  }
  const source = asRecord(envelope ?? body);
  const existing = await orgRepo.getPolicy(env.DB, orgId, policyType);
  const policy = {
    id: existing?.id || generateUUID(),
    orgId,
    type: policyType,
    enabled: asBoolean(readBody(source, ['enabled', 'Enabled'])),
    data: (readBody(source, ['data', 'Data']) as Record<string, unknown>) || {},
    updatedAt: new Date().toISOString(),
  };
  await orgRepo.savePolicy(env.DB, policy);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(policyResponse(policy));
}

export async function handleGetPlans(): Promise<Response> {
  return jsonResponse(enterprisePlansResponse());
}

// Bitwarden guards the organization API key endpoints with a SecretVerificationRequestModel,
// so re-authenticate the caller before minting a key instead of trusting the session alone.
async function verifyMasterPassword(env: Env, userId: string, body: Record<string, unknown>): Promise<Response | null> {
  const secret = asString(readBody(body, ['masterPasswordHash', 'MasterPasswordHash', 'secret', 'Secret']));
  if (!secret) return errorResponse('masterPasswordHash is required', 400);
  const user = await new StorageService(env.DB).getUserById(userId);
  if (!user) return errorResponse('User not found', 404);
  const valid = await new AuthService(env).verifyPassword(secret, user.masterPasswordHash, user.email);
  return valid ? null : errorResponse('Invalid password', 400);
}

export async function handleOrgApiKey(request: Request, env: Env, userId: string, orgId: string, rotate: boolean): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const unverified = await verifyMasterPassword(env, userId, body);
  if (unverified) return unverified;

  // Only the hash is persisted, so an existing key can never be displayed again:
  // a non-rotating read has nothing to hand back and must be rotated instead.
  const existing = await orgRepo.getOrganizationApiKey(env.DB, orgId);
  if (!rotate && existing) {
    return errorResponse('The organization API key is only shown when it is created or rotated. Rotate it to get a new key.', 409);
  }

  const apiKey = generateUUID().replace(/-/g, '') + generateUUID().replace(/-/g, '');
  const revisionDate = new Date().toISOString();
  await orgRepo.saveOrganizationApiKey(env.DB, {
    id: existing?.id || generateUUID(),
    orgId,
    type: 0,
    apiKeyHash: await hashApiKey(apiKey),
    revisionDate,
  });
  return jsonResponse({ apiKey, revisionDate, object: 'organizationApiKey' });
}

export async function handleRotateScimKey(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageScim(member)) return errorResponse('Access denied', 403);
  const token = `scim.${orgId}.${generateUUID().replace(/-/g, '')}`;
  await orgRepo.saveScimToken(env.DB, orgId, await hashApiKey(token), new Date().toISOString());
  return jsonResponse({ token, object: 'organizationScimKey' });
}

export async function verifyScimBearer(env: Env, orgId: string, authorization: string | null): Promise<boolean> {
  const token = String(authorization || '').replace(/^Bearer\s+/i, '').trim();
  if (!token) return false;
  const stored = await orgRepo.getScimTokenHash(env.DB, orgId);
  if (!stored) return false;
  return verifyApiKey(token, stored);
}

export async function handleGetAutoEnrollStatus(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  return jsonResponse({
    id: orgId,
    resetPasswordEnabled: false,
    object: 'organizationAutoEnrollStatus',
    enrolled: !!member?.resetPasswordKey,
  });
}

export function emptyCollectionAccess(): CollectionAccess[] {
  return [];
}
