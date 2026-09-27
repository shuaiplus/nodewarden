import { z } from 'zod';
import { twoFactorProviders } from '../services/two-factor-providers';
import type { Env, User } from '../types';
import { LIMITS } from '../config/limits';
import { EventType, recordEvents } from '../services/events';
import { AuthService } from '../services/auth';
import {
  acceptInviteCheck,
  canAccessSecretsManager,
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
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type CollectionRecord,
  type MembershipRecord,
  OrgPermissions,
  publicMembershipStatus,
} from '../services/org-types';
import { deleteOrganizationAccount } from '../services/account-deletion';
import * as orgRepo from '../services/storage-org-repo';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID, isUUID } from '../utils/uuid';
import { organizationResponse, policyResponse } from '../utils/org-response';
import { enterprisePlansResponse } from '../services/enterprise-license';
import { publishPlatformEvent } from '../services/queue-publisher';
import { RateLimitService } from '../services/ratelimit';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { createOrgInviteToken, verifyOrgInviteToken, ORG_INVITE_TTL_DAYS } from '../utils/jwt';
import { runInBackground } from '../services/mail-notify';
import {
  readMailConfig,
  mailStatusCheck,
  EMAIL_PATTERN,
  type StatusCheck,
  isReservedDocumentationEmail,
  configuredVaultOrigin,
  sendMail,
} from '../services/mail';
import * as userRepo from '../services/storage-user-repo';

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

type MessageCheck = { ok: true } | { ok: false; message: string };
// Failures carry the status and headers every caller answers with, such as Retry-After on a 429.

function inviteEmailsCheck(emails: string[]): MessageCheck {
  if (!emails.length) return { ok: false, message: 'An email is required.' };
  if (emails.length > MAX_INVITE_EMAILS) {
    return { ok: false, message: `You can only submit up to ${MAX_INVITE_EMAILS} emails at a time.` };
  }
  // Upstream reports the first failing address, checking its format before its length.
  const [message] = emails.flatMap((email, index) => {
    if (!EMAIL_PATTERN.test(email)) return [`Email #${index + 1} is not valid.`];
    if (email.length > MAX_INVITE_EMAIL_LENGTH) return [`Email #${index + 1} is longer than ${MAX_INVITE_EMAIL_LENGTH} characters.`];
    return [];
  });
  return message ? { ok: false, message } : { ok: true };
}

// Clients post null or '' for unset text, so a blank value falls back to the stored one.
const optionalText = z.string().trim().nullish();
const requiredText = (message: string) => z.string({ error: message }).trim().min(1, { error: message });

const OrganizationKeysRequest = z.object({ publicKey: optionalText, encryptedPrivateKey: optionalText });

const CreateOrganizationRequest = z.object({
  name: requiredText('Name and key are required'),
  key: requiredText('Name and key are required'),
  billingEmail: optionalText,
  collectionName: optionalText,
  identifier: optionalText,
  keys: OrganizationKeysRequest.nullish(),
});

// Upstream CollectionAccessSelection; a flag that is not a boolean reads as false.
const accessFlag = z.boolean().catch(false);
const AccessSelection = z.object({ id: z.string(), readOnly: accessFlag, hidePasswords: accessFlag, manage: accessFlag });
type AccessSelection = z.output<typeof AccessSelection>;

const CollectionRequest = z.object({
  name: optionalText,
  externalId: optionalText,
  users: z.array(AccessSelection).nullish(),
  groups: z.array(AccessSelection).nullish(),
});

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
  const body = await parseBody(request, CreateOrganizationRequest);
  if (body instanceof Response) return body;

  const org = await createOwnedOrganization(env, user, {
    name: body.name,
    billingEmail: body.billingEmail || user.email,
    collectionName: body.collectionName || 'Default Collection',
    key: body.key,
    identifier: body.identifier || null,
    privateKey: body.keys?.encryptedPrivateKey || null,
    publicKey: body.keys?.publicKey || null,
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
  const body = await parseBody(request, z.object({ name: optionalText, billingEmail: optionalText }));
  if (body instanceof Response) return body;
  const previousSettings = [org.name, org.billingEmail];
  org.name = body.name || org.name;
  org.billingEmail = body.billingEmail || org.billingEmail;
  org.updatedAt = new Date().toISOString();
  await orgRepo.updateOrganization(env.DB, org);
  if (org.name !== previousSettings[0] || org.billingEmail !== previousSettings[1]) {
    await recordEvents(env, request, { userId }, [{ type: EventType.OrganizationUpdated, organizationId: orgId }]);
  }
  return jsonResponse(organizationResponse(org));
}

export async function handleDeleteOrganization(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canDeleteOrganization(member)) return errorResponse('Only an owner can delete the organization', 403);
  await deleteOrganizationAccount(env, orgId, {
    actorUserId: userId,
    action: 'organization.delete',
    category: 'security',
    level: 'security',
    targetType: 'organization',
    targetId: orgId,
  });
  return jsonResponse({});
}

export async function handleLeaveOrganization(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type === MembershipType.Owner && (await orgRepo.countConfirmedOwners(env.DB, orgId)) <= 1) {
    return errorResponse('The last owner cannot leave', 400);
  }
  await orgRepo.applyMembershipAction(env.DB, orgId, [member.id], 'remove');
  await recordEvents(env, request, { userId }, [{ type: EventType.OrganizationUserLeft, organizationId: orgId, resourceType: 'organizationUser', resourceId: member.id, userId: member.userId }]);
  return jsonResponse({});
}

export async function handlePostOrganizationKeys(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse('Access denied', 403);
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return errorResponse('Organization not found', 404);
  const body = await parseBody(request, OrganizationKeysRequest);
  if (body instanceof Response) return body;
  const previousKeys = [org.publicKey, org.privateKey];
  org.publicKey = body.publicKey || org.publicKey;
  org.privateKey = body.encryptedPrivateKey || org.privateKey;
  org.updatedAt = new Date().toISOString();
  await orgRepo.updateOrganization(env.DB, org);
  if (org.publicKey !== previousKeys[0] || org.privateKey !== previousKeys[1]) {
    await recordEvents(env, request, { userId }, [{ type: EventType.OrganizationUpdated, organizationId: orgId }]);
  }
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
  // The 9.0 member-access report maps grants in the client; AccessReports needs this bulk metadata
  // even though upstream's old collection gate omits it. Single-resource and write gates stay separate.
  const canReadReports = resolvePermissions(member).accessReports;
  const data = collections
    .filter((collection) => canReadReports || canActOnCollection(member, accessById.get(collection.id) || null, 'readAllWithAccess'))
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
  const body = await parseBody(request, CollectionRequest.extend({ name: requiredText('Name is required') }));
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const collection = {
    id: generateUUID(),
    orgId,
    name: body.name,
    externalId: body.externalId || null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo.saveCollection(env.DB, collection);
  await applyCollectionAccess(env.DB, orgId, collection.id, body);
  await recordEvents(env, request, { userId }, [{ type: EventType.CollectionCreated, organizationId: orgId, resourceType: 'collection', resourceId: collection.id }]);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(await savedCollectionJson(env.DB, userId, member, collection));
}

export async function handleUpdateOrgCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const target = await authorizedCollection(env.DB, userId, orgId, collectionId, 'update');
  if (target instanceof Response) return target;
  const { member, collection } = target;
  const body = await parseBody(request, CollectionRequest);
  if (body instanceof Response) return body;
  const previousSettings = [collection.name, collection.externalId];
  collection.name = body.name || collection.name;
  collection.externalId = body.externalId || collection.externalId;
  collection.updatedAt = new Date().toISOString();
  await orgRepo.saveCollection(env.DB, collection);
  const accessChanged = await applyCollectionAccess(env.DB, collection.orgId, collection.id, body);
  if (accessChanged || collection.name !== previousSettings[0] || collection.externalId !== previousSettings[1]) {
    await recordEvents(env, request, { userId }, [{ type: EventType.CollectionUpdated, organizationId: orgId, resourceType: 'collection', resourceId: collection.id }]);
  }
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(await savedCollectionJson(env.DB, userId, member, collection));
}

export async function handleDeleteOrgCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo.getCollection(env.DB, collectionId);
  if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
  if (!hasFullCollectionAccess(member) && !resolvePermissions(member).deleteAnyCollection) {
    return errorResponse('Access denied', 403);
  }
  await orgRepo.deleteCollection(env.DB, collectionId);
  await recordEvents(env, request, { userId }, [{ type: EventType.CollectionDeleted, organizationId: collection.orgId, resourceType: 'collection', resourceId: collection.id }]);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

// Membership and group ids come straight from the request body, so each posted entry is matched
// against the organization's own records and unknown ids are skipped. An omitted list stays undefined.
function grantedSelections<T extends { id: string }, R>(entries: AccessSelection[] | null | undefined, records: T[], grantee: (record: T) => R) {
  if (!entries) return undefined;
  const recordsById = new Map(records.map((record) => [record.id, record]));
  return entries.flatMap(({ id, ...flags }) => {
    const record = recordsById.get(id);
    return record ? [{ ...grantee(record), ...flags }] : [];
  });
}

function accessEventState(entries: unknown[]): string {
  return JSON.stringify(entries.map(entry => JSON.stringify(entry, Object.keys(entry as object).sort())).sort());
}

// As upstream ReplaceAsync, an omitted list leaves that access as is and an empty one removes it,
// since official web's collection dialog always posts the full lists it opened with. The org's
// members and groups are read once rather than per entry, as every save posts back each grant.
async function applyCollectionAccess(
  db: D1Database,
  orgId: string,
  collectionId: string,
  { users, groups }: z.output<typeof CollectionRequest>
): Promise<boolean> {
  if (!users && !groups) return false;
  const [members, groupRecords] = await Promise.all([
    users ? orgRepo.listMembershipsByOrg(db, orgId) : [],
    groups ? orgRepo.listGroupsByOrg(db, orgId) : [],
  ]);
  const previous = (await orgRepo.listCollectionAccessGrants(db, orgId, collectionId)).get(collectionId) ?? { users: [], groups: [] };
  const selection = {
    users: grantedSelections(users, members, (member) => ({ member })),
    groups: grantedSelections(groups, groupRecords, (group) => ({ groupId: group.id })),
  };
  await orgRepo.replaceCollectionAccess(db, collectionId, selection);
  return (selection.users !== undefined && accessEventState(previous.users) !== accessEventState(selection.users.map(({ member, ...flags }) => ({ id: member.id, ...flags }))))
    || (selection.groups !== undefined && accessEventState(previous.groups) !== accessEventState(selection.groups.map(({ groupId, ...flags }) => ({ id: groupId, ...flags }))));
}

// Upstream deleted Manager (3), so EnumDataType on the request's Type rejects it like any unknown value.
const ASSIGNABLE_MEMBER_TYPES = Object.values(MembershipType).filter((type) => type !== MembershipType.Manager);

// The role, custom permissions, collections and groups that OrganizationUserInviteRequestModel and
// OrganizationUserUpdateRequestModel share. An omitted collections or groups list leaves that access as is.
const memberChangeFields = {
  type: z.literal(ASSIGNABLE_MEMBER_TYPES, {
    error: ({ input }) => (input == null ? 'The Type field is required.' : 'The field Type is invalid.'),
  }),
  permissions: OrgPermissions,
  collections: z.array(AccessSelection).nullish(),
  groups: z.array(z.string()).nullish(),
};
const MemberUpdateRequest = z.object(memberChangeFields);

// Upstream checks the invited emails before the rest of the request.
const MemberInviteRequest = z.object({
  emails: z.array(z.string()).nullish()
    .transform((emails) => (emails ?? []).map((email) => email.trim().toLowerCase()).filter(Boolean))
    .superRefine((emails, context) => {
      const check = inviteEmailsCheck(emails);
      if (!check.ok) context.addIssue({ code: 'custom', message: check.message });
    }),
  ...memberChangeFields,
});

type MemberChange =
  | { ok: true; type: number; permissions: OrgPermissions; collections?: CollectionAccess[]; groupIds?: string[] }
  | { ok: false; status: number; message: string };

// Checks the requested collections and groups against the organization's own records.
async function readMemberChange(db: D1Database, orgId: string, body: z.output<typeof MemberUpdateRequest>): Promise<MemberChange> {
  const collections = body.collections?.map(({ id, ...flags }) => ({ collectionId: id, ...flags }));
  const groupIds = body.groups ?? undefined;
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
  return { ok: true, type: body.type, permissions: body.permissions, collections, groupIds };
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

export async function handleListMembers(env: Env, userId: string, orgId: string, includeGroups = false): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const groupsByMember = includeGroups ? await orgRepo.listMembershipGroupIdsByOrg(env.DB, orgId) : null;
  const data = (await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId)).map(({ item, account, hasTwoFactorPasskey }) => ({
    ...memberMiniDetails(item, account),
    ...(groupsByMember ? { groups: groupsByMember.get(item.id) || [] } : {}),
    externalId: item.externalId,
    accessAll: item.accessAll,
    twoFactorEnabled: account ? twoFactorProviders(account, hasTwoFactorPasskey).length > 0 : false,
    resetPasswordEnrolled: !!item.resetPasswordKey,
    permissions: item.type === MembershipType.Custom ? resolvePermissions(item) : null,
    accessSecretsManager: canAccessSecretsManager(item),
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
  const account = membership.userId ? await userRepo.getUserById(env.DB, membership.userId) : null;
  const type = clientMembershipType(membership.type);
  const collections = await orgRepo.listMemberCollectionAccess(env.DB, membership);
  const includeGroups = new URL(request.url).searchParams.get('includeGroups') === 'true';
  return jsonResponse({
    id: membership.id,
    userId: membership.userId,
    type,
    status: publicMembershipStatus(membership.status),
    externalId: membership.externalId,
    accessSecretsManager: canAccessSecretsManager(membership),
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
  const body = await parseBody(request, MemberInviteRequest);
  if (body instanceof Response) return body;
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
  const invites = [...new Set(body.emails)].filter((email) => !knownEmails.has(email)).map((email) => ({ id: generateUUID(), email, invitedByEmail: user.email }));
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
  await recordEvents(env, request, { userId: user.id }, invites.map(invite => ({ type: EventType.OrganizationUserInvited, organizationId: orgId, resourceType: 'organizationUser', resourceId: invite.id })));
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
  invites: Array<{ id: string; email: string; invitedByEmail?: string | null }>,
): Promise<StatusCheck> {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled') return mailStatusCheck(config);
  const vaultOrigin = configuredVaultOrigin(request, env);
  if (!vaultOrigin) {
    console.warn('Organization invite email skipped: WEB_VAULT_ORIGINS is not set');
    return { ok: true };
  }

  // Documentation domains bounce and hurt sender reputation, as in register verification.
  const deliverable = invites.filter(({ email }) => !isReservedDocumentationEmail(email));
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
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
  const expiresAt = Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_DAYS * 86400;
  const outcomes = await Promise.all(deliverable.map(async ({ id, email, invitedByEmail }) => sendMail(env, email, 'organizationInvite', {
    vaultOrigin, organizationId: orgId, organizationUserId: id,
    organizationName: organization?.name ?? '', email,
    token: await createOrgInviteToken(env.JWT_SECRET, id, email, expiresAt), hasExistingUser: registered.has(email),
    inviterEmail: !inviter.startsWith('scim:') && invitedByEmail && EMAIL_PATTERN.test(invitedByEmail) ? invitedByEmail : undefined,
    expiresAt: new Date(expiresAt * 1000).toISOString(),
  })));
  for (const outcome of outcomes) { const check = mailStatusCheck(outcome); if (!check.ok) return check; }
  return { ok: true };
}

export async function handleAcceptInvite(request: Request, env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Organization user mismatch', 404);
  // The emailed token is the only proof that this user owns the invited mailbox (upstream
  // OrganizationUserAcceptRequestModel.Token is [Required]).
  const body = await parseBody(request, z.object({ token: requiredText('The Token field is required.') }));
  if (body instanceof Response) return body;
  const tokenCheck = await verifyOrgInviteToken(body.token, env.JWT_SECRET, membership.id, membership.email);
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
  runInBackground('organization-user-accepted', async () => {
    for (const { item, account } of await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId)) {
      const email = account?.email || item.email;
      if (item.status !== MembershipStatus.Confirmed || item.type > MembershipType.Admin || item.userId === user.id || !email) continue;
      await sendMail(env, email, 'organizationUserAccepted', { organizationName: organization?.name || '', memberName: user.name || user.email });
    }
  });
  return jsonResponse({});
}

function notifyConfirmedMembers(request: Request, env: Env, orgId: string, members: MembershipRecord[]): void {
  const vaultOrigin = configuredVaultOrigin(request, env);
  runInBackground('organization-user-confirmed', async () => {
    const ids = new Set(members.map((member) => member.id));
    const [organization, rows] = await Promise.all([
      orgRepo.getOrganization(env.DB, orgId), orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId),
    ]);
    for (const { item, account } of rows) {
      const email = account?.email || item.email;
      if (ids.has(item.id) && email) await sendMail(env, email, 'organizationUserConfirmed', { organizationName: organization?.name || '', vaultOrigin });
    }
  });
}

// Upstream OrganizationUserBulkRequestModel.Ids is [Required, MinLength(1)] and defaults to an empty
// list, so an absent field fails MinLength and only an explicit null fails Required.
const BulkIdsRequest = z.object({
  ids: z.array(z.string(), { error: 'The Ids field is required.' })
    .min(1, { error: "The field Ids must be a string or array type with a minimum length of '1'." })
    .prefault([]),
});

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
  const body = await parseBody(request, BulkIdsRequest);
  if (body instanceof Response) return body;
  const { ids } = body;
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
  const body = await parseBody(request, z.object({ key: requiredText('Key is required') }));
  if (body instanceof Response) return body;
  const confirmed = confirmedWithKey(check, body.key);
  if (!confirmed.ok) return errorResponse(confirmed.message, 400);
  await orgRepo.saveMembership(env.DB, confirmed.member);
  await recordEvents(env, request, { userId }, [{ type: EventType.OrganizationUserConfirmed, organizationId: orgId, resourceType: 'organizationUser', resourceId: confirmed.member.id, userId: confirmed.member.userId }]);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  notifyConfirmedMembers(request, env, orgId, [confirmed.member]);
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
  const body = await parseBody(request, z.object({
    keys: z.array(z.object({ id: z.string(), key: z.string().trim() }), { error: 'The Keys field is required.' }),
  }));
  if (body instanceof Response) return body;
  const membersById = new Map((await orgRepo.listMembershipsByOrg(env.DB, orgId)).map((member) => [member.id, member]));
  // Upstream's ToDictionary rejects a repeated id; here the last key sent for an id wins, so each
  // member is confirmed once.
  const keysById = new Map(body.keys.map(({ id, key }) => [id, key]));
  const results = [...keysById].map(([id, key]) => ({ id, check: confirmedWithKey(confirmMemberCheck(membersById.get(id) ?? null, orgId), key) }));
  const confirmed = results.flatMap(({ check }) => (check.ok ? [check.member] : []));
  if (confirmed.length) {
    await orgRepo.saveMemberships(env.DB, confirmed);
    await recordEvents(env, request, { userId }, confirmed.map(member => ({ type: EventType.OrganizationUserConfirmed, organizationId: orgId, resourceType: 'organizationUser', resourceId: member.id, userId: member.userId })));
    await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
    notifyConfirmedMembers(request, env, orgId, confirmed);
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
  const body = await parseBody(request, BulkIdsRequest);
  if (body instanceof Response) return body;
  const { ids } = body;
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
  const body = await parseBody(request, MemberUpdateRequest);
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
  const previousType = membership.type;
  const previousPermissions = JSON.stringify(membership.permissions);
  const previousAccessAll = membership.accessAll;
  const previousCollections = collections ? await orgRepo.listMemberCollectionAccess(env.DB, membership) : [];
  const previousGroups = change.groupIds ? await orgRepo.listMembershipGroupIds(env.DB, membership.id) : [];
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
  const memberChanged = previousType !== membership.type || previousPermissions !== JSON.stringify(membership.permissions)
    || previousAccessAll !== membership.accessAll || (collections !== undefined && accessEventState(previousCollections) !== accessEventState(collections));
  const groupsChanged = groupIds !== undefined && JSON.stringify([...new Set(previousGroups)].sort()) !== JSON.stringify([...new Set(groupIds)].sort());
  // Upstream's member update logs OrganizationUser_Updated even when only groups change; it reserves
  // OrganizationUser_UpdatedGroups for the group endpoints.
  if (memberChanged || groupsChanged) {
    await recordEvents(env, request, { userId }, [{ type: EventType.OrganizationUserUpdated, organizationId: orgId, resourceType: 'organizationUser', resourceId: membership.id, userId: membership.userId }]);
  }
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

type MemberAction = 'remove' | 'revoke' | 'restore';

// One membership transition for any number of ids: per-id role checks, the last-confirmed-owner
// guard (an Owner can only be restored by another Owner), then one chunked batch and its events.
async function applyMemberAction(request: Request, env: Env, userId: string, orgId: string, ids: string[], action: MemberAction): Promise<Array<{ id: string; error: string }> | Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const members = await orgRepo.listMembershipsByOrg(env.DB, orgId);
  const byId = new Map(members.map((member) => [member.id, member]));
  const results = [...new Set(ids)].map((id) => {
    const member = byId.get(id);
    const check = member ? memberRemovalCheck(actor, member, action) : { ok: false as const, message: 'Invalid user.' };
    return { id, error: check.ok ? '' : check.message };
  });
  if (action !== 'restore') {
    const owners = new Set(members.filter((member) => member.type === MembershipType.Owner && isActiveMember(member)).map((member) => member.id));
    const removedOwners = results.filter((result) => !result.error && owners.has(result.id));
    if (removedOwners.length && removedOwners.length === owners.size) {
      for (const result of removedOwners) result.error = 'Organization must have at least one confirmed owner.';
    }
  }
  const successful = results.filter(result => !result.error);
  await orgRepo.applyMembershipAction(env.DB, orgId, successful.map(result => result.id), action);
  const type = { remove: EventType.OrganizationUserRemoved, revoke: EventType.OrganizationUserRevoked, restore: EventType.OrganizationUserRestored }[action];
  await recordEvents(env, request, { userId }, successful.map(({ id }) => ({ type, organizationId: orgId, resourceType: 'organizationUser', resourceId: id, userId: byId.get(id)!.userId })));
  return results;
}

export async function handleBulkMemberAction(request: Request, env: Env, userId: string, orgId: string, action: MemberAction): Promise<Response> {
  const body = await parseBody(request, BulkIdsRequest);
  if (body instanceof Response) return body;
  const { ids } = body;
  if (!ids.every(isUUID)) return errorResponse('The Ids field must contain valid GUIDs.', 400);
  const results = await applyMemberAction(request, env, userId, orgId, ids, action);
  return results instanceof Response ? results : bulkResultsResponse(results);
}

async function handleMemberAction(request: Request, env: Env, userId: string, orgId: string, memberId: string, action: MemberAction): Promise<Response> {
  const results = await applyMemberAction(request, env, userId, orgId, [memberId], action);
  if (results instanceof Response) return results;
  const [{ error }] = results;
  if (error === 'Invalid user.') return errorResponse('Member not found', 404);
  return error ? errorResponse(error, 400) : jsonResponse({});
}

export const handleDeleteMember = (request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> => handleMemberAction(request, env, userId, orgId, memberId, 'remove');
export const handleRevokeMember = (request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> => handleMemberAction(request, env, userId, orgId, memberId, 'revoke');
export const handleRestoreMember = (request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> => handleMemberAction(request, env, userId, orgId, memberId, 'restore');

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
  const body = await parseBody(request, z.object({
    name: optionalText,
    accessAll: z.boolean().nullish(),
    externalId: optionalText,
    users: z.array(z.string()).nullish(),
  }));
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const existing = groupId ? await orgRepo.getGroup(env.DB, groupId) : null;
  if (groupId && (!existing || existing.orgId !== orgId)) return errorResponse('Group not found', 404);
  const users = body.users ?? [];
  // Upstream ValidateMemberAccessAsync: missing and foreign membership ids fail alike, before any
  // write, so the response cannot probe other organizations. Like upstream, skip it without users.
  const orgMemberships = users.length ? await orgRepo.listMembershipsByOrg(env.DB, orgId) : [];
  if (users.length) {
    const orgMembershipIds = new Set(orgMemberships.map(membership => membership.id));
    if (users.some((id) => !orgMembershipIds.has(id))) return errorResponse('Resource not found.', 404);
  }
  const group = {
    id: existing?.id || generateUUID(),
    orgId,
    name: body.name || existing?.name || 'Group',
    accessAll: body.accessAll ?? existing?.accessAll ?? false,
    externalId: body.externalId || existing?.externalId || null,
    createdAt: existing?.createdAt || now,
    updatedAt: now,
  };
  const previousUsers = existing ? await orgRepo.listGroupMemberIds(env.DB, group.id) : [];
  await orgRepo.saveGroup(env.DB, group);
  if (users.length || !existing) await orgRepo.replaceGroupMembers(env.DB, group.id, users);
  const previousUserIds = new Set(previousUsers);
  const currentUserIds = new Set(users.length || !existing ? users : previousUsers);
  const changedUsers = orgMemberships.filter(membership => previousUserIds.has(membership.id) !== currentUserIds.has(membership.id));
  const groupChanged = !existing || changedUsers.length > 0 || existing.name !== group.name || existing.accessAll !== group.accessAll || existing.externalId !== group.externalId;
  await recordEvents(env, request, { userId }, [
    ...(groupChanged ? [{ type: existing ? EventType.GroupUpdated : EventType.GroupCreated, organizationId: orgId, resourceType: 'group' as const, resourceId: group.id }] : []),
    ...changedUsers.map(membership => ({ type: EventType.OrganizationUserUpdatedGroups, organizationId: orgId, resourceType: 'organizationUser' as const, resourceId: membership.id, userId: membership.userId })),
  ]);
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

export async function handleDeleteGroup(request: Request, env: Env, userId: string, orgId: string, groupId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageGroups(member)) return errorResponse('Access denied', 403);
  const group = await orgRepo.getGroup(env.DB, groupId);
  if (!group || group.orgId !== orgId) return errorResponse('Group not found', 404);
  await orgRepo.deleteGroup(env.DB, groupId);
  await recordEvents(env, request, { userId }, [{ type: EventType.GroupDeleted, organizationId: group.orgId, resourceType: 'group', resourceId: group.id }]);
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

// Official clients send SavePolicyRequest {policy:{enabled,data},metadata}; NodeWarden's webapp
// still sends the flat policy. Metadata only feeds upstream side effects we do not run. Upstream
// marks Policy [Required], so a malformed envelope is rejected instead of saving a disabled policy.
const policyState = z.object({
  enabled: z.boolean().catch(false),
  data: z.record(z.string(), z.unknown()).nullish().transform((data) => data ?? {}),
}, { error: 'The Policy field is required.' });
const SavePolicyRequest = policyState.extend({ policy: policyState.optional() }).transform(({ policy, ...flat }) => policy ?? flat);

export async function handlePutPolicy(request: Request, env: Env, userId: string, orgId: string, policyType: number): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse('Access denied', 403);
  const source = await parseBody(request, SavePolicyRequest);
  if (source instanceof Response) return source;
  const existing = await orgRepo.getPolicy(env.DB, orgId, policyType);
  const policy = {
    id: existing?.id || generateUUID(),
    orgId,
    type: policyType,
    enabled: source.enabled,
    data: source.data,
    updatedAt: new Date().toISOString(),
  };
  await orgRepo.savePolicy(env.DB, policy);
  if (!existing || existing.enabled !== policy.enabled || JSON.stringify(existing.data) !== JSON.stringify(policy.data)) {
    await recordEvents(env, request, { userId }, [{ type: EventType.PolicyUpdated, organizationId: orgId, resourceType: 'policy', resourceId: policy.id }]);
  }
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(policyResponse(policy));
}

export async function handleGetPlans(): Promise<Response> {
  return jsonResponse(enterprisePlansResponse());
}

// Bitwarden guards the organization API key endpoints with a SecretVerificationRequestModel,
// so re-authenticate the caller before minting a key instead of trusting the session alone. A sent
// masterPasswordHash wins over secret even when it is null.
const SecretVerificationRequest = z.object({ masterPasswordHash: z.string().nullish(), secret: z.string().nullish() })
  .transform((body) => ('masterPasswordHash' in body ? body.masterPasswordHash : body.secret)?.trim() ?? '');

async function verifyMasterPassword(env: Env, userId: string, secret: string): Promise<Response | null> {
  if (!secret) return errorResponse('masterPasswordHash is required', 400);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const valid = await new AuthService(env).verifyPassword(secret, user.masterPasswordHash, user.email);
  return valid ? null : errorResponse('Invalid password', 400);
}

export async function handleOrgApiKey(request: Request, env: Env, userId: string, orgId: string, rotate: boolean): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (member.type > MembershipType.Admin) return errorResponse('Access denied', 403);
  const secret = await parseBody(request, SecretVerificationRequest);
  if (secret instanceof Response) return secret;
  const unverified = await verifyMasterPassword(env, userId, secret);
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

export async function handleEnableSecretsManager(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManageMembers(member)) return errorResponse('Access denied', 403);
  return new Response(null, { status: 200 });
}
