import type { Env, User } from '../types';
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
  confirmMemberCheck,
  hasFullCollectionAccess,
  isActiveMember,
  memberCollectionsCheck,
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

type InviteEmailsCheck = { ok: true } | { ok: false; message: string };

function inviteEmailsCheck(emails: string[]): InviteEmailsCheck {
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

export async function handleListOrgCollections(env: Env, userId: string, orgId: string, details: boolean): Promise<Response> {
  if (!orgId) return handleListAllCollections(env, userId);
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collections = await orgRepo.listCollectionsByOrg(env.DB, orgId);
  const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, orgId);
  const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
  const visible = collections.filter((collection) => hasFullCollectionAccess(member) || assignedMap.has(collection.id));
  return jsonResponse({
    data: visible.map((collection) => {
      const permission = resolveCollectionPermission(member, assignedMap.get(collection.id) || null);
      return collectionJson(collection, details ? {
        readOnly: permission.readOnly,
        hidePasswords: permission.hidePasswords,
        manage: permission.manage,
      } : undefined);
    }),
    object: 'list',
    continuationToken: null,
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
  return jsonResponse(collectionJson(collection));
}

export async function handleUpdateOrgCollection(request: Request, env: Env, userId: string, orgId: string, collectionId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const collection = await orgRepo.getCollection(env.DB, collectionId);
  if (!collection || collection.orgId !== orgId) return errorResponse('Collection not found', 404);
  const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, orgId);
  const permission = resolveCollectionPermission(member, assigned.find((item) => item.collectionId === collectionId) || null);
  if (!permission.canEdit && !hasFullCollectionAccess(member) && !permission.manage) {
    return errorResponse('Access denied', 403);
  }
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  collection.name = asString(readBody(body, ['name', 'Name'])) || collection.name;
  collection.externalId = asString(readBody(body, ['externalId', 'ExternalId'])) || collection.externalId;
  collection.updatedAt = new Date().toISOString();
  await orgRepo.saveCollection(env.DB, collection);
  await applyCollectionAccess(env.DB, collection.orgId, collection.id, body);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse(collectionJson(collection));
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

// Membership and group ids come straight from the request body, so every referenced
// record must be re-checked against the collection's organization before it is granted access.
async function applyCollectionAccess(
  db: D1Database,
  orgId: string,
  collectionId: string,
  body: Record<string, unknown>
): Promise<void> {
  const users = (readBody(body, ['users', 'Users']) as Array<Record<string, unknown>> | undefined) || [];
  const groups = (readBody(body, ['groups', 'Groups']) as Array<Record<string, unknown>> | undefined) || [];
  if (users.length) {
    const mapped = [];
    for (const entry of users) {
      const membership = await orgRepo.getMembership(db, asString(readBody(entry, ['id', 'Id'])));
      if (!membership || membership.orgId !== orgId) continue;
      mapped.push({ member: membership, ...accessFlags(entry) });
    }
    await orgRepo.replaceCollectionUsers(db, collectionId, mapped);
  }
  if (groups.length) {
    const mapped = [];
    for (const entry of groups) {
      const group = await orgRepo.getGroup(db, asString(readBody(entry, ['id', 'Id'])));
      if (!group || group.orgId !== orgId) continue;
      mapped.push({ groupId: group.id, ...accessFlags(entry) });
    }
    await orgRepo.replaceCollectionGroups(db, collectionId, mapped);
  }
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
  const now = new Date().toISOString();
  // Upstream OrganizationService.InviteUsersAsync: every invite starts Invited and unbound, even for
  // an existing account, so the invitee stays hidden until they accept with the emailed token.
  const invites = emails.map((email) => ({ id: generateUUID(), email }));
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
  if (!env.EMAIL || !getEmailSender(env)) return jsonResponse({});
  const vaultOrigin = organizationInviteVaultOrigin(request, env);
  if (!vaultOrigin) {
    console.warn('Organization invite email skipped: WEB_VAULT_ORIGINS is not set');
    return jsonResponse({});
  }

  const organization = await orgRepo.getOrganization(env.DB, orgId);
  const storage = new StorageService(env.DB);
  // Documentation domains bounce and hurt sender reputation, as in register verification.
  const deliverable = invites.filter(({ email }) => !isReservedDocumentationEmail(email));
  try {
    await Promise.all(deliverable.map(async ({ id, email }) => sendOrganizationInviteEmail(env, {
      vaultOrigin,
      organizationId: orgId,
      organizationUserId: id,
      organizationName: organization?.name ?? '',
      email,
      token: await createOrgInviteToken(env.JWT_SECRET, id, email),
      hasExistingUser: !!(await storage.getUser(email)),
    })));
  } catch (error) {
    console.error('Organization invite email failed:', error instanceof Error ? error.message : String(error));
    return errorResponse('Unable to send invitation email', 502);
  }
  return jsonResponse({});
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

// Upstream OrganizationUsersController.UserPublicKeys: official web's bulk confirm dialog wraps the
// org key with each selected member's public key before it posts the confirm.
export async function handleListMemberPublicKeys(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  // Upstream OrganizationUserBulkRequestModel.Ids is [Required, MinLength(1)] and defaults to an
  // empty list, so an absent field fails MinLength and only an explicit null fails Required.
  const sentIds = readBody(body, ['ids', 'Ids']);
  const ids = sentIds === undefined ? [] : sentIds;
  if (!Array.isArray(ids)) return errorResponse('The Ids field is required.', 400);
  if (!ids.length) return errorResponse("The field Ids must be a string or array type with a minimum length of '1'.", 400);
  const keys = await orgRepo.listAcceptedMemberPublicKeys(env.DB, orgId, ids.map(asString));
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
  if (!MEMBER_ORG_KEY_PATTERN.test(key)) return errorResponse('Key is not a valid encrypted string.', 400);
  const confirmed = check.member;
  confirmed.key = key;
  confirmed.status = MembershipStatus.Confirmed;
  confirmed.updatedAt = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, confirmed);
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
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
  // Upstream HasConfirmedOwnersExceptAsync: leaving Owner must leave another confirmed owner behind.
  const isConfirmedOwner = membership.type === MembershipType.Owner && membership.status === MembershipStatus.Confirmed;
  const otherConfirmedOwners = (await orgRepo.countConfirmedOwners(env.DB, orgId)) - (isConfirmedOwner ? 1 : 0);
  if (change.type !== MembershipType.Owner && otherConfirmedOwners < 1) {
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
  if (membership.type === MembershipType.Owner && (await orgRepo.countConfirmedOwners(env.DB, orgId)) <= 1) {
    return errorResponse('The last owner cannot be removed', 400);
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
