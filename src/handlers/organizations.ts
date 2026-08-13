import type { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import {
  canCreateCollection,
  canDeleteOrganization,
  canManageGroups,
  canManageMembers,
  canManagePolicies,
  canManageScim,
  hasFullCollectionAccess,
  isActiveMember,
  resolveCollectionPermission,
  resolvePermissions,
} from '../services/org-authz';
import {
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type MembershipRecord,
  publicMembershipStatus,
  revokeStatus,
  restoreStatus,
} from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { organizationResponse, policyResponse } from '../utils/org-response';
import { enterprisePlansResponse } from '../services/enterprise-license';
import { publishPlatformEvent } from '../services/queue-publisher';
import { hashApiKey, verifyApiKey } from '../utils/api-key';

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
  const cipherIds = await orgRepo.listOrgCipherIds(env.DB, orgId);
  for (const cipherId of cipherIds) {
    await env.DB.prepare('DELETE FROM ciphers WHERE id = ?').bind(cipherId).run();
  }
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
      if (!membership?.userId || membership.orgId !== orgId) continue;
      mapped.push({ userId: membership.userId, ...accessFlags(entry) });
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

export async function handleListMembers(env: Env, userId: string, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  const storage = new StorageService(env.DB);
  const members = await orgRepo.listMembershipsByOrg(env.DB, orgId);
  const data = [];
  for (const item of members) {
    const account = item.userId ? await storage.getUserById(item.userId) : null;
    data.push({
      id: item.id,
      userId: item.userId,
      name: account?.name || null,
      email: account?.email || item.email,
      externalId: item.externalId,
      status: publicMembershipStatus(item.status),
      type: item.type === MembershipType.Manager ? MembershipType.Custom : item.type,
      accessAll: item.accessAll,
      twoFactorEnabled: !!(account?.totpSecret),
      resetPasswordEnrolled: !!item.resetPasswordKey,
      permissions: item.type === MembershipType.Custom ? resolvePermissions(item) : null,
      accessSecretsManager: item.type <= MembershipType.Admin,
      object: 'organizationUserUserDetails',
    });
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

export async function handleInviteMembers(request: Request, env: Env, user: User, orgId: string): Promise<Response> {
  const member = await requireMember(env.DB, user.id, orgId);
  if (member instanceof Response) return member;
  if (!canManageMembers(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const emails = ((readBody(body, ['emails', 'Emails']) as string[]) || []).map((email) => String(email || '').trim().toLowerCase()).filter(Boolean);
  const type = Number(readBody(body, ['type', 'Type']) ?? MembershipType.User);
  const accessAll = asBoolean(readBody(body, ['accessAll', 'AccessAll']));
  const storage = new StorageService(env.DB);
  const now = new Date().toISOString();
  for (const email of emails) {
    const existingUser = await storage.getUser(email);
    await orgRepo.saveMembership(env.DB, {
      id: generateUUID(),
      userId: existingUser?.id || null,
      orgId,
      email,
      invitedByEmail: user.email,
      accessAll,
      key: '',
      status: existingUser ? MembershipStatus.Accepted : MembershipStatus.Invited,
      type: type === MembershipType.Custom ? MembershipType.Custom : type,
      permissions: null,
      resetPasswordKey: null,
      externalId: null,
      createdAt: now,
      updatedAt: now,
    });
  }
  await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
  return jsonResponse({});
}

export async function handleAcceptInvite(request: Request, env: Env, user: User, orgId: string, memberId: string): Promise<Response> {
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Invitation not found', 404);
  if (membership.email && membership.email.toLowerCase() !== user.email.toLowerCase() && membership.userId !== user.id) {
    return errorResponse('Invitation not found', 404);
  }
  membership.userId = user.id;
  membership.email = user.email;
  membership.status = MembershipStatus.Accepted;
  membership.updatedAt = new Date().toISOString();
  const body = await parseJsonBody(request);
  if (!(body instanceof Response)) {
    const token = asString(readBody(body, ['token', 'Token']));
    void token;
  }
  await orgRepo.saveMembership(env.DB, membership);
  return jsonResponse({});
}

export async function handleConfirmMember(request: Request, env: Env, userId: string, orgId: string, memberId: string): Promise<Response> {
  const actor = await requireMember(env.DB, userId, orgId);
  if (actor instanceof Response) return actor;
  if (!canManageMembers(actor)) return errorResponse('Access denied', 403);
  const membership = await orgRepo.getMembership(env.DB, memberId);
  if (!membership || membership.orgId !== orgId) return errorResponse('Member not found', 404);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  membership.key = asString(readBody(body, ['key', 'Key']));
  if (!membership.key) return errorResponse('Key is required', 400);
  membership.status = MembershipStatus.Confirmed;
  membership.updatedAt = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, membership);
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
  if (readBody(body, ['type', 'Type']) != null) membership.type = Number(readBody(body, ['type', 'Type']));
  if (readBody(body, ['accessAll', 'AccessAll']) != null) membership.accessAll = asBoolean(readBody(body, ['accessAll', 'AccessAll']));
  membership.updatedAt = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, membership);
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

export async function handlePutPolicy(request: Request, env: Env, userId: string, orgId: string, policyType: number): Promise<Response> {
  const member = await requireMember(env.DB, userId, orgId);
  if (member instanceof Response) return member;
  if (!canManagePolicies(member)) return errorResponse('Access denied', 403);
  const body = await parseJsonBody(request);
  if (body instanceof Response) return body;
  const existing = await orgRepo.getPolicy(env.DB, orgId, policyType);
  const policy = {
    id: existing?.id || generateUUID(),
    orgId,
    type: policyType,
    enabled: asBoolean(readBody(body, ['enabled', 'Enabled'])),
    data: (readBody(body, ['data', 'Data']) as Record<string, unknown>) || {},
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
