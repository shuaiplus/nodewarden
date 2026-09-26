import {
  Env,
  Organization,
  OrganizationUser,
  OrganizationUserStatus,
  OrganizationUserType,
  User,
  Invite,
} from '../types';
import { StorageService } from '../services/storage';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { readActingDeviceIdentifier } from '../utils/device';
import { isYubiKeyEnabled } from '../utils/yubico-otp';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { bumpOrganizationMembers } from '../utils/org-notify';
import { ORG_SELF_SERVICE_REGISTRATION_CONFIG_KEY, ORG_USER_STATUS, ORG_USER_TYPE } from '../config/org';
import { isValidEncString } from './ciphers';
import { deleteAllAttachmentsForCiphers } from './attachments';

// CONTRACT:
// Bitwarden-compatible organizations: sharing between users with client-side
// crypto. The server never decrypts; it stores EncStrings and gates access.
//
// Wire shapes mirror the Bitwarden server responses (OrganizationResponse,
// OrganizationUserUserDetailsResponse, CollectionResponse,
// ProfileOrganizationResponse) as exercised by official clients via
// /api/sync, /api/ciphers/:id/share, and the member/collection management
// surface used by the NodeWarden webapp.
//
// No email is sent anywhere. Invitations are email-string records: a user
// whose email matches can accept from the webapp. Inviting an unregistered
// email also mints a registration invite code so the owner can onboard the
// person without the server admin.

// ProductTierType on the wire: Free=0, Families=1, Teams=2, Enterprise=3,
// TeamsStarter=4. We present every organization as Teams.
const WIRE_PRODUCT_TIER_TYPE = 2;

const ORG_INVITE_REGISTRATION_TTL_HOURS = 24 * 7;

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return normalized ? normalized : null;
}

export function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function optionalEncString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return isValidEncString(trimmed) ? trimmed : null;
}

export async function readJsonBody(request: Request): Promise<any | null> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

export async function writeOrgAudit(
  storage: StorageService,
  request: Request,
  actorUserId: string,
  action: string,
  metadata: Record<string, unknown>,
  level: 'info' | 'security' = 'info'
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId,
    action,
    category: 'data',
    level,
    targetType: 'organization',
    targetId: typeof metadata.organizationId === 'string' ? metadata.organizationId : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

// Fan-out for org changes lives in src/utils/org-notify.ts; the
// bumpOrganizationMembers helper used throughout this file is imported from it.

// Member-visible org shape. billingEmail is deliberately absent here: it
// defaults to the owner's personal email and Bitwarden only exposes it to
// billing-scope admins, so callers add it back only when the requester is an
// Owner of this organization.
function organizationToResponse(
  organization: Organization,
  options: { includeBillingEmail?: boolean } = {}
): Record<string, unknown> {
  return {
    id: organization.id,
    name: organization.name,
    businessName: null,
    ...(options.includeBillingEmail ? { billingEmail: organization.billingEmail } : {}),
    plan: 'Teams',
    planType: 2,
    productTierType: WIRE_PRODUCT_TIER_TYPE,
    seats: null,
    maxSeats: null,
    maxCollections: null,
    maxStorageGb: null,
    use2fa: true,
    useKeys: true,
    useTotp: true,
    usePolicies: false,
    useGroups: false,
    useDirectory: false,
    useSso: false,
    useEvents: false,
    useScim: false,
    useResetPassword: false,
    selfHost: true,
    hasPublicAndPrivateKeys: !!organization.publicKey && !!organization.privateKey,
    object: 'organization',
  };
}

// The per-user organization view embedded in sync.profile.organizations.
// `key` (the organization key encrypted with the member's public key) is the
// decryption path for every org cipher, so it must be present when confirmed.
export function profileOrganizationResponse(
  organization: Organization,
  organizationUser: OrganizationUser
): Record<string, unknown> {
  const wireStatus = Number(organizationUser.status);
  return {
    id: organization.id,
    name: organization.name,
    key: organizationUser.key,
    status: wireStatus,
    type: Number(organizationUser.type),
    enabled: true,
    maxAutoscaleSeats: null,
    maxSeats: null,
    seats: null,
    maxCollections: null,
    maxStorageGb: null,
    use2fa: true,
    useTotp: true,
    useKeys: true,
    useApi: true,
    usePolicies: false,
    useGroups: false,
    useDirectory: false,
    useSso: false,
    useEvents: false,
    useScim: false,
    useOrganizationDomains: false,
    useKeyConnector: false,
    keyConnectorEnabled: false,
    useCustomPermissions: false,
    useResetPassword: false,
    useSecretsManager: false,
    usePasswordManager: true,
    usePam: false,
    useActivateAutofillPolicy: false,
    selfHost: true,
    usersGetPremium: true,
    plan: 'Teams',
    planType: 2,
    productTierType: WIRE_PRODUCT_TIER_TYPE,
    hasPublicAndPrivateKeys: !!organization.publicKey && !!organization.privateKey,
    familySponsorshipAvailable: false,
    accessSecretsManager: false,
    limitCollectionCreation: false,
    limitCollectionDeletion: false,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsClaimedByOrganization: false,
    useAccessIntelligence: false,
    useAdminSponsoredFamilies: false,
    isAdminInitiated: false,
    ssoEnabled: false,
    identifier: null,
    permissions: {
      accessEventLogs: true,
      accessImportExport: true,
      accessReports: true,
      manageResetPassword: false,
      manageScim: false,
      manageSso: false,
      manageUsers: true,
      manageGroups: false,
      managePolicies: false,
      manageOrganizations: false,
      editAnyCollection: true,
      deleteAnyCollection: true,
      createNewCollections: true,
    },
    object: 'profileOrganization',
  };
}

function organizationUserToResponse(
  organizationUser: OrganizationUser,
  user: User | null
): Record<string, unknown> {
  return {
    id: organizationUser.id,
    userId: organizationUser.userId,
    name: user?.name ?? null,
    email: organizationUser.email,
    type: Number(organizationUser.type),
    status: Number(organizationUser.status),
    accessAll: !!organizationUser.accessAll,
    twoFactorEnabled: !!user && (!!user.totpSecret || isYubiKeyEnabled(user)),
    avatarColor: null,
    // Squatter signal: an account created after the invitation was sent may
    // not be the person the owner intended to invite (no email verification).
    invitationDate: organizationUser.creationDate,
    userCreatedAt: user?.createdAt ?? null,
    object: 'organizationUserUserDetails',
  };
}

interface OwnerContext {
  organization: Organization;
  organizationUser: OrganizationUser;
}

export async function requireOrganizationOwner(
  storage: StorageService,
  organizationId: string,
  userId: string
): Promise<OwnerContext | Response> {
  const organization = await storage.getOrganization(organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  const organizationUser = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!organizationUser || organizationUser.status !== ORG_USER_STATUS.CONFIRMED) {
    return errorResponse('Organization not found', 404);
  }
  if (organizationUser.type !== ORG_USER_TYPE.OWNER) {
    return errorResponse('Only organization owners may perform this action', 403);
  }
  return { organization, organizationUser };
}

export function readCollectionAccessInput(value: unknown): Array<{ collectionId: string; readOnly: boolean; hidePasswords: boolean }> | null {
  if (!Array.isArray(value)) return null;
  const out: Array<{ collectionId: string; readOnly: boolean; hidePasswords: boolean }> = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const row = item as Record<string, unknown>;
    const collectionId = normalizeOptionalId(row.id);
    if (!collectionId) continue;
    out.push({
      collectionId,
      readOnly: !!row.readOnly,
      hidePasswords: !!row.hidePasswords,
    });
  }
  return out;
}

// GET /api/organizations
// Memberships for the current user (any linked status) so the webapp can show
// pending invitations and owned organizations.
export async function handleListMyOrganizations(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const memberships = await storage.listOrganizationsForUser(userId);

  const data = [];
  for (const membership of memberships) {
    const { organization, organizationUser } = membership;
    const pending = organizationUser.status === ORG_USER_STATUS.INVITED || organizationUser.status === ORG_USER_STATUS.ACCEPTED;
    let ownerEmail: string | null = null;
    if (pending) {
      // Pending members cannot decrypt the org name (they lack the org key);
      // surface the owner's email so the webapp banner is still informative.
      const organizationUsers = await storage.listOrganizationUsers(organization.id);
      ownerEmail = organizationUsers.find((member) => member.type === ORG_USER_TYPE.OWNER)?.email ?? null;
    }
    data.push({
      ...organizationToResponse(organization),
      status: Number(organizationUser.status),
      type: Number(organizationUser.type),
      organizationUserId: organizationUser.id,
      // The org key wrapped for this member (same string the sync profile
      // exposes). The webapp uses it to detect and re-wrap legacy OAEP hashes.
      key: organizationUser.status === ORG_USER_STATUS.CONFIRMED ? organizationUser.key : null,
      ...(pending ? { ownerEmail } : {}),
    });
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// POST /api/organizations
// Body: { name (enc w/ org key), key (org key enc w/ creator pubkey),
//         keys: { publicKey, encryptedPrivateKey }, collectionName (enc w/ org key),
//         billingEmail? }
export async function handleCreateOrganization(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  const name = optionalEncString(body.name);
  const key = optionalEncString(body.key);
  const collectionName = optionalEncString(body.collectionName ?? body.defaultCollectionName);
  const publicKey = typeof body.keys?.publicKey === 'string' ? body.keys.publicKey.trim() : null;
  const privateKey = optionalEncString(body.keys?.encryptedPrivateKey ?? body.keys?.privateKey);

  if (!name) return errorResponse('name must be an encrypted string', 400);
  if (!key) return errorResponse('key must be an encrypted string', 400);
  if (!publicKey) return errorResponse('keys.publicKey is required', 400);
  if (!privateKey) return errorResponse('keys.encryptedPrivateKey must be an encrypted string', 400);

  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const now = new Date().toISOString();
  const organization: Organization = {
    id: generateUUID(),
    name,
    privateKey,
    publicKey,
    billingEmail: typeof body.billingEmail === 'string' && body.billingEmail.trim() ? body.billingEmail.trim() : user.email,
    creationDate: now,
    revisionDate: now,
  };

  const organizationUser: OrganizationUser = {
    id: generateUUID(),
    organizationId: organization.id,
    userId,
    email: user.email,
    key,
    status: ORG_USER_STATUS.CONFIRMED,
    type: ORG_USER_TYPE.OWNER,
    accessAll: true,
    creationDate: now,
    revisionDate: now,
  };

  // Default collection, as the official clients create during org setup — part
  // of the same atomic batch as the org and owner membership.
  const defaultCollection = collectionName
    ? {
        id: generateUUID(),
        organizationId: organization.id,
        name: collectionName,
        externalId: null,
        creationDate: now,
        revisionDate: now,
      }
    : null;

  await storage.createOrganizationWithOwner(organization, organizationUser, defaultCollection);

  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  await writeOrgAudit(storage, request, userId, 'organization.create', {
    organizationId: organization.id,
  });

  return jsonResponse(organizationToResponse(organization, { includeBillingEmail: true }), 200);
}

// GET /api/organizations/:id (owners)
export async function handleGetOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;
  return jsonResponse(organizationToResponse(owner.organization, { includeBillingEmail: true }));
}

// PUT /api/organizations/:id (owners) — { name (enc w/ org key) }
export async function handleUpdateOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  const name = optionalEncString(body.name);
  if (!name) return errorResponse('name must be an encrypted string', 400);

  const organization = owner.organization;
  organization.name = name;
  organization.revisionDate = new Date().toISOString();
  await storage.saveOrganization(organization);

  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeOrgAudit(storage, request, userId, 'organization.update', { organizationId });

  return jsonResponse(organizationToResponse(organization, { includeBillingEmail: true }));
}

// DELETE /api/organizations/:id (owners)
// Deletes the org and every shared cipher, collection, and membership.
export async function handleDeleteOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const members = await storage.listConfirmedOrganizationUserIds(organizationId);
  const orgCipherIds = await storage.listCipherIdsByOrganization(organizationId);

  // Single-statement owner-preconditioned delete: authorization and deletion
  // cannot drift apart (a concurrent demotion yields false -> 404). Attachment
  // cleanup runs only after the delete is proven, using the ids captured
  // before the cascade removed the rows — a failed delete leaves the org and
  // its attachments intact.
  const deleted = await storage.deleteOrganizationForOwner(organizationId, userId);
  if (!deleted) {
    return errorResponse('Organization not found', 404);
  }
  await deleteAllAttachmentsForCiphers(env, orgCipherIds);

  const contextId = readActingDeviceIdentifier(request);
  for (const member of members) {
    const revisionDate = await storage.updateRevisionDate(member.userId);
    notifyUserVaultSync(env, member.userId, revisionDate, contextId);
  }
  await writeOrgAudit(storage, request, userId, 'organization.delete', {
    organizationId,
    cipherCount: orgCipherIds.length,
  }, 'security');

  return new Response(null, { status: 204 });
}

// POST /api/organizations/:id/leave
export async function handleLeaveOrganization(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const organization = await storage.getOrganization(organizationId);
  if (!organization) return errorResponse('Organization not found', 404);
  const organizationUser = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!organizationUser) return errorResponse('Not a member of this organization', 404);

  if (organizationUser.type === ORG_USER_TYPE.OWNER && organizationUser.status >= ORG_USER_STATUS.ACCEPTED) {
    const confirmedOwners = await storage.countConfirmedOrganizationOwners(organizationId);
    if (confirmedOwners <= 1) {
      return errorResponse('The last owner cannot leave the organization. Promote another owner or delete the organization.', 400);
    }
  }

  // Guarded delete: a concurrent demote of the other owner can no longer
  // strand the org ownerless (the count re-evaluates inside the statement).
  const left = await storage.deleteOrganizationUserGuardingLastOwner(organizationUser.id);
  if (!left) {
    return errorResponse('The last owner cannot leave the organization. Promote another owner or delete the organization.', 400);
  }
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  await bumpOrganizationMembers(request, env, storage, organizationId, userId);
  await writeOrgAudit(storage, request, userId, 'organization.user.leave', {
    organizationId,
    organizationUserId: organizationUser.id,
  });

  return new Response(null, { status: 204 });
}

// POST /api/organizations/:id/invites (owners)
// Body: { emails: string[], collections: [{id, readOnly, hidePasswords}], type, accessAll }
export async function handleInviteOrganizationUsers(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  const emails: string[] = Array.isArray(body.emails)
    ? body.emails.map(normalizeEmail).filter((email: string | null): email is string => !!email)
    : [];
  if (!emails.length) return errorResponse('emails array is required', 400);

  const type: OrganizationUserType = [0, 1, 2, 3, 4].includes(Number(body.type)) ? Number(body.type) as OrganizationUserType : ORG_USER_TYPE.USER;
  const accessAll = !!body.accessAll;
  const collectionAccess = readCollectionAccessInput(body.collections) || [];

  // Validate all referenced collections belong to this organization.
  if (collectionAccess.length) {
    const collections = await storage.getCollectionsByIds(collectionAccess.map((row) => row.collectionId));
    const validIds = new Set(collections.filter((collection) => collection.organizationId === organizationId).map((collection) => collection.id));
    for (const row of collectionAccess) {
      if (!validIds.has(row.collectionId)) {
        return errorResponse(`Collection ${row.collectionId} does not belong to this organization`, 400);
      }
    }
  }

  const selfServiceRegistration = (await storage.getConfigValue(ORG_SELF_SERVICE_REGISTRATION_CONFIG_KEY)) === 'true';
  const now = new Date().toISOString();
  const invited: Array<{ email: string; organizationUserId: string; registered: boolean; inviteCode?: string; requiresAdminRegistration?: boolean }> = [];
  const skipped: Array<{ email: string; reason: string }> = [];

  for (const email of Array.from(new Set(emails))) {
    const existing = await storage.getOrganizationUserByEmail(organizationId, email);
    if (existing) {
      skipped.push({ email, reason: 'already-invited' });
      continue;
    }

    const invitedUser = await storage.getUser(email);
    if (invitedUser && invitedUser.id === userId) {
      skipped.push({ email, reason: 'self' });
      continue;
    }

    const organizationUser: OrganizationUser = {
      id: generateUUID(),
      organizationId,
      userId: invitedUser?.id ?? null,
      email,
      key: null,
      status: ORG_USER_STATUS.INVITED,
      type,
      accessAll,
      creationDate: now,
      revisionDate: now,
    };
    await storage.saveOrganizationUser(organizationUser);

    // Per-collection access rows for users without accessAll.
    if (!accessAll && collectionAccess.length) {
      await storage.replaceOrganizationUserCollections(
        organizationUser.id,
        collectionAccess.map((row) => ({ collectionId: row.collectionId, readOnly: row.readOnly, hidePasswords: row.hidePasswords }))
      );
    }

    let inviteCode: string | undefined;
    let requiresAdminRegistration = false;
    if (!invitedUser) {
      // Unregistered email: only mint a registration code when the instance
      // admin opted in to self-service registration. Minted codes are bound
      // to the invited email so they cannot register arbitrary addresses.
      if (selfServiceRegistration) {
        const expiresAt = new Date(Date.now() + ORG_INVITE_REGISTRATION_TTL_HOURS * 60 * 60 * 1000);
        const invite: Invite = {
          code: randomHex(20),
          createdBy: userId,
          usedBy: null,
          email,
          expiresAt: expiresAt.toISOString(),
          status: 'active',
          createdAt: now,
          updatedAt: now,
        };
        await storage.createInvite(invite);
        inviteCode = invite.code;
      } else {
        requiresAdminRegistration = true;
      }
    }

    invited.push({
      email,
      organizationUserId: organizationUser.id,
      registered: !!invitedUser,
      ...(inviteCode ? { inviteCode } : {}),
      ...(requiresAdminRegistration ? { requiresAdminRegistration } : {}),
    });
  }

  await writeOrgAudit(storage, request, userId, 'organization.user.invite', {
    organizationId,
    invited: invited.map((item) => item.email),
    skipped: skipped.map((item) => item.email),
  });

  return jsonResponse({ invited, skipped, object: 'organizationInviteResult' });
}

// GET /api/organizations/:id/users (owners)
export async function handleListOrganizationUsers(request: Request, env: Env, userId: string, organizationId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const organizationUsers = await storage.listOrganizationUsers(organizationId);
  const data = [];
  for (const organizationUser of organizationUsers) {
    const user = organizationUser.userId ? await storage.getUserById(organizationUser.userId) : null;
    data.push(organizationUserToResponse(organizationUser, user));
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/organizations/:id/users/:organizationUserId (owners)
// Includes the member's public key so owners can encrypt the org key on confirm.
export async function handleGetOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  organizationUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const organizationUser = await storage.getOrganizationUser(organizationUserId);
  if (!organizationUser || organizationUser.organizationId !== organizationId) {
    return errorResponse('Organization user not found', 404);
  }

  const user = organizationUser.userId ? await storage.getUserById(organizationUser.userId) : null;
  const collectionUsers = await storage.listCollectionUsersByOrganizationUser(organizationUserId);
  const collections = collectionUsers.length
    ? await storage.getCollectionsByIds(collectionUsers.map((row) => row.collectionId))
    : [];
  const collectionIds = new Set(collections.map((collection) => collection.id));

  return jsonResponse({
    ...organizationUserToResponse(organizationUser, user),
    userId: organizationUser.userId,
    publicKey: user?.publicKey ?? null,
    collections: collectionUsers
      .filter((row) => collectionIds.has(row.collectionId))
      .map((row) => ({ id: row.collectionId, readOnly: !!row.readOnly, hidePasswords: !!row.hidePasswords })),
    object: 'organizationUserDetails',
  });
}

// POST /api/organizations/:id/users/:organizationUserId/accept
// Email-string invite acceptance: the authenticated user must match the email
// on the invitation. No token is required (there is no email delivery).
export async function handleAcceptOrganizationInvitation(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  organizationUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  const organizationUser = await storage.getOrganizationUser(organizationUserId);
  if (!organizationUser || organizationUser.organizationId !== organizationId) {
    return errorResponse('Organization invitation not found', 404);
  }
  if (organizationUser.status !== ORG_USER_STATUS.INVITED) {
    return errorResponse('Invitation is no longer pending', 400);
  }
  if (organizationUser.userId && organizationUser.userId !== userId) {
    return errorResponse('This invitation belongs to another account', 403);
  }
  if (organizationUser.email !== user.email && organizationUser.email !== user.email.toLowerCase()) {
    return errorResponse('This invitation was issued for a different email address', 403);
  }

  // Conditional transition: fails cleanly when the membership was removed or
  // already accepted between the read above and this write (no resurrection).
  const accepted = await storage.transitionOrganizationUserStatus(organizationUserId, ORG_USER_STATUS.INVITED, {
    status: ORG_USER_STATUS.ACCEPTED,
    userId,
  });
  if (!accepted) {
    return errorResponse('Invitation is no longer pending (membership changed concurrently; retry)', 409);
  }

  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  await writeOrgAudit(storage, request, userId, 'organization.user.accept', {
    organizationId,
    organizationUserId,
  });

  return new Response(null, { status: 200 });
}

// POST /api/organizations/:id/users/:organizationUserId/confirm (owners)
// Body: { key: org key encrypted with the member's public key }
export async function handleConfirmOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  organizationUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const key = optionalEncString(body.key);
  if (!key) return errorResponse('key must be an encrypted string', 400);

  const organizationUser = await storage.getOrganizationUser(organizationUserId);
  if (!organizationUser || organizationUser.organizationId !== organizationId) {
    return errorResponse('Organization user not found', 404);
  }
  // Re-confirming an already-confirmed member is allowed: it re-writes the
  // org key wrapped with the member's current public key (used by the webapp
  // to migrate legacy OAEP-hash wraps without a full re-invite).
  if (
    organizationUser.status !== ORG_USER_STATUS.ACCEPTED &&
    organizationUser.status !== ORG_USER_STATUS.CONFIRMED
  ) {
    return errorResponse('User has not accepted the invitation yet', 400);
  }
  if (!organizationUser.userId) {
    return errorResponse('User has not linked an account to this invitation', 400);
  }

  // Conditional transition: a concurrent remove demotes this to a no-op
  // failure instead of resurrecting the deleted membership with the org key.
  // Branch on the current status: ACCEPTED→CONFIRMED (first confirm) or
  // CONFIRMED→CONFIRMED (re-confirm, updates the wrapped key only).
  const isReconfirm = organizationUser.status === ORG_USER_STATUS.CONFIRMED;
  const transitioned = await storage.transitionOrganizationUserStatus(
    organizationUserId,
    isReconfirm ? ORG_USER_STATUS.CONFIRMED : ORG_USER_STATUS.ACCEPTED,
    {
      status: ORG_USER_STATUS.CONFIRMED,
      key,
    }
  );
  if (!transitioned) {
    return errorResponse('Membership changed concurrently; retry', 409);
  }

  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeOrgAudit(storage, request, userId, 'organization.user.confirm', {
    organizationId,
    organizationUserId,
  });

  return new Response(null, { status: 200 });
}

// PUT /api/organizations/:id/users/:organizationUserId (owners)
// Body: { type, accessAll, collections: [{id, readOnly, hidePasswords}] }
export async function handleUpdateOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  organizationUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  const organizationUser = await storage.getOrganizationUser(organizationUserId);
  if (!organizationUser || organizationUser.organizationId !== organizationId) {
    return errorResponse('Organization user not found', 404);
  }

  if (body.type !== undefined) {
    const nextType = Number(body.type);
    // Same range the invite endpoint accepts — rejecting Manager/Custom here
    // would make any role edit on such a member (including official clients
    // re-sending the unchanged type) fail with a 400.
    if (nextType < ORG_USER_TYPE.OWNER || nextType > ORG_USER_TYPE.CUSTOM) {
      return errorResponse('Unsupported member type', 400);
    }
    if (organizationUser.type === ORG_USER_TYPE.OWNER && nextType !== ORG_USER_TYPE.OWNER) {
      const confirmedOwners = await storage.countConfirmedOrganizationOwners(organizationId);
      if (confirmedOwners <= 1) {
        return errorResponse('The last owner cannot be demoted. Promote another owner first.', 400);
      }
    }
  }

  // Validate collection assignments BEFORE persisting any state so a 400
  // leaves the member unchanged (no partial writes).
  if (Array.isArray(body.collections)) {
    const collectionAccess = readCollectionAccessInput(body.collections) || [];
    if (collectionAccess.length) {
      const collections = await storage.getCollectionsByIds(collectionAccess.map((row) => row.collectionId));
      const validIds = new Set(collections.filter((collection) => collection.organizationId === organizationId).map((collection) => collection.id));
      for (const row of collectionAccess) {
        if (!validIds.has(row.collectionId)) {
          return errorResponse(`Collection ${row.collectionId} does not belong to this organization`, 400);
        }
      }
    }
  }

  // Conditional transition: fails cleanly when the membership was removed
  // or its status changed between the read above and this write (no
  // resurrection via the unconditional upsert).
  const updated = await storage.transitionOrganizationUserStatus(
    organizationUserId,
    organizationUser.status,
    {
      ...(body.type !== undefined ? { type: Number(body.type) } : {}),
      ...(body.accessAll !== undefined ? { accessAll: !!body.accessAll } : {}),
    },
    // Race-free last-owner guard: a concurrent demote of the other owner
    // cannot leave the org ownerless even when both upfront checks passed.
    { guardLastOwner: true }
  );
  if (!updated) {
    return errorResponse('Membership changed concurrently; retry', 409);
  }

  if (Array.isArray(body.collections)) {
    const collectionAccess = readCollectionAccessInput(body.collections) || [];
    await storage.replaceOrganizationUserCollections(
      organizationUserId,
      collectionAccess.map((row) => ({ collectionId: row.collectionId, readOnly: row.readOnly, hidePasswords: row.hidePasswords }))
    );
  }

  // Permission changes alter this member's sync payload only.
  if (organizationUser.userId) {
    const revisionDate = await storage.updateRevisionDate(organizationUser.userId);
    notifyUserVaultSync(env, organizationUser.userId, revisionDate, readActingDeviceIdentifier(request));
  }
  await writeOrgAudit(storage, request, userId, 'organization.user.update', {
    organizationId,
    organizationUserId,
  });

  return new Response(null, { status: 200 });
}

// DELETE /api/organizations/:id/users/:organizationUserId (owners)
export async function handleRemoveOrganizationUser(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  organizationUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const organizationUser = await storage.getOrganizationUser(organizationUserId);
  if (!organizationUser || organizationUser.organizationId !== organizationId) {
    return errorResponse('Organization user not found', 404);
  }
  if (organizationUser.type === ORG_USER_TYPE.OWNER && organizationUser.status >= ORG_USER_STATUS.ACCEPTED) {
    const confirmedOwners = await storage.countConfirmedOrganizationOwners(organizationId);
    if (confirmedOwners <= 1) {
      return errorResponse('The last owner cannot be removed. Promote another owner or delete the organization.', 400);
    }
  }

  const removedUserId = organizationUser.userId;
  // Guarded delete: a concurrent demote of the other owner can no longer
  // strand the org ownerless.
  const removed = await storage.deleteOrganizationUserGuardingLastOwner(organizationUserId);
  if (!removed) {
    return errorResponse('The last owner cannot be removed. Promote another owner or delete the organization.', 400);
  }

  if (removedUserId) {
    const revisionDate = await storage.updateRevisionDate(removedUserId);
    notifyUserVaultSync(env, removedUserId, revisionDate, readActingDeviceIdentifier(request));
  }
  await writeOrgAudit(storage, request, userId, 'organization.user.remove', {
    organizationId,
    organizationUserId,
  }, 'security');

  return new Response(null, { status: 204 });
}
