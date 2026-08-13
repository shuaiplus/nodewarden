import { and, asc, count, desc, eq, inArray, isNotNull, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import {
  cipherCollections,
  ciphers,
  collectionGroups,
  collections,
  collectionUsers,
  organizationApiKeys,
  organizationMemberships,
  organizations,
  organizationScimTokens,
  orgGroupMembers,
  orgGroups,
  orgPolicies,
  ssoAuth,
  ssoUsers,
} from '../db/schema';
import type { Cipher } from '../types';
import { hasFullCollectionAccess } from './org-authz';
import {
  type CollectionAccess,
  type CollectionRecord,
  type GroupRecord,
  type MembershipRecord,
  type OrganizationRecord,
  type PolicyRecord,
  parsePermissions,
} from './org-types';

function mapOrganization(row: typeof organizations.$inferSelect): OrganizationRecord {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billingEmail,
    identifier: row.identifier,
    privateKey: row.privateKey,
    publicKey: row.publicKey,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapMembership(row: typeof organizationMemberships.$inferSelect): MembershipRecord {
  return {
    id: row.id,
    userId: row.userId,
    orgId: row.orgId,
    email: row.email,
    invitedByEmail: row.invitedByEmail,
    accessAll: !!row.accessAll,
    key: row.key || '',
    status: Number(row.status),
    type: Number(row.type),
    permissions: parsePermissions(row.permissions),
    resetPasswordKey: row.resetPasswordKey,
    externalId: row.externalId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapCollection(row: typeof collections.$inferSelect): CollectionRecord {
  return {
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    externalId: row.externalId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapGroup(row: typeof orgGroups.$inferSelect): GroupRecord {
  return {
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    accessAll: !!row.accessAll,
    externalId: row.externalId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapPolicy(row: typeof orgPolicies.$inferSelect): PolicyRecord {
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(row.data || '{}') as Record<string, unknown>;
  } catch {
    data = {};
  }
  return {
    id: row.id,
    orgId: row.orgId,
    type: Number(row.type),
    enabled: !!row.enabled,
    data,
    updatedAt: row.updatedAt,
  };
}

function mapAccess(row: { collectionId: string; readOnly: number; hidePasswords: number; manage: number }): CollectionAccess {
  return {
    collectionId: row.collectionId,
    readOnly: !!row.readOnly,
    hidePasswords: !!row.hidePasswords,
    manage: !!row.manage,
  };
}

export async function insertOrganization(db: D1Database, org: OrganizationRecord): Promise<void> {
  await getOrm(db).insert(organizations).values({
    id: org.id,
    name: org.name,
    billingEmail: org.billingEmail,
    identifier: org.identifier,
    privateKey: org.privateKey,
    publicKey: org.publicKey,
    createdAt: org.createdAt,
    updatedAt: org.updatedAt,
  });
}

export async function updateOrganization(db: D1Database, org: OrganizationRecord): Promise<void> {
  await getOrm(db)
    .update(organizations)
    .set({
      name: org.name,
      billingEmail: org.billingEmail,
      identifier: org.identifier,
      privateKey: org.privateKey,
      publicKey: org.publicKey,
      updatedAt: org.updatedAt,
    })
    .where(eq(organizations.id, org.id));
}

export async function getOrganization(db: D1Database, id: string): Promise<OrganizationRecord | null> {
  const [row] = await getOrm(db).select().from(organizations).where(eq(organizations.id, id)).limit(1);
  return row ? mapOrganization(row) : null;
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(organizations).where(eq(organizations.id, id));
}

export async function saveMembership(db: D1Database, member: MembershipRecord): Promise<void> {
  const values = {
    id: member.id,
    userId: member.userId,
    orgId: member.orgId,
    email: member.email,
    invitedByEmail: member.invitedByEmail,
    accessAll: member.accessAll ? 1 : 0,
    key: member.key,
    status: member.status,
    type: member.type,
    permissions: member.permissions ? JSON.stringify(member.permissions) : null,
    resetPasswordKey: member.resetPasswordKey,
    externalId: member.externalId,
    createdAt: member.createdAt,
    updatedAt: member.updatedAt,
  };
  await getOrm(db)
    .insert(organizationMemberships)
    .values(values)
    .onConflictDoUpdate({
      target: organizationMemberships.id,
      set: {
        userId: values.userId,
        email: values.email,
        invitedByEmail: values.invitedByEmail,
        accessAll: values.accessAll,
        key: values.key,
        status: values.status,
        type: values.type,
        permissions: values.permissions,
        resetPasswordKey: values.resetPasswordKey,
        externalId: values.externalId,
        updatedAt: values.updatedAt,
      },
    });
}

export async function getMembership(db: D1Database, id: string): Promise<MembershipRecord | null> {
  const [row] = await getOrm(db).select().from(organizationMemberships).where(eq(organizationMemberships.id, id)).limit(1);
  return row ? mapMembership(row) : null;
}

export async function getMembershipByUserAndOrg(
  db: D1Database,
  userId: string,
  orgId: string
): Promise<MembershipRecord | null> {
  const [row] = await getOrm(db)
    .select()
    .from(organizationMemberships)
    .where(and(eq(organizationMemberships.userId, userId), eq(organizationMemberships.orgId, orgId)))
    .limit(1);
  return row ? mapMembership(row) : null;
}

export async function listMembershipsByUser(db: D1Database, userId: string): Promise<MembershipRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(organizationMemberships)
    .where(eq(organizationMemberships.userId, userId))
    .orderBy(asc(organizationMemberships.createdAt));
  return rows.map(mapMembership);
}

export async function listMembershipsByOrg(db: D1Database, orgId: string): Promise<MembershipRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(organizationMemberships)
    .where(eq(organizationMemberships.orgId, orgId))
    .orderBy(asc(organizationMemberships.createdAt));
  return rows.map(mapMembership);
}

export async function deleteMembership(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(organizationMemberships).where(eq(organizationMemberships.id, id));
}

export async function countConfirmedOwners(db: D1Database, orgId: string): Promise<number> {
  const [row] = await getOrm(db)
    .select({ count: count() })
    .from(organizationMemberships)
    .where(and(
      eq(organizationMemberships.orgId, orgId),
      eq(organizationMemberships.type, 0),
      eq(organizationMemberships.status, 2),
    ));
  return Number(row?.count || 0);
}

export async function saveCollection(db: D1Database, collection: CollectionRecord): Promise<void> {
  await getOrm(db)
    .insert(collections)
    .values({
      id: collection.id,
      orgId: collection.orgId,
      name: collection.name,
      externalId: collection.externalId,
      createdAt: collection.createdAt,
      updatedAt: collection.updatedAt,
    })
    .onConflictDoUpdate({
      target: collections.id,
      set: {
        name: collection.name,
        externalId: collection.externalId,
        updatedAt: collection.updatedAt,
      },
    });
}

export async function getCollection(db: D1Database, id: string): Promise<CollectionRecord | null> {
  const [row] = await getOrm(db).select().from(collections).where(eq(collections.id, id)).limit(1);
  return row ? mapCollection(row) : null;
}

export async function listCollectionsByOrg(db: D1Database, orgId: string): Promise<CollectionRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(collections)
    .where(eq(collections.orgId, orgId))
    .orderBy(asc(collections.createdAt));
  return rows.map(mapCollection);
}

export async function deleteCollection(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(collections).where(eq(collections.id, id));
}

export async function replaceCollectionUsers(
  db: D1Database,
  collectionId: string,
  users: Array<{ userId: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>
): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(collectionUsers).where(eq(collectionUsers.collectionId, collectionId));
  if (users.length) {
    await orm.insert(collectionUsers).values(users.map((user) => ({
      userId: user.userId,
      collectionId,
      readOnly: user.readOnly ? 1 : 0,
      hidePasswords: user.hidePasswords ? 1 : 0,
      manage: user.manage ? 1 : 0,
    })));
  }
}

export async function listCollectionUsers(db: D1Database, collectionId: string): Promise<CollectionAccess[]> {
  const rows = await getOrm(db)
    .select({
      userId: collectionUsers.userId,
      collectionId: collectionUsers.collectionId,
      readOnly: collectionUsers.readOnly,
      hidePasswords: collectionUsers.hidePasswords,
      manage: collectionUsers.manage,
    })
    .from(collectionUsers)
    .where(eq(collectionUsers.collectionId, collectionId));
  return rows.map((row) => ({
    ...mapAccess(row),
    userId: row.userId,
  })) as CollectionAccess[];
}

export async function listUserCollectionAccess(db: D1Database, userId: string, orgId: string): Promise<CollectionAccess[]> {
  const orm = getOrm(db);
  const direct = await orm
    .select({
      collectionId: collectionUsers.collectionId,
      readOnly: collectionUsers.readOnly,
      hidePasswords: collectionUsers.hidePasswords,
      manage: collectionUsers.manage,
    })
    .from(collectionUsers)
    .innerJoin(collections, eq(collections.id, collectionUsers.collectionId))
    .where(and(eq(collectionUsers.userId, userId), eq(collections.orgId, orgId)));

  const groupRows = await orm
    .select({
      collectionId: collectionGroups.collectionId,
      readOnly: collectionGroups.readOnly,
      hidePasswords: collectionGroups.hidePasswords,
      manage: collectionGroups.manage,
    })
    .from(collectionGroups)
    .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, collectionGroups.groupId))
    .innerJoin(organizationMemberships, eq(organizationMemberships.id, orgGroupMembers.membershipId))
    .innerJoin(collections, eq(collections.id, collectionGroups.collectionId))
    .where(and(eq(organizationMemberships.userId, userId), eq(collections.orgId, orgId)));

  const merged = new Map<string, CollectionAccess>();
  for (const access of [...direct, ...groupRows].map(mapAccess)) {
    const existing = merged.get(access.collectionId);
    if (!existing) {
      merged.set(access.collectionId, access);
      continue;
    }
    merged.set(access.collectionId, {
      collectionId: access.collectionId,
      readOnly: existing.readOnly && access.readOnly,
      hidePasswords: existing.hidePasswords && access.hidePasswords,
      manage: existing.manage || access.manage,
    });
  }
  return [...merged.values()];
}

export async function replaceCipherCollections(db: D1Database, cipherId: string, collectionIds: string[]): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(cipherCollections).where(eq(cipherCollections.cipherId, cipherId));
  if (collectionIds.length) {
    await orm.insert(cipherCollections).values(
      collectionIds.map((collectionId) => ({ cipherId, collectionId }))
    ).onConflictDoNothing();
  }
}

export async function listCipherCollectionIds(db: D1Database, cipherId: string): Promise<string[]> {
  const rows = await getOrm(db)
    .select({ collectionId: cipherCollections.collectionId })
    .from(cipherCollections)
    .where(eq(cipherCollections.cipherId, cipherId));
  return rows.map((row) => row.collectionId);
}

export async function listCipherCollectionIdsByCipherIds(
  db: D1Database,
  cipherIds: string[]
): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  if (cipherIds.length === 0) return map;
  const orm = getOrm(db);
  const chunkSize = 90;
  for (let offset = 0; offset < cipherIds.length; offset += chunkSize) {
    const chunk = cipherIds.slice(offset, offset + chunkSize);
    const rows = await orm
      .select({
        cipherId: cipherCollections.cipherId,
        collectionId: cipherCollections.collectionId,
      })
      .from(cipherCollections)
      .where(inArray(cipherCollections.cipherId, chunk));
    for (const row of rows) {
      const list = map.get(row.cipherId) || [];
      list.push(row.collectionId);
      map.set(row.cipherId, list);
    }
  }
  return map;
}

export async function listOrgCipherIds(db: D1Database, orgId: string): Promise<string[]> {
  const rows = await getOrm(db)
    .select({ id: ciphers.id })
    .from(ciphers)
    .where(eq(ciphers.organizationId, orgId));
  return rows.map((row) => row.id);
}

function mapOrgCipherRow(
  row: typeof ciphers.$inferSelect,
  userId: string,
  orgId: string,
  collectionIds: string[]
): Cipher | null {
  let parsed: Record<string, unknown> = {};
  try {
    parsed = JSON.parse(String(row.data || '{}')) as Record<string, unknown>;
  } catch {
    return null;
  }
  return {
    ...(parsed as unknown as Cipher),
    id: row.id,
    userId: row.userId || userId,
    organizationId: row.organizationId || orgId,
    type: Number(row.type) || 1,
    folderId: row.folderId ?? null,
    name: row.name ?? null,
    notes: row.notes ?? null,
    favorite: !!row.favorite,
    reprompt: Number(row.reprompt || 0),
    key: row.key ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    archivedAt: row.archivedAt ?? null,
    deletedAt: row.deletedAt ?? null,
    collectionIds,
  };
}

async function listOrgCipherCollectionIds(db: D1Database, orgId: string): Promise<Map<string, string[]>> {
  const rows = await getOrm(db)
    .select({
      cipherId: cipherCollections.cipherId,
      collectionId: cipherCollections.collectionId,
    })
    .from(cipherCollections)
    .innerJoin(ciphers, eq(ciphers.id, cipherCollections.cipherId))
    .where(eq(ciphers.organizationId, orgId));
  const map = new Map<string, string[]>();
  for (const row of rows) {
    const list = map.get(row.cipherId);
    if (list) list.push(row.collectionId);
    else map.set(row.cipherId, [row.collectionId]);
  }
  return map;
}

async function listRestrictedOrgCiphers(
  db: D1Database,
  userId: string,
  membershipId: string,
  orgId: string
): Promise<Array<typeof ciphers.$inferSelect>> {
  const orm = getOrm(db);
  const direct = await orm
    .select({ collectionId: collectionUsers.collectionId })
    .from(collectionUsers)
    .where(eq(collectionUsers.userId, userId));
  const grouped = await orm
    .select({ collectionId: collectionGroups.collectionId })
    .from(collectionGroups)
    .innerJoin(orgGroupMembers, eq(orgGroupMembers.groupId, collectionGroups.groupId))
    .where(eq(orgGroupMembers.membershipId, membershipId));
  const allowed = [...new Set([...direct, ...grouped].map((row) => row.collectionId))];
  if (!allowed.length) return [];

  const rows = await orm
    .select({ cipher: ciphers })
    .from(ciphers)
    .innerJoin(cipherCollections, eq(cipherCollections.cipherId, ciphers.id))
    .where(and(
      eq(ciphers.organizationId, orgId),
      inArray(cipherCollections.collectionId, allowed),
    ))
    .orderBy(desc(ciphers.updatedAt));

  const seen = new Set<string>();
  const unique: Array<typeof ciphers.$inferSelect> = [];
  for (const row of rows) {
    if (seen.has(row.cipher.id)) continue;
    seen.add(row.cipher.id);
    unique.push(row.cipher);
  }
  return unique;
}

export async function listAccessibleOrgCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const memberships = await listMembershipsByUser(db, userId);
  const confirmed = memberships.filter((member) => member.status === 2);
  if (confirmed.length === 0) return [];

  const orgCiphers: Cipher[] = [];
  for (const member of confirmed) {
    // Members without full access only reach ciphers in collections assigned to them
    // directly or through a group they belong to; everything else stays invisible.
    const rows = hasFullCollectionAccess(member)
      ? await getOrm(db)
        .select()
        .from(ciphers)
        .where(eq(ciphers.organizationId, member.orgId))
        .orderBy(desc(ciphers.updatedAt))
      : await listRestrictedOrgCiphers(db, userId, member.id, member.orgId);

    if (rows.length === 0) continue;
    const collectionsByCipher = await listOrgCipherCollectionIds(db, member.orgId);
    for (const row of rows) {
      const cipher = mapOrgCipherRow(row, userId, member.orgId, collectionsByCipher.get(row.id) || []);
      if (cipher) orgCiphers.push(cipher);
    }
  }
  return orgCiphers;
}

export async function saveGroup(db: D1Database, group: GroupRecord): Promise<void> {
  await getOrm(db)
    .insert(orgGroups)
    .values({
      id: group.id,
      orgId: group.orgId,
      name: group.name,
      accessAll: group.accessAll ? 1 : 0,
      externalId: group.externalId,
      createdAt: group.createdAt,
      updatedAt: group.updatedAt,
    })
    .onConflictDoUpdate({
      target: orgGroups.id,
      set: {
        name: group.name,
        accessAll: group.accessAll ? 1 : 0,
        externalId: group.externalId,
        updatedAt: group.updatedAt,
      },
    });
}

export async function getGroup(db: D1Database, id: string): Promise<GroupRecord | null> {
  const [row] = await getOrm(db).select().from(orgGroups).where(eq(orgGroups.id, id)).limit(1);
  return row ? mapGroup(row) : null;
}

export async function listGroupsByOrg(db: D1Database, orgId: string): Promise<GroupRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(orgGroups)
    .where(eq(orgGroups.orgId, orgId))
    .orderBy(asc(orgGroups.name));
  return rows.map(mapGroup);
}

export async function deleteGroup(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(orgGroups).where(eq(orgGroups.id, id));
}

export async function replaceGroupMembers(db: D1Database, groupId: string, membershipIds: string[]): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(orgGroupMembers).where(eq(orgGroupMembers.groupId, groupId));
  if (membershipIds.length) {
    await orm.insert(orgGroupMembers).values(
      membershipIds.map((membershipId) => ({ groupId, membershipId }))
    ).onConflictDoNothing();
  }
}

export async function listGroupMemberIds(db: D1Database, groupId: string): Promise<string[]> {
  const rows = await getOrm(db)
    .select({ membershipId: orgGroupMembers.membershipId })
    .from(orgGroupMembers)
    .where(eq(orgGroupMembers.groupId, groupId));
  return rows.map((row) => row.membershipId);
}

export async function replaceCollectionGroups(
  db: D1Database,
  collectionId: string,
  groups: Array<{ groupId: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>
): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(collectionGroups).where(eq(collectionGroups.collectionId, collectionId));
  if (groups.length) {
    await orm.insert(collectionGroups).values(groups.map((group) => ({
      collectionId,
      groupId: group.groupId,
      readOnly: group.readOnly ? 1 : 0,
      hidePasswords: group.hidePasswords ? 1 : 0,
      manage: group.manage ? 1 : 0,
    })));
  }
}

export async function savePolicy(db: D1Database, policy: PolicyRecord): Promise<void> {
  await getOrm(db)
    .insert(orgPolicies)
    .values({
      id: policy.id,
      orgId: policy.orgId,
      type: policy.type,
      enabled: policy.enabled ? 1 : 0,
      data: JSON.stringify(policy.data || {}),
      updatedAt: policy.updatedAt,
    })
    .onConflictDoUpdate({
      target: [orgPolicies.orgId, orgPolicies.type],
      set: {
        enabled: policy.enabled ? 1 : 0,
        data: JSON.stringify(policy.data || {}),
        updatedAt: policy.updatedAt,
      },
    });
}

export async function listPoliciesByOrg(db: D1Database, orgId: string): Promise<PolicyRecord[]> {
  const rows = await getOrm(db).select().from(orgPolicies).where(eq(orgPolicies.orgId, orgId));
  return rows.map(mapPolicy);
}

export async function listEnabledPoliciesForUser(db: D1Database, userId: string): Promise<PolicyRecord[]> {
  const rows = await getOrm(db)
    .select({ policy: orgPolicies })
    .from(orgPolicies)
    .innerJoin(organizationMemberships, eq(organizationMemberships.orgId, orgPolicies.orgId))
    .where(and(
      eq(organizationMemberships.userId, userId),
      eq(organizationMemberships.status, 2),
      eq(orgPolicies.enabled, 1),
    ));
  return rows.map((row) => mapPolicy(row.policy));
}

export async function getPolicy(db: D1Database, orgId: string, type: number): Promise<PolicyRecord | null> {
  const [row] = await getOrm(db)
    .select()
    .from(orgPolicies)
    .where(and(eq(orgPolicies.orgId, orgId), eq(orgPolicies.type, type)))
    .limit(1);
  return row ? mapPolicy(row) : null;
}

// The api_key column holds a one-way hash only; the plaintext key is shown once at mint time.
export async function saveOrganizationApiKey(
  db: D1Database,
  row: { id: string; orgId: string; type: number; apiKeyHash: string; revisionDate: string }
): Promise<void> {
  await getOrm(db)
    .insert(organizationApiKeys)
    .values({
      id: row.id,
      orgId: row.orgId,
      type: row.type,
      apiKey: row.apiKeyHash,
      revisionDate: row.revisionDate,
    })
    .onConflictDoUpdate({
      target: organizationApiKeys.id,
      set: { apiKey: row.apiKeyHash, revisionDate: row.revisionDate },
    });
}

export async function getOrganizationApiKey(db: D1Database, orgId: string): Promise<{ id: string; apiKeyHash: string } | null> {
  const [row] = await getOrm(db)
    .select({ id: organizationApiKeys.id, apiKey: organizationApiKeys.apiKey })
    .from(organizationApiKeys)
    .where(eq(organizationApiKeys.orgId, orgId))
    .orderBy(desc(organizationApiKeys.revisionDate))
    .limit(1);
  return row ? { id: row.id, apiKeyHash: row.apiKey } : null;
}

export async function saveScimToken(db: D1Database, orgId: string, tokenHash: string, createdAt: string): Promise<void> {
  await getOrm(db)
    .insert(organizationScimTokens)
    .values({ orgId, tokenHash, createdAt })
    .onConflictDoUpdate({
      target: organizationScimTokens.orgId,
      set: { tokenHash, createdAt },
    });
}

export async function getScimTokenHash(db: D1Database, orgId: string): Promise<string | null> {
  const [row] = await getOrm(db)
    .select({ tokenHash: organizationScimTokens.tokenHash })
    .from(organizationScimTokens)
    .where(eq(organizationScimTokens.orgId, orgId))
    .limit(1);
  return row?.tokenHash || null;
}

export async function saveSsoAuth(
  db: D1Database,
  row: {
    state: string;
    codeChallenge: string | null;
    redirectUri: string;
    clientId: string;
    bindingHash: string | null;
    identifier?: string | null;
    codeResponse?: string | null;
    codeResponseError?: string | null;
    createdAt: string;
    updatedAt: string;
  }
): Promise<void> {
  const values = {
    state: row.state,
    codeChallenge: row.codeChallenge,
    redirectUri: row.redirectUri,
    clientId: row.clientId,
    bindingHash: row.bindingHash,
    identifier: row.identifier || null,
    codeResponse: row.codeResponse || null,
    codeResponseError: row.codeResponseError || null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
  await getOrm(db)
    .insert(ssoAuth)
    .values(values)
    .onConflictDoUpdate({
      target: ssoAuth.state,
      set: {
        codeChallenge: values.codeChallenge,
        redirectUri: values.redirectUri,
        clientId: values.clientId,
        bindingHash: values.bindingHash,
        identifier: values.identifier,
        codeResponse: values.codeResponse,
        codeResponseError: values.codeResponseError,
        updatedAt: values.updatedAt,
      },
    });
}

export async function getSsoAuth(db: D1Database, state: string): Promise<{
  state: string;
  codeChallenge: string | null;
  redirectUri: string;
  clientId: string;
  bindingHash: string | null;
  identifier: string | null;
  codeResponse: string | null;
  codeResponseError: string | null;
} | null> {
  const [row] = await getOrm(db).select().from(ssoAuth).where(eq(ssoAuth.state, state)).limit(1);
  if (!row) return null;
  return {
    state: row.state,
    codeChallenge: row.codeChallenge,
    redirectUri: row.redirectUri,
    clientId: row.clientId,
    bindingHash: row.bindingHash,
    identifier: row.identifier,
    codeResponse: row.codeResponse,
    codeResponseError: row.codeResponseError,
  };
}

export async function saveSsoUser(db: D1Database, userId: string, identifier: string, createdAt: string): Promise<void> {
  await getOrm(db)
    .insert(ssoUsers)
    .values({ userId, identifier, createdAt })
    .onConflictDoUpdate({
      target: ssoUsers.userId,
      set: { identifier },
    });
}

export async function getSsoUserByIdentifier(db: D1Database, identifier: string): Promise<{ userId: string; identifier: string } | null> {
  const [row] = await getOrm(db)
    .select({ userId: ssoUsers.userId, identifier: ssoUsers.identifier })
    .from(ssoUsers)
    .where(eq(ssoUsers.identifier, identifier))
    .limit(1);
  return row ?? null;
}

export async function getSsoUserByUserId(db: D1Database, userId: string): Promise<{ userId: string; identifier: string } | null> {
  const [row] = await getOrm(db)
    .select({ userId: ssoUsers.userId, identifier: ssoUsers.identifier })
    .from(ssoUsers)
    .where(eq(ssoUsers.userId, userId))
    .limit(1);
  return row ?? null;
}

export async function bumpOrgMemberRevisions(db: D1Database, orgId: string): Promise<void> {
  const now = new Date().toISOString();
  await getOrm(db).run(sql`
    INSERT INTO user_revisions(user_id, revision_date)
    SELECT user_id, ${now} FROM organization_memberships
    WHERE org_id = ${orgId} AND user_id IS NOT NULL
    ON CONFLICT(user_id) DO UPDATE SET revision_date=excluded.revision_date
  `);
}
