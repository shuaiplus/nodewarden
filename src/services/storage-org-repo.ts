import type { Cipher } from '../types';
import {
  type CollectionAccess,
  type CollectionRecord,
  type GroupRecord,
  type MembershipRecord,
  type OrganizationRecord,
  type PolicyRecord,
  parsePermissions,
} from './org-types';

interface OrganizationRow {
  id: string;
  name: string;
  billing_email: string;
  identifier: string | null;
  private_key: string | null;
  public_key: string | null;
  created_at: string;
  updated_at: string;
}

interface MembershipRow {
  id: string;
  user_id: string | null;
  org_id: string;
  email: string | null;
  invited_by_email: string | null;
  access_all: number;
  key: string;
  status: number;
  type: number;
  permissions: string | null;
  reset_password_key: string | null;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

interface CollectionRow {
  id: string;
  org_id: string;
  name: string;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

interface GroupRow {
  id: string;
  org_id: string;
  name: string;
  access_all: number;
  external_id: string | null;
  created_at: string;
  updated_at: string;
}

interface PolicyRow {
  id: string;
  org_id: string;
  type: number;
  enabled: number;
  data: string;
  updated_at: string;
}

function mapOrganization(row: OrganizationRow): OrganizationRecord {
  return {
    id: row.id,
    name: row.name,
    billingEmail: row.billing_email,
    identifier: row.identifier,
    privateKey: row.private_key,
    publicKey: row.public_key,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapMembership(row: MembershipRow): MembershipRecord {
  return {
    id: row.id,
    userId: row.user_id,
    orgId: row.org_id,
    email: row.email,
    invitedByEmail: row.invited_by_email,
    accessAll: !!row.access_all,
    key: row.key || '',
    status: Number(row.status),
    type: Number(row.type),
    permissions: parsePermissions(row.permissions),
    resetPasswordKey: row.reset_password_key,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapCollection(row: CollectionRow): CollectionRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapGroup(row: GroupRow): GroupRecord {
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    accessAll: !!row.access_all,
    externalId: row.external_id,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapPolicy(row: PolicyRow): PolicyRecord {
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(row.data || '{}') as Record<string, unknown>;
  } catch {
    data = {};
  }
  return {
    id: row.id,
    orgId: row.org_id,
    type: Number(row.type),
    enabled: !!row.enabled,
    data,
    updatedAt: row.updated_at,
  };
}

export async function insertOrganization(db: D1Database, org: OrganizationRecord): Promise<void> {
  await db.prepare(
    'INSERT INTO organizations(id, name, billing_email, identifier, private_key, public_key, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(org.id, org.name, org.billingEmail, org.identifier, org.privateKey, org.publicKey, org.createdAt, org.updatedAt).run();
}

export async function updateOrganization(db: D1Database, org: OrganizationRecord): Promise<void> {
  await db.prepare(
    'UPDATE organizations SET name = ?, billing_email = ?, identifier = ?, private_key = ?, public_key = ?, updated_at = ? WHERE id = ?'
  ).bind(org.name, org.billingEmail, org.identifier, org.privateKey, org.publicKey, org.updatedAt, org.id).run();
}

export async function getOrganization(db: D1Database, id: string): Promise<OrganizationRecord | null> {
  const row = await db.prepare('SELECT * FROM organizations WHERE id = ?').bind(id).first<OrganizationRow>();
  return row ? mapOrganization(row) : null;
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

export async function saveMembership(db: D1Database, member: MembershipRecord): Promise<void> {
  await db.prepare(
    'INSERT INTO organization_memberships(id, user_id, org_id, email, invited_by_email, access_all, key, status, type, permissions, reset_password_key, external_id, created_at, updated_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET user_id=excluded.user_id, email=excluded.email, invited_by_email=excluded.invited_by_email, access_all=excluded.access_all, key=excluded.key, status=excluded.status, type=excluded.type, permissions=excluded.permissions, reset_password_key=excluded.reset_password_key, external_id=excluded.external_id, updated_at=excluded.updated_at'
  ).bind(
    member.id,
    member.userId,
    member.orgId,
    member.email,
    member.invitedByEmail,
    member.accessAll ? 1 : 0,
    member.key,
    member.status,
    member.type,
    member.permissions ? JSON.stringify(member.permissions) : null,
    member.resetPasswordKey,
    member.externalId,
    member.createdAt,
    member.updatedAt
  ).run();
}

export async function getMembership(db: D1Database, id: string): Promise<MembershipRecord | null> {
  const row = await db.prepare('SELECT * FROM organization_memberships WHERE id = ?').bind(id).first<MembershipRow>();
  return row ? mapMembership(row) : null;
}

export async function getMembershipByUserAndOrg(
  db: D1Database,
  userId: string,
  orgId: string
): Promise<MembershipRecord | null> {
  const row = await db
    .prepare('SELECT * FROM organization_memberships WHERE user_id = ? AND org_id = ?')
    .bind(userId, orgId)
    .first<MembershipRow>();
  return row ? mapMembership(row) : null;
}

export async function listMembershipsByUser(db: D1Database, userId: string): Promise<MembershipRecord[]> {
  const result = await db
    .prepare('SELECT * FROM organization_memberships WHERE user_id = ? ORDER BY created_at')
    .bind(userId)
    .all<MembershipRow>();
  return (result.results || []).map(mapMembership);
}

export async function listMembershipsByOrg(db: D1Database, orgId: string): Promise<MembershipRecord[]> {
  const result = await db
    .prepare('SELECT * FROM organization_memberships WHERE org_id = ? ORDER BY created_at')
    .bind(orgId)
    .all<MembershipRow>();
  return (result.results || []).map(mapMembership);
}

export async function deleteMembership(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organization_memberships WHERE id = ?').bind(id).run();
}

export async function countConfirmedOwners(db: D1Database, orgId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) as count FROM organization_memberships WHERE org_id = ? AND type = 0 AND status = 2')
    .bind(orgId)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function saveCollection(db: D1Database, collection: CollectionRecord): Promise<void> {
  await db.prepare(
    'INSERT INTO collections(id, org_id, name, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET name=excluded.name, external_id=excluded.external_id, updated_at=excluded.updated_at'
  ).bind(
    collection.id,
    collection.orgId,
    collection.name,
    collection.externalId,
    collection.createdAt,
    collection.updatedAt
  ).run();
}

export async function getCollection(db: D1Database, id: string): Promise<CollectionRecord | null> {
  const row = await db.prepare('SELECT * FROM collections WHERE id = ?').bind(id).first<CollectionRow>();
  return row ? mapCollection(row) : null;
}

export async function listCollectionsByOrg(db: D1Database, orgId: string): Promise<CollectionRecord[]> {
  const result = await db.prepare('SELECT * FROM collections WHERE org_id = ? ORDER BY created_at').bind(orgId).all<CollectionRow>();
  return (result.results || []).map(mapCollection);
}

export async function deleteCollection(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM collections WHERE id = ?').bind(id).run();
}

export async function replaceCollectionUsers(
  db: D1Database,
  collectionId: string,
  users: Array<{ userId: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>
): Promise<void> {
  await db.prepare('DELETE FROM collection_users WHERE collection_id = ?').bind(collectionId).run();
  for (const user of users) {
    await db.prepare(
      'INSERT INTO collection_users(user_id, collection_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?)'
    ).bind(user.userId, collectionId, user.readOnly ? 1 : 0, user.hidePasswords ? 1 : 0, user.manage ? 1 : 0).run();
  }
}

export async function listCollectionUsers(db: D1Database, collectionId: string): Promise<CollectionAccess[]> {
  const result = await db
    .prepare('SELECT user_id, collection_id, read_only, hide_passwords, manage FROM collection_users WHERE collection_id = ?')
    .bind(collectionId)
    .all<{ user_id: string; collection_id: string; read_only: number; hide_passwords: number; manage: number }>();
  return (result.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
    userId: row.user_id,
  })) as CollectionAccess[];
}

export async function listUserCollectionAccess(db: D1Database, userId: string, orgId: string): Promise<CollectionAccess[]> {
  const result = await db.prepare(
    'SELECT cu.collection_id, cu.read_only, cu.hide_passwords, cu.manage ' +
    'FROM collection_users cu INNER JOIN collections c ON c.id = cu.collection_id ' +
    'WHERE cu.user_id = ? AND c.org_id = ?'
  ).bind(userId, orgId).all<{ collection_id: string; read_only: number; hide_passwords: number; manage: number }>();
  const direct = (result.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  }));

  const groupResult = await db.prepare(
    'SELECT cg.collection_id, cg.read_only, cg.hide_passwords, cg.manage ' +
    'FROM collection_groups cg ' +
    'INNER JOIN org_group_members gm ON gm.group_id = cg.group_id ' +
    'INNER JOIN organization_memberships m ON m.id = gm.membership_id ' +
    'INNER JOIN collections c ON c.id = cg.collection_id ' +
    'WHERE m.user_id = ? AND c.org_id = ?'
  ).bind(userId, orgId).all<{ collection_id: string; read_only: number; hide_passwords: number; manage: number }>();

  const merged = new Map<string, CollectionAccess>();
  for (const access of [...direct, ...(groupResult.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!row.read_only,
    hidePasswords: !!row.hide_passwords,
    manage: !!row.manage,
  }))]) {
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
  await db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ?').bind(cipherId).run();
  for (const collectionId of collectionIds) {
    await db.prepare('INSERT OR IGNORE INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)').bind(cipherId, collectionId).run();
  }
}

export async function listCipherCollectionIds(db: D1Database, cipherId: string): Promise<string[]> {
  const result = await db
    .prepare('SELECT collection_id FROM cipher_collections WHERE cipher_id = ?')
    .bind(cipherId)
    .all<{ collection_id: string }>();
  return (result.results || []).map((row) => row.collection_id);
}

export async function listCipherCollectionIdsByCipherIds(
  db: D1Database,
  cipherIds: string[]
): Promise<Map<string, string[]>> {
  const map = new Map<string, string[]>();
  if (cipherIds.length === 0) return map;
  const placeholders = cipherIds.map(() => '?').join(',');
  const result = await db
    .prepare(`SELECT cipher_id, collection_id FROM cipher_collections WHERE cipher_id IN (${placeholders})`)
    .bind(...cipherIds)
    .all<{ cipher_id: string; collection_id: string }>();
  for (const row of result.results || []) {
    const list = map.get(row.cipher_id) || [];
    list.push(row.collection_id);
    map.set(row.cipher_id, list);
  }
  return map;
}

export async function listOrgCipherIds(db: D1Database, orgId: string): Promise<string[]> {
  const result = await db
    .prepare('SELECT id FROM ciphers WHERE organization_id = ?')
    .bind(orgId)
    .all<{ id: string }>();
  return (result.results || []).map((row) => row.id);
}

export async function listAccessibleOrgCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const memberships = await listMembershipsByUser(db, userId);
  const confirmed = memberships.filter((member) => member.status === 2);
  if (confirmed.length === 0) return [];

  const ciphers: Cipher[] = [];
  for (const member of confirmed) {
    const result = await db
      .prepare(
        'SELECT id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at ' +
        'FROM ciphers WHERE organization_id = ? ORDER BY updated_at DESC'
      )
      .bind(member.orgId)
      .all<Record<string, unknown>>();
    for (const row of result.results || []) {
      const dataRaw = String(row.data || '{}');
      let parsed: Record<string, unknown> = {};
      try {
        parsed = JSON.parse(dataRaw) as Record<string, unknown>;
      } catch {
        continue;
      }
      ciphers.push({
        ...(parsed as unknown as Cipher),
        id: String(row.id),
        userId: String(row.user_id || userId),
        organizationId: String(row.organization_id || member.orgId),
        type: Number(row.type) || 1,
        folderId: (row.folder_id as string | null) ?? null,
        name: (row.name as string | null) ?? null,
        notes: (row.notes as string | null) ?? null,
        favorite: !!row.favorite,
        reprompt: Number(row.reprompt || 0),
        key: (row.key as string | null) ?? null,
        createdAt: String(row.created_at),
        updatedAt: String(row.updated_at),
        archivedAt: (row.archived_at as string | null) ?? null,
        deletedAt: (row.deleted_at as string | null) ?? null,
      });
    }
  }
  return ciphers;
}

export async function saveGroup(db: D1Database, group: GroupRecord): Promise<void> {
  await db.prepare(
    'INSERT INTO org_groups(id, org_id, name, access_all, external_id, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET name=excluded.name, access_all=excluded.access_all, external_id=excluded.external_id, updated_at=excluded.updated_at'
  ).bind(group.id, group.orgId, group.name, group.accessAll ? 1 : 0, group.externalId, group.createdAt, group.updatedAt).run();
}

export async function getGroup(db: D1Database, id: string): Promise<GroupRecord | null> {
  const row = await db.prepare('SELECT * FROM org_groups WHERE id = ?').bind(id).first<GroupRow>();
  return row ? mapGroup(row) : null;
}

export async function listGroupsByOrg(db: D1Database, orgId: string): Promise<GroupRecord[]> {
  const result = await db.prepare('SELECT * FROM org_groups WHERE org_id = ? ORDER BY name').bind(orgId).all<GroupRow>();
  return (result.results || []).map(mapGroup);
}

export async function deleteGroup(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM org_groups WHERE id = ?').bind(id).run();
}

export async function replaceGroupMembers(db: D1Database, groupId: string, membershipIds: string[]): Promise<void> {
  await db.prepare('DELETE FROM org_group_members WHERE group_id = ?').bind(groupId).run();
  for (const membershipId of membershipIds) {
    await db.prepare('INSERT OR IGNORE INTO org_group_members(group_id, membership_id) VALUES(?, ?)').bind(groupId, membershipId).run();
  }
}

export async function listGroupMemberIds(db: D1Database, groupId: string): Promise<string[]> {
  const result = await db.prepare('SELECT membership_id FROM org_group_members WHERE group_id = ?').bind(groupId).all<{ membership_id: string }>();
  return (result.results || []).map((row) => row.membership_id);
}

export async function replaceCollectionGroups(
  db: D1Database,
  collectionId: string,
  groups: Array<{ groupId: string; readOnly: boolean; hidePasswords: boolean; manage: boolean }>
): Promise<void> {
  await db.prepare('DELETE FROM collection_groups WHERE collection_id = ?').bind(collectionId).run();
  for (const group of groups) {
    await db.prepare(
      'INSERT INTO collection_groups(collection_id, group_id, read_only, hide_passwords, manage) VALUES(?, ?, ?, ?, ?)'
    ).bind(collectionId, group.groupId, group.readOnly ? 1 : 0, group.hidePasswords ? 1 : 0, group.manage ? 1 : 0).run();
  }
}

export async function savePolicy(db: D1Database, policy: PolicyRecord): Promise<void> {
  await db.prepare(
    'INSERT INTO org_policies(id, org_id, type, enabled, data, updated_at) VALUES(?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(org_id, type) DO UPDATE SET enabled=excluded.enabled, data=excluded.data, updated_at=excluded.updated_at'
  ).bind(policy.id, policy.orgId, policy.type, policy.enabled ? 1 : 0, JSON.stringify(policy.data || {}), policy.updatedAt).run();
}

export async function listPoliciesByOrg(db: D1Database, orgId: string): Promise<PolicyRecord[]> {
  const result = await db.prepare('SELECT * FROM org_policies WHERE org_id = ?').bind(orgId).all<PolicyRow>();
  return (result.results || []).map(mapPolicy);
}

export async function listEnabledPoliciesForUser(db: D1Database, userId: string): Promise<PolicyRecord[]> {
  const result = await db.prepare(
    'SELECT p.* FROM org_policies p INNER JOIN organization_memberships m ON m.org_id = p.org_id ' +
    'WHERE m.user_id = ? AND m.status = 2 AND p.enabled = 1'
  ).bind(userId).all<PolicyRow>();
  return (result.results || []).map(mapPolicy);
}

export async function getPolicy(db: D1Database, orgId: string, type: number): Promise<PolicyRecord | null> {
  const row = await db.prepare('SELECT * FROM org_policies WHERE org_id = ? AND type = ?').bind(orgId, type).first<PolicyRow>();
  return row ? mapPolicy(row) : null;
}

export async function saveOrganizationApiKey(
  db: D1Database,
  row: { id: string; orgId: string; type: number; apiKey: string; revisionDate: string }
): Promise<void> {
  await db.prepare(
    'INSERT INTO organization_api_keys(id, org_id, type, api_key, revision_date) VALUES(?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET api_key=excluded.api_key, revision_date=excluded.revision_date'
  ).bind(row.id, row.orgId, row.type, row.apiKey, row.revisionDate).run();
}

export async function getOrganizationApiKey(db: D1Database, orgId: string): Promise<{ id: string; apiKey: string } | null> {
  const row = await db
    .prepare('SELECT id, api_key FROM organization_api_keys WHERE org_id = ? ORDER BY revision_date DESC LIMIT 1')
    .bind(orgId)
    .first<{ id: string; api_key: string }>();
  return row ? { id: row.id, apiKey: row.api_key } : null;
}

export async function saveScimToken(db: D1Database, orgId: string, tokenHash: string, createdAt: string): Promise<void> {
  await db.prepare(
    'INSERT INTO organization_scim_tokens(org_id, token_hash, created_at) VALUES(?, ?, ?) ' +
    'ON CONFLICT(org_id) DO UPDATE SET token_hash=excluded.token_hash, created_at=excluded.created_at'
  ).bind(orgId, tokenHash, createdAt).run();
}

export async function getScimTokenHash(db: D1Database, orgId: string): Promise<string | null> {
  const row = await db.prepare('SELECT token_hash FROM organization_scim_tokens WHERE org_id = ?').bind(orgId).first<{ token_hash: string }>();
  return row?.token_hash || null;
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
  await db.prepare(
    'INSERT INTO sso_auth(state, code_challenge, redirect_uri, client_id, binding_hash, identifier, code_response, code_response_error, created_at, updated_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(state) DO UPDATE SET code_challenge=excluded.code_challenge, redirect_uri=excluded.redirect_uri, client_id=excluded.client_id, binding_hash=excluded.binding_hash, identifier=excluded.identifier, code_response=excluded.code_response, code_response_error=excluded.code_response_error, updated_at=excluded.updated_at'
  ).bind(
    row.state,
    row.codeChallenge,
    row.redirectUri,
    row.clientId,
    row.bindingHash,
    row.identifier || null,
    row.codeResponse || null,
    row.codeResponseError || null,
    row.createdAt,
    row.updatedAt
  ).run();
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
  const row = await db.prepare('SELECT * FROM sso_auth WHERE state = ?').bind(state).first<{
    state: string;
    code_challenge: string | null;
    redirect_uri: string;
    client_id: string;
    binding_hash: string | null;
    identifier: string | null;
    code_response: string | null;
    code_response_error: string | null;
  }>();
  if (!row) return null;
  return {
    state: row.state,
    codeChallenge: row.code_challenge,
    redirectUri: row.redirect_uri,
    clientId: row.client_id,
    bindingHash: row.binding_hash,
    identifier: row.identifier,
    codeResponse: row.code_response,
    codeResponseError: row.code_response_error,
  };
}

export async function saveSsoUser(db: D1Database, userId: string, identifier: string, createdAt: string): Promise<void> {
  await db.prepare(
    'INSERT INTO sso_users(user_id, identifier, created_at) VALUES(?, ?, ?) ON CONFLICT(user_id) DO UPDATE SET identifier=excluded.identifier'
  ).bind(userId, identifier, createdAt).run();
}

export async function getSsoUserByIdentifier(db: D1Database, identifier: string): Promise<{ userId: string; identifier: string } | null> {
  const row = await db.prepare('SELECT user_id, identifier FROM sso_users WHERE identifier = ?').bind(identifier).first<{ user_id: string; identifier: string }>();
  return row ? { userId: row.user_id, identifier: row.identifier } : null;
}

export async function getSsoUserByUserId(db: D1Database, userId: string): Promise<{ userId: string; identifier: string } | null> {
  const row = await db.prepare('SELECT user_id, identifier FROM sso_users WHERE user_id = ?').bind(userId).first<{ user_id: string; identifier: string }>();
  return row ? { userId: row.user_id, identifier: row.identifier } : null;
}

export async function bumpOrgMemberRevisions(db: D1Database, orgId: string): Promise<void> {
  const now = new Date().toISOString();
  await db.prepare(
    'INSERT INTO user_revisions(user_id, revision_date) ' +
    'SELECT user_id, ? FROM organization_memberships WHERE org_id = ? AND user_id IS NOT NULL ' +
    'ON CONFLICT(user_id) DO UPDATE SET revision_date=excluded.revision_date'
  ).bind(now, orgId).run();
}
