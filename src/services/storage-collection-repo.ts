import type { Collection, CollectionUserAccess, OrganizationUserType } from '../types';
import { ORG_USER_STATUS, ORG_USER_TYPE } from '../config/org';

// Safe chunk for bulk id-list SQL (under the D1 100-variable limit).
const ID_LIST_CHUNK_SIZE = 90;

export interface UserCollectionAccess extends Collection {
  readOnly: boolean;
  hidePasswords: boolean;
}

// Resolved access for one organization cipher + member. Access rows reflect
// Bitwarden semantics: accessAll grants full edit; otherwise the member can
// edit when any accessible collection of the cipher grants edit, and passwords
// are hidden when every accessible collection hides them.
export interface CipherAccessInfo {
  organizationUserId: string;
  organizationUserType: OrganizationUserType;
  accessAll: boolean;
  canEdit: boolean;
  hidePasswords: boolean;
  accessibleCollectionIds: string[];
}

function mapCollectionRow(row: any): Collection {
  return {
    id: row.id,
    organizationId: row.organization_id,
    name: row.name,
    externalId: row.external_id ?? null,
    creationDate: row.creation_date,
    revisionDate: row.revision_date,
  };
}

const COLLECTION_COLUMNS = 'id, organization_id, name, external_id, creation_date, revision_date';

export async function getCollection(db: D1Database, id: string): Promise<Collection | null> {
  const row = await db
    .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections WHERE id = ?`)
    .bind(id)
    .first<any>();
  return row ? mapCollectionRow(row) : null;
}

export async function saveCollection(db: D1Database, collection: Collection): Promise<void> {
  await db
    .prepare(
      'INSERT INTO collections(id, organization_id, name, external_id, creation_date, revision_date) ' +
      'VALUES(?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, external_id=excluded.external_id, revision_date=excluded.revision_date ' +
      'WHERE organization_id=excluded.organization_id'
    )
    .bind(
      collection.id,
      collection.organizationId,
      collection.name,
      collection.externalId ?? null,
      collection.creationDate,
      collection.revisionDate
    )
    .run();
}

export async function deleteCollection(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM collections WHERE id = ?').bind(id).run();
}

// Delete a collection in a single statement that simultaneously proves the
// collection belongs to the named organization and the caller is a confirmed
// Owner of that organization — authorization and deletion cannot drift apart.
// Returns false when no such combination exists.
export async function deleteCollectionForOwner(
  db: D1Database,
  collectionId: string,
  organizationId: string,
  ownerUserId: string
): Promise<boolean> {
  const result = await db
    .prepare(
      'DELETE FROM collections WHERE id = ? AND organization_id = ? AND EXISTS (' +
        'SELECT 1 FROM organization_users ou ' +
        'WHERE ou.organization_id = ? AND ou.user_id = ? AND ou.type = ${ORG_USER_TYPE.OWNER} AND ou.status = ${ORG_USER_STATUS.CONFIRMED}' +
      ')'
    )
    .bind(collectionId, organizationId, organizationId, ownerUserId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function listCollectionsForOrganization(db: D1Database, organizationId: string): Promise<Collection[]> {
  const result = await db
    .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections WHERE organization_id = ? ORDER BY creation_date ASC`)
    .bind(organizationId)
    .all<any>();
  return (result.results || []).map(mapCollectionRow);
}

export async function getCollectionsByIds(
  db: D1Database,
  ids: string[],
  sqlChunkSize: (fixedBindCount: number, bindCountPerItem?: number) => number
): Promise<Collection[]> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return [];
  const out: Collection[] = [];
  const chunkSize = sqlChunkSize(0);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const result = await db
      .prepare(`SELECT ${COLLECTION_COLUMNS} FROM collections WHERE id IN (${placeholders})`)
      .bind(...chunk)
      .all<any>();
    out.push(...(result.results || []).map(mapCollectionRow));
  }
  return out;
}

// Collections a confirmed member can see, with per-member flags.
export async function listCollectionsForUser(db: D1Database, userId: string): Promise<UserCollectionAccess[]> {
  const result = await db
    .prepare(
      `SELECT c.id, c.organization_id, c.name, c.external_id, c.creation_date, c.revision_date,
              CASE WHEN ou.access_all = 1 THEN 0 ELSE COALESCE(cu.read_only, 0) END AS read_only,
              CASE WHEN ou.access_all = 1 THEN 0 ELSE COALESCE(cu.hide_passwords, 0) END AS hide_passwords
       FROM collections c
       JOIN organization_users ou
         ON ou.organization_id = c.organization_id AND ou.user_id = ? AND ou.status = ${ORG_USER_STATUS.CONFIRMED}
       LEFT JOIN collection_users cu ON cu.collection_id = c.id AND cu.organization_user_id = ou.id
       WHERE ou.access_all = 1 OR cu.collection_id IS NOT NULL
       ORDER BY c.creation_date ASC`
    )
    .bind(userId)
    .all<any>();
  return (result.results || []).map((row) => ({
    ...mapCollectionRow(row),
    readOnly: !!Number(row.read_only),
    hidePasswords: !!Number(row.hide_passwords),
  }));
}

export async function listCollectionUsers(db: D1Database, collectionId: string): Promise<CollectionUserAccess[]> {
  const result = await db
    .prepare(
      'SELECT collection_id, organization_user_id, read_only, hide_passwords FROM collection_users WHERE collection_id = ?'
    )
    .bind(collectionId)
    .all<any>();
  return (result.results || []).map((row) => ({
    collectionId: row.collection_id,
    organizationUserId: row.organization_user_id,
    readOnly: !!Number(row.read_only),
    hidePasswords: !!Number(row.hide_passwords),
  }));
}

// Replace the complete set of member access rows for a collection.
export async function replaceCollectionUsers(
  db: D1Database,
  collectionId: string,
  rows: Array<{ organizationUserId: string; readOnly: boolean; hidePasswords: boolean }>
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM collection_users WHERE collection_id = ?').bind(collectionId),
  ];
  for (const row of rows) {
    statements.push(
      db
        .prepare(
          'INSERT INTO collection_users(collection_id, organization_user_id, read_only, hide_passwords) VALUES(?, ?, ?, ?)'
        )
        .bind(collectionId, row.organizationUserId, row.readOnly ? 1 : 0, row.hidePasswords ? 1 : 0)
    );
  }
  await db.batch(statements);
}

// Replace the complete set of collection access rows for an organization user.
export async function replaceOrganizationUserCollections(
  db: D1Database,
  organizationUserId: string,
  rows: Array<{ collectionId: string; readOnly: boolean; hidePasswords: boolean }>
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM collection_users WHERE organization_user_id = ?').bind(organizationUserId),
  ];
  for (const row of rows) {
    statements.push(
      db
        .prepare(
          'INSERT INTO collection_users(collection_id, organization_user_id, read_only, hide_passwords) VALUES(?, ?, ?, ?)'
        )
        .bind(row.collectionId, organizationUserId, row.readOnly ? 1 : 0, row.hidePasswords ? 1 : 0)
    );
  }
  await db.batch(statements);
}

export async function setCipherCollections(
  db: D1Database,
  cipherId: string,
  collectionIds: string[]
): Promise<void> {
  const uniqueIds = Array.from(new Set(collectionIds.map((id) => String(id || '').trim()).filter(Boolean)));
  const statements: D1PreparedStatement[] = [
    db.prepare('DELETE FROM cipher_collections WHERE cipher_id = ?').bind(cipherId),
  ];
  for (const collectionId of uniqueIds) {
    statements.push(
      db.prepare('INSERT INTO cipher_collections(cipher_id, collection_id) VALUES(?, ?)').bind(cipherId, collectionId)
    );
  }
  await db.batch(statements);
}

export async function listCollectionIdsForCipher(db: D1Database, cipherId: string): Promise<string[]> {
  const result = await db
    .prepare('SELECT collection_id FROM cipher_collections WHERE cipher_id = ?')
    .bind(cipherId)
    .all<{ collection_id: string }>();
  return (result.results || []).map((row) => row.collection_id);
}

export async function listCollectionIdsForCiphers(
  db: D1Database,
  cipherIds: string[]
): Promise<Map<string, string[]>> {
  const uniqueIds = Array.from(new Set(cipherIds.map((id) => String(id || '').trim()).filter(Boolean)));
  const out = new Map<string, string[]>();
  if (!uniqueIds.length) return out;
  for (let i = 0; i < uniqueIds.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = uniqueIds.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    const result = await db
      .prepare(`SELECT cipher_id, collection_id FROM cipher_collections WHERE cipher_id IN (${placeholders})`)
      .bind(...chunk)
      .all<{ cipher_id: string; collection_id: string }>();
    for (const row of result.results || []) {
      const list = out.get(row.cipher_id) || [];
      list.push(row.collection_id);
      out.set(row.cipher_id, list);
    }
  }
  return out;
}

// Resolve member access for a single organization cipher.
export async function resolveCipherAccessForUser(
  db: D1Database,
  cipherId: string,
  userId: string
): Promise<CipherAccessInfo | null> {
  const membership = await db
    .prepare(
      `SELECT c.organization_id, ou.id AS organization_user_id, ou.type AS organization_user_type, ou.access_all
       FROM ciphers c
       JOIN organization_users ou
         ON ou.organization_id = c.organization_id AND ou.user_id = ? AND ou.status = ${ORG_USER_STATUS.CONFIRMED}
       WHERE c.id = ? AND c.organization_id IS NOT NULL`
    )
    .bind(userId, cipherId)
    .first<{
      organization_id: string;
      organization_user_id: string;
      organization_user_type: number;
      access_all: number;
    }>();
  if (!membership) return null;

  const accessAll = !!Number(membership.access_all);
  let canEdit = accessAll;
  let hidePasswords = false;
  let accessibleCollectionIds: string[] = [];

  if (accessAll) {
    const all = await db
      .prepare('SELECT collection_id FROM cipher_collections WHERE cipher_id = ?')
      .bind(cipherId)
      .all<{ collection_id: string }>();
    accessibleCollectionIds = (all.results || []).map((row) => row.collection_id);
  } else {
    const rows = await db
      .prepare(
        `SELECT cc.collection_id, cu.read_only, cu.hide_passwords
         FROM cipher_collections cc
         JOIN collection_users cu ON cu.collection_id = cc.collection_id AND cu.organization_user_id = ?
         WHERE cc.cipher_id = ?`
      )
      .bind(membership.organization_user_id, cipherId)
      .all<{ collection_id: string; read_only: number; hide_passwords: number }>();
    const results = rows.results || [];
    if (!results.length) return null;
    accessibleCollectionIds = results.map((row) => row.collection_id);
    canEdit = results.some((row) => !Number(row.read_only));
    hidePasswords = results.every((row) => !!Number(row.hide_passwords));
  }

  return {
    organizationUserId: membership.organization_user_id,
    organizationUserType: Number(membership.organization_user_type) as OrganizationUserType,
    accessAll,
    canEdit,
    hidePasswords,
    accessibleCollectionIds,
  };
}

export async function listCollectionUsersByOrganizationUser(
  db: D1Database,
  organizationUserId: string
): Promise<Array<{ collectionId: string; readOnly: boolean; hidePasswords: boolean }>> {
  const result = await db
    .prepare(
      'SELECT collection_id, read_only, hide_passwords FROM collection_users WHERE organization_user_id = ?'
    )
    .bind(organizationUserId)
    .all<{ collection_id: string; read_only: number; hide_passwords: number }>();
  return (result.results || []).map((row) => ({
    collectionId: row.collection_id,
    readOnly: !!Number(row.read_only),
    hidePasswords: !!Number(row.hide_passwords),
  }));
}
