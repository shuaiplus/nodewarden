import type { Cipher } from '../types';
import {
  listCollectionIdsForCiphers,
  resolveCipherAccessForUser,
  type CipherAccessInfo,
} from './storage-collection-repo';

// Safe chunk for bulk id-list SQL (under the D1 100-variable limit).
const ID_LIST_CHUNK_SIZE = 90;

import { ORG_USER_STATUS } from '../config/org';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number, bindCountPerItem?: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

interface CipherRow {
  id: string;
  user_id: string | null;
  organization_id: string | null;
  type: number | null;
  folder_id: string | null;
  name: string | null;
  notes: string | null;
  favorite: number | null;
  data: string;
  reprompt: number | null;
  key: string | null;
  created_at: string;
  updated_at: string;
  archived_at: string | null;
  deleted_at: string | null;
}

const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
  // Server-managed organization fields: kept in columns, never in the JSON blob.
  'organizationId',
  'organization_id',
  'organizationFolderId',
  'organization_folder_id',
  'collectionIds',
  'CollectionIds',
  'edit',
  'Edit',
  'viewPassword',
  'ViewPassword',
]);

function buildCipherData(cipher: Cipher, folderId: string | null): string {
  const payload: Record<string, unknown> = {
    ...cipher,
    folderId,
  };
  for (const key of CIPHER_SCALAR_DATA_KEYS) {
    delete payload[key];
  }
  return JSON.stringify(payload);
}

function parseCipherRow(row: CipherRow | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    const folderId = normalizeOptionalId(row.folder_id ?? parsed.folderId ?? null);
    return {
      ...parsed,
      id: row.id,
      userId: row.user_id ?? null,
      organizationId: normalizeOptionalId(row.organization_id ?? null),
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId,
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      archivedAt: row.archived_at ?? parsed.archivedAt ?? parsed.archivedDate ?? null,
      deletedAt: row.deleted_at ?? parsed.deletedAt ?? parsed.deletedDate ?? null,
    };
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}

function selectCipherColumns(): string {
  return 'id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at';
}

export async function getCipher(db: D1Database, id: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ?`)
    .bind(id)
    .first<CipherRow>();
  return parseCipherRow(row);
}

export async function getCipherForUser(db: D1Database, id: string, userId: string): Promise<Cipher | null> {
  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ? AND user_id = ?`)
    .bind(id, userId)
    .first<CipherRow>();
  return parseCipherRow(row);
}

export async function saveCipher(db: D1Database, safeBind: SafeBind, cipher: Cipher): Promise<void> {
  // Org rows never persist a personal folder id: shared-item filing is
  // per-user (cipher_user_folders) and the in-memory folderId may carry the
  // acting user's overlaid assignment for response building.
  const folderId = cipher.organizationId ? null : normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, organization_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=excluded.archived_at, deleted_at=excluded.deleted_at ' +
    // IS comparison so organization ciphers (user_id NULL) can update.
    'WHERE user_id IS excluded.user_id'
  );
  await safeBind(
    stmt,
    cipher.id,
    cipher.userId ?? null,
    normalizeOptionalId(cipher.organizationId),
    Number(cipher.type) || 1,
    folderId,
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.createdAt,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt
  ).run();
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM ciphers WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = ?, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkRestoreCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = NULL, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const chunkSize = sqlChunkSize(1);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`).bind(userId, ...chunk).run();
  }

  return updateRevisionDate(userId);
}

export async function getAllCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const res = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? ORDER BY updated_at DESC`)
    .bind(userId)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const whereDeleted = includeDeleted
    ? ''
    : "AND deleted_at IS NULL AND json_extract(data, '$.deletedAt') IS NULL AND json_extract(data, '$.deletedDate') IS NULL";
  const res = await db
    .prepare(
      `SELECT ${selectCipherColumns()} FROM ciphers
       WHERE user_id = ?
       ${whereDeleted}
       ORDER BY updated_at DESC
       LIMIT ? OFFSET ?`
    )
    .bind(userId, limit, offset)
    .all<CipherRow>();
  return (res.results || []).flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  if (ids.length === 0) return [];
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return [];

  const chunkSize = sqlChunkSize(1);
  const out: Cipher[] = [];
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const stmt = db.prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE user_id = ? AND id IN (${placeholders})`);
    const res = await stmt.bind(userId, ...chunk).all<CipherRow>();
    out.push(
      ...(res.results || []).flatMap((row) => {
        const cipher = parseCipherRow(row);
        return cipher ? [cipher] : [];
      })
    );
  }
  return out;
}

export async function bulkMoveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const now = new Date().toISOString();
  const normalizedFolderId = normalizeOptionalId(folderId);
  const uniqueIds = sanitizeIds(ids);
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET folder_id = ?, updated_at = ?,
             data = json_remove(data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate')
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(normalizedFolderId, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkArchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(3);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = ?, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE user_id = ? AND id IN (${placeholders})
           AND deleted_at IS NULL
           AND json_extract(data, '$.deletedAt') IS NULL
           AND json_extract(data, '$.deletedDate') IS NULL`
      )
      .bind(now, now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

export async function bulkUnarchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;

  const now = new Date().toISOString();
  const chunkSize = sqlChunkSize(2);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = NULL, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(now, userId, ...chunk)
      .run();
  }

  return updateRevisionDate(userId);
}

// --- Organization-aware cipher queries ---

export interface AccessibleCipher {
  cipher: Cipher;
  /** null for personally-owned ciphers (full access). */
  access: CipherAccessInfo | null;
}

// Load one cipher for a user: personal ownership or confirmed org membership.
export async function getAccessibleCipher(db: D1Database, id: string, userId: string): Promise<AccessibleCipher | null> {
  const personal = await getCipherForUser(db, id, userId);
  if (personal) return { cipher: personal, access: null };

  const row = await db
    .prepare(`SELECT ${selectCipherColumns()} FROM ciphers WHERE id = ? AND organization_id IS NOT NULL`)
    .bind(id)
    .first<CipherRow>();
  if (!row) return null;
  const cipher = parseCipherRow(row);
  if (!cipher) return null;
  const access = await resolveCipherAccessForUser(db, id, userId);
  if (!access) return null;
  return { cipher, access };
}

interface OrgCipherRow extends CipherRow {
  ou_id: string;
  ou_access_all: number;
}

// All ciphers a user can see: personal ciphers plus accessible org ciphers.
// Org ciphers carry computed collectionIds/edit/viewPassword so cipherToResponse
// can surface per-member permission flags in sync/list responses.
export async function getAllCiphersIncludingOrgs(db: D1Database, userId: string): Promise<Cipher[]> {
  const personal = await getAllCiphers(db, userId);

  const orgResult = await db
    .prepare(
      `SELECT c.id, c.user_id, c.organization_id, c.type, c.folder_id, c.name, c.notes, c.favorite, c.data,
              c.reprompt, c.key, c.created_at, c.updated_at, c.archived_at, c.deleted_at,
              ou.id AS ou_id, ou.access_all AS ou_access_all
       FROM ciphers c
       JOIN organization_users ou
         ON ou.organization_id = c.organization_id AND ou.user_id = ? AND ou.status = ${ORG_USER_STATUS.CONFIRMED}
       WHERE c.organization_id IS NOT NULL
         AND (ou.access_all = 1 OR EXISTS (
           SELECT 1 FROM cipher_collections cc
           JOIN collection_users cu ON cu.collection_id = cc.collection_id AND cu.organization_user_id = ou.id
           WHERE cc.cipher_id = c.id
         ))
       ORDER BY c.updated_at DESC`
    )
    .bind(userId)
    .all<OrgCipherRow>();
  const orgRows = orgResult.results || [];
  if (!orgRows.length) return personal;

  const accessAllByCipher = new Map<string, string>();
  const limitedByOrgUser = new Map<string, string[]>();
  const orgCiphers: Cipher[] = [];
  for (const row of orgRows) {
    const cipher = parseCipherRow(row);
    if (!cipher) continue;
    orgCiphers.push(cipher);
    if (Number(row.ou_access_all)) {
      accessAllByCipher.set(row.id, row.ou_id);
    } else {
      const list = limitedByOrgUser.get(row.ou_id) || [];
      list.push(row.id);
      limitedByOrgUser.set(row.ou_id, list);
    }
  }

  const accessibleByCipher = new Map<string, Array<{ collectionId: string; readOnly: boolean; hidePasswords: boolean }>>();
  for (const [organizationUserId, cipherIds] of limitedByOrgUser.entries()) {
    for (let i = 0; i < cipherIds.length; i += ID_LIST_CHUNK_SIZE) {
      const chunk = cipherIds.slice(i, i + 90);
      const placeholders = chunk.map(() => '?').join(',');
      const result = await db
        .prepare(
          `SELECT cc.cipher_id, cc.collection_id, cu.read_only, cu.hide_passwords
           FROM cipher_collections cc
           JOIN collection_users cu ON cu.collection_id = cc.collection_id
           WHERE cu.organization_user_id = ? AND cc.cipher_id IN (${placeholders})`
        )
        .bind(organizationUserId, ...chunk)
        .all<{ cipher_id: string; collection_id: string; read_only: number; hide_passwords: number }>();
      for (const row of result.results || []) {
        const list = accessibleByCipher.get(row.cipher_id) || [];
        list.push({ collectionId: row.collection_id, readOnly: !!Number(row.read_only), hidePasswords: !!Number(row.hide_passwords) });
        accessibleByCipher.set(row.cipher_id, list);
      }
    }
  }

  const allCollectionIdsByCipher = await listCollectionIdsForCiphers(db, [...accessAllByCipher.keys()]);

  for (const cipher of orgCiphers) {
    if (accessAllByCipher.has(cipher.id)) {
      cipher.collectionIds = allCollectionIdsByCipher.get(cipher.id) || [];
      cipher.edit = true;
      cipher.viewPassword = true;
    } else {
      const rows = accessibleByCipher.get(cipher.id) || [];
      cipher.collectionIds = rows.map((row) => row.collectionId);
      cipher.edit = rows.some((row) => !row.readOnly);
      cipher.viewPassword = !rows.every((row) => row.hidePasswords);
    }
  }

  return [...personal, ...orgCiphers];
}

export async function listAccessibleCiphersByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  userId: string,
  ids: string[]
): Promise<AccessibleCipher[]> {
  if (!ids.length) return [];
  const out: AccessibleCipher[] = [];
  const chunkSize = sqlChunkSize(1);
  for (let i = 0; i < ids.length; i += chunkSize) {
    const chunk = ids.slice(i, i + chunkSize);
    const results = await Promise.all(chunk.map((id) => getAccessibleCipher(db, id, userId)));
    for (const result of results) {
      if (result) out.push(result);
    }
  }
  return out;
}

// --- By-id bulk mutations (organization ciphers) ---
// Callers must already have verified access; these operate purely by id so the
// user_id-scoped bulk helpers remain untouched for personal vault operations.

export async function softDeleteCiphersByIds(db: D1Database, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const now = new Date().toISOString();
  for (let i = 0; i < ids.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = ?, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders})`
      )
      .bind(now, now, ...chunk)
      .run();
  }
}

export async function restoreCiphersByIds(db: D1Database, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const now = new Date().toISOString();
  for (let i = 0; i < ids.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET deleted_at = NULL, updated_at = ?,
             data = json_remove(data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders})`
      )
      .bind(now, ...chunk)
      .run();
  }
}

export async function archiveCiphersByIds(db: D1Database, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const now = new Date().toISOString();
  for (let i = 0; i < ids.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = ?, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders})
           AND deleted_at IS NULL
           AND json_extract(data, '$.deletedAt') IS NULL
           AND json_extract(data, '$.deletedDate') IS NULL`
      )
      .bind(now, now, ...chunk)
      .run();
  }
}

export async function unarchiveCiphersByIds(db: D1Database, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const now = new Date().toISOString();
  for (let i = 0; i < ids.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    await db
      .prepare(
        `UPDATE ciphers
         SET archived_at = NULL, updated_at = ?,
             data = json_remove(data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')
         WHERE id IN (${placeholders})`
      )
      .bind(now, ...chunk)
      .run();
  }
}

export async function deleteCiphersByIds(db: D1Database, ids: string[]): Promise<void> {
  if (!ids.length) return;
  for (let i = 0; i < ids.length; i += ID_LIST_CHUNK_SIZE) {
    const chunk = ids.slice(i, i + 90);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM ciphers WHERE id IN (${placeholders})`).bind(...chunk).run();
  }
}

export async function listCipherIdsByOrganization(db: D1Database, organizationId: string): Promise<string[]> {
  const result = await db
    .prepare('SELECT id FROM ciphers WHERE organization_id = ?')
    .bind(organizationId)
    .all<{ id: string }>();
  return (result.results || []).map((row) => row.id);
}

// Move a personally-owned cipher into an organization. The user_id guard
// proves the caller still owns the row at write time; the transfer nulls the
// personal owner, sets the organization, and clears the personal folder (the
// saveCipher's upsert cannot express this because its conflict guard requires
// user_id equality.
export async function transferCipherToOrganization(
  db: D1Database,
  safeBind: SafeBind,
  cipher: Cipher,
  expectedUserId: string
): Promise<boolean> {
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const stmt = db.prepare(
    'UPDATE ciphers SET ' +
    'user_id = NULL, organization_id = ?, folder_id = NULL, type = ?, name = ?, notes = ?, favorite = ?, ' +
    'data = ?, reprompt = ?, key = ?, updated_at = ?, archived_at = ?, deleted_at = ? ' +
    'WHERE id = ? AND user_id = ?'
  );
  const result = await safeBind(
    stmt,
    normalizeOptionalId(cipher.organizationId),
    Number(cipher.type) || 1,
    cipher.name,
    cipher.notes,
    cipher.favorite ? 1 : 0,
    data,
    cipher.reprompt ?? 0,
    cipher.key,
    cipher.updatedAt,
    cipher.archivedAt ?? null,
    cipher.deletedAt,
    cipher.id,
    expectedUserId
  ).run();
  return (result.meta?.changes || 0) > 0;
}
