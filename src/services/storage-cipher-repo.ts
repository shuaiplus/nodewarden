import type { Cipher } from '../types';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

interface CipherRow {
  id: string;
  user_id: string;
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
      userId: row.user_id,
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
  return 'id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at';
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
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const stmt = db.prepare(
    'INSERT INTO ciphers(id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'type=excluded.type, folder_id=excluded.folder_id, name=excluded.name, notes=excluded.notes, favorite=excluded.favorite, data=excluded.data, reprompt=excluded.reprompt, key=excluded.key, updated_at=excluded.updated_at, archived_at=excluded.archived_at, deleted_at=excluded.deleted_at ' +
    'WHERE user_id=excluded.user_id'
  );
  await safeBind(
    stmt,
    cipher.id,
    cipher.userId,
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
