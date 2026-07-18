import type { Send } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

function mapSendRow(row: any): Send {
  return {
    id: row.id,
    userId: row.user_id,
    type: row.type,
    name: row.name,
    notes: row.notes,
    data: row.data,
    key: row.key,
    passwordHash: row.password_hash,
    passwordSalt: row.password_salt,
    passwordIterations: row.password_iterations,
    authType: row.auth_type ?? 0,
    emails: row.emails ?? null,
    maxAccessCount: row.max_access_count,
    accessCount: row.access_count,
    disabled: !!row.disabled,
    hideEmail: row.hide_email === null || row.hide_email === undefined ? null : !!row.hide_email,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    expirationDate: row.expiration_date,
    deletionDate: row.deletion_date,
  };
}

export async function getSend(db: D1Database, id: string): Promise<Send | null> {
  const row = await db
    .prepare(
      'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE id = ?'
    )
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapSendRow(row);
}

export async function getSendForUser(db: D1Database, id: string, userId: string): Promise<Send | null> {
  const row = await db
    .prepare(
      'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE id = ? AND user_id = ?'
    )
    .bind(id, userId)
    .first<any>();
  if (!row) return null;
  return mapSendRow(row);
}

export async function saveSend(db: D1Database, safeBind: SafeBind, send: Send): Promise<void> {
  const stmt = db.prepare(
    'INSERT INTO sends(id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'type=excluded.type, name=excluded.name, notes=excluded.notes, data=excluded.data, key=excluded.key, ' +
    'password_hash=excluded.password_hash, password_salt=excluded.password_salt, password_iterations=excluded.password_iterations, auth_type=excluded.auth_type, emails=excluded.emails, ' +
    'max_access_count=excluded.max_access_count, access_count=excluded.access_count, disabled=excluded.disabled, hide_email=excluded.hide_email, ' +
    'updated_at=excluded.updated_at, expiration_date=excluded.expiration_date, deletion_date=excluded.deletion_date ' +
    'WHERE user_id=excluded.user_id'
  );

  await safeBind(
    stmt,
    send.id,
    send.userId,
    Number(send.type) || 0,
    send.name,
    send.notes,
    send.data,
    send.key,
    send.passwordHash,
    send.passwordSalt,
    send.passwordIterations,
    send.authType,
    send.emails,
    send.maxAccessCount,
    send.accessCount,
    send.disabled ? 1 : 0,
    send.hideEmail === null || send.hideEmail === undefined ? null : send.hideEmail ? 1 : 0,
    send.createdAt,
    send.updatedAt,
    send.expirationDate,
    send.deletionDate
  ).run();
}

export async function incrementSendAccessCount(db: D1Database, sendId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      'UPDATE sends SET access_count = access_count + 1, updated_at = ? ' +
      'WHERE id = ? ' +
      'AND disabled = 0 ' +
      'AND (max_access_count IS NULL OR access_count < max_access_count) ' +
      'AND (expiration_date IS NULL OR expiration_date > ?) ' +
      'AND deletion_date > ?'
    )
    .bind(now, sendId, now, now)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteSend(db: D1Database, id: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM sends WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

export async function getSendsByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Send[]> {
  if (ids.length === 0) return [];
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return [];
  const chunkSize = sqlChunkSize(1);
  const out: Send[] = [];

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    const res = await db
      .prepare(
        `SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date
         FROM sends
         WHERE user_id = ? AND id IN (${placeholders})`
      )
      .bind(userId, ...chunk)
      .all<any>();
    out.push(...(res.results || []).map((row) => mapSendRow(row)));
  }

  return out;
}

export async function bulkDeleteSends(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  if (ids.length === 0) return null;
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;
  const chunkSize = sqlChunkSize(1);

  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    const placeholders = chunk.map(() => '?').join(',');
    await db.prepare(`DELETE FROM sends WHERE user_id = ? AND id IN (${placeholders})`).bind(userId, ...chunk).run();
  }

  return updateRevisionDate(userId);
}

export async function getAllSends(db: D1Database, userId: string): Promise<Send[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE user_id = ? ORDER BY updated_at DESC'
    )
    .bind(userId)
    .all<any>();
  return (res.results || []).map((row) => mapSendRow(row));
}

export async function getSendsPage(db: D1Database, userId: string, limit: number, offset: number): Promise<Send[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, type, name, notes, data, key, password_hash, password_salt, password_iterations, auth_type, emails, max_access_count, access_count, disabled, hide_email, created_at, updated_at, expiration_date, deletion_date FROM sends WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?'
    )
    .bind(userId, limit, offset)
    .all<any>();
  return (res.results || []).map((row) => mapSendRow(row));
}
