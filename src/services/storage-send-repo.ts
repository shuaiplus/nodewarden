import { and, desc, eq, gt, inArray, isNull, or, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { sends } from '../db/schema';
import type { Send } from '../types';

type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

function mapSendRow(row: typeof sends.$inferSelect): Send {
  return {
    id: row.id,
    userId: row.userId,
    type: row.type,
    name: row.name,
    notes: row.notes,
    data: row.data,
    key: row.key,
    passwordHash: row.passwordHash,
    passwordSalt: row.passwordSalt,
    passwordIterations: row.passwordIterations,
    authType: row.authType ?? 0,
    emails: row.emails ?? null,
    maxAccessCount: row.maxAccessCount,
    accessCount: row.accessCount,
    disabled: !!row.disabled,
    hideEmail: row.hideEmail === null || row.hideEmail === undefined ? null : !!row.hideEmail,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    expirationDate: row.expirationDate,
    deletionDate: row.deletionDate,
  };
}

function sendValues(send: Send) {
  return {
    id: send.id,
    userId: send.userId,
    type: Number(send.type) || 0,
    name: send.name,
    notes: send.notes,
    data: send.data,
    key: send.key,
    passwordHash: send.passwordHash,
    passwordSalt: send.passwordSalt,
    passwordIterations: send.passwordIterations,
    authType: send.authType,
    emails: send.emails,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    disabled: send.disabled ? 1 : 0,
    hideEmail: send.hideEmail === null || send.hideEmail === undefined ? null : send.hideEmail ? 1 : 0,
    createdAt: send.createdAt,
    updatedAt: send.updatedAt,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
  };
}

export async function getSend(db: D1Database, id: string): Promise<Send | null> {
  const [row] = await getOrm(db).select().from(sends).where(eq(sends.id, id)).limit(1);
  return row ? mapSendRow(row) : null;
}

export async function getSendForUser(db: D1Database, id: string, userId: string): Promise<Send | null> {
  const [row] = await getOrm(db)
    .select()
    .from(sends)
    .where(and(eq(sends.id, id), eq(sends.userId, userId)))
    .limit(1);
  return row ? mapSendRow(row) : null;
}

export async function saveSend(db: D1Database, send: Send): Promise<void> {
  const values = sendValues(send);
  await getOrm(db)
    .insert(sends)
    .values(values)
    .onConflictDoUpdate({
      target: sends.id,
      set: {
        type: values.type,
        name: values.name,
        notes: values.notes,
        data: values.data,
        key: values.key,
        passwordHash: values.passwordHash,
        passwordSalt: values.passwordSalt,
        passwordIterations: values.passwordIterations,
        authType: values.authType,
        emails: values.emails,
        maxAccessCount: values.maxAccessCount,
        accessCount: values.accessCount,
        disabled: values.disabled,
        hideEmail: values.hideEmail,
        updatedAt: values.updatedAt,
        expirationDate: values.expirationDate,
        deletionDate: values.deletionDate,
      },
      where: eq(sends.userId, send.userId),
    });
}

export async function incrementSendAccessCount(db: D1Database, sendId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await getOrm(db)
    .update(sends)
    .set({
      accessCount: sql`${sends.accessCount} + 1`,
      updatedAt: now,
    })
    .where(and(
      eq(sends.id, sendId),
      eq(sends.disabled, 0),
      or(isNull(sends.maxAccessCount), sql`${sends.accessCount} < ${sends.maxAccessCount}`),
      or(isNull(sends.expirationDate), gt(sends.expirationDate, now)),
      gt(sends.deletionDate, now),
    ))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteSend(db: D1Database, id: string, userId: string): Promise<void> {
  await getOrm(db).delete(sends).where(and(eq(sends.id, id), eq(sends.userId, userId)));
}

export async function getSendsByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Send[]> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return [];
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(1);
  const out: Send[] = [];

  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
    const rows = await orm
      .select()
      .from(sends)
      .where(and(eq(sends.userId, userId), inArray(sends.id, chunk)));
    out.push(...rows.map(mapSendRow));
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
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(1);

  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
    await orm.delete(sends).where(and(eq(sends.userId, userId), inArray(sends.id, chunk)));
  }

  return updateRevisionDate(userId);
}

export async function getAllSends(db: D1Database, userId: string): Promise<Send[]> {
  const rows = await getOrm(db)
    .select()
    .from(sends)
    .where(eq(sends.userId, userId))
    .orderBy(desc(sends.updatedAt));
  return rows.map(mapSendRow);
}

export async function getSendsPage(db: D1Database, userId: string, limit: number, offset: number): Promise<Send[]> {
  const rows = await getOrm(db)
    .select()
    .from(sends)
    .where(eq(sends.userId, userId))
    .orderBy(desc(sends.updatedAt))
    .limit(limit)
    .offset(offset);
  return rows.map(mapSendRow);
}
