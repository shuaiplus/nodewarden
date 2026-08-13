import { and, eq, gte, isNull, lt, or, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { session } from '../db/schema';
import type { RefreshTokenRecord } from '../types';
import { generateUUID } from '../utils/uuid';

type RefreshTokenKeyFn = (token: string) => Promise<string>;
type CleanupExpiredFn = (nowMs: number) => Promise<void>;

function mapSession(row: typeof session.$inferSelect): RefreshTokenRecord {
  return {
    userId: row.userId,
    expiresAt: row.expiresAt,
    deviceIdentifier: row.deviceIdentifier ?? null,
    deviceSessionStamp: row.deviceSessionStamp ?? null,
    securityStamp: row.securityStamp ?? null,
    createdAt: row.createdAt ?? null,
    lastUsedAt: row.lastUsedAt ?? null,
    absoluteExpiresAt: row.absoluteExpiresAt ?? null,
    clientType: row.clientType ?? null,
  };
}

export async function saveRefreshToken(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  maybeCleanupExpiredRefreshTokens: CleanupExpiredFn,
  token: string,
  userId: string,
  expiresAtMs: number,
  deviceIdentifier?: string | null,
  deviceSessionStamp?: string | null,
  securityStamp?: string | null,
  clientType?: string | null,
  absoluteExpiresAtMs?: number | null
): Promise<void> {
  await maybeCleanupExpiredRefreshTokens(Date.now());
  const tokenKey = await refreshTokenKey(token);
  const now = Date.now();
  await getOrm(db)
    .insert(session)
    .values({
      id: generateUUID(),
      token: tokenKey,
      userId,
      expiresAt: expiresAtMs,
      createdAt: now,
      updatedAt: now,
      deviceIdentifier: deviceIdentifier ?? null,
      deviceSessionStamp: deviceSessionStamp ?? null,
      securityStamp: securityStamp ?? null,
      clientType: clientType ?? null,
      absoluteExpiresAt: absoluteExpiresAtMs ?? null,
      lastUsedAt: now,
    })
    .onConflictDoUpdate({
      target: session.token,
      set: {
        userId,
        expiresAt: expiresAtMs,
        updatedAt: now,
        deviceIdentifier: deviceIdentifier ?? null,
        deviceSessionStamp: deviceSessionStamp ?? null,
        securityStamp: securityStamp ?? null,
        clientType: clientType ?? null,
        lastUsedAt: now,
        absoluteExpiresAt: absoluteExpiresAtMs ?? null,
      },
    });
}

export async function getRefreshTokenRecord(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  maybeCleanupExpiredRefreshTokens: CleanupExpiredFn,
  deleteRefreshTokenRecord: (token: string) => Promise<void>,
  token: string
): Promise<RefreshTokenRecord | null> {
  const now = Date.now();
  await maybeCleanupExpiredRefreshTokens(now);
  const tokenKey = await refreshTokenKey(token);
  const [row] = await getOrm(db).select().from(session).where(eq(session.token, tokenKey)).limit(1);
  if (!row) return null;
  if ((row.expiresAt && row.expiresAt < now) || (row.absoluteExpiresAt && row.absoluteExpiresAt < now)) {
    await deleteRefreshTokenRecord(token);
    return null;
  }
  return mapSession(row);
}

export async function extendRefreshTokenExpiry(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  token: string,
  requestedExpiresAtMs: number,
  nowMs: number
): Promise<boolean> {
  const tokenKey = await refreshTokenKey(token);
  const result = await getOrm(db)
    .update(session)
    .set({
      expiresAt: sql`CASE
        WHEN ${session.absoluteExpiresAt} IS NOT NULL AND ${session.absoluteExpiresAt} < ${requestedExpiresAtMs}
        THEN ${session.absoluteExpiresAt}
        ELSE ${requestedExpiresAtMs} END`,
      lastUsedAt: nowMs,
      updatedAt: nowMs,
    })
    .where(and(
      eq(session.token, tokenKey),
      gte(session.expiresAt, nowMs),
      or(isNull(session.absoluteExpiresAt), gte(session.absoluteExpiresAt, nowMs)),
    ))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function bindRefreshTokenSecurityStamp(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  token: string,
  securityStamp: string
): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  await getOrm(db)
    .update(session)
    .set({ securityStamp, updatedAt: Date.now() })
    .where(and(
      eq(session.token, tokenKey),
      or(isNull(session.securityStamp), eq(session.securityStamp, '')),
    ));
}

export async function bindRefreshTokenDeviceStamp(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  token: string,
  deviceSessionStamp: string
): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  await getOrm(db)
    .update(session)
    .set({ deviceSessionStamp, updatedAt: Date.now() })
    .where(and(
      eq(session.token, tokenKey),
      or(isNull(session.deviceSessionStamp), eq(session.deviceSessionStamp, '')),
    ));
}

export async function deleteRefreshToken(db: D1Database, refreshTokenKey: RefreshTokenKeyFn, token: string): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  const orm = getOrm(db);
  await orm.delete(session).where(eq(session.token, token));
  await orm.delete(session).where(eq(session.token, tokenKey));
}

export async function deleteRefreshTokensByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await getOrm(db).delete(session).where(eq(session.userId, userId)).run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteRefreshTokensByDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<number> {
  const result = await getOrm(db)
    .delete(session)
    .where(and(eq(session.userId, userId), eq(session.deviceIdentifier, deviceIdentifier)))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteExpiredRefreshTokens(db: D1Database, nowMs: number): Promise<void> {
  await getOrm(db).delete(session).where(lt(session.expiresAt, nowMs));
}
