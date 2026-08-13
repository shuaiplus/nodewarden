import { and, eq, gte, isNull, lt, or, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { refreshTokens } from '../db/schema';
import type { RefreshTokenRecord } from '../types';

type RefreshTokenKeyFn = (token: string) => Promise<string>;
type CleanupExpiredFn = (nowMs: number) => Promise<void>;

function mapRefreshToken(row: typeof refreshTokens.$inferSelect): RefreshTokenRecord {
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
    .insert(refreshTokens)
    .values({
      token: tokenKey,
      userId,
      expiresAt: expiresAtMs,
      deviceIdentifier: deviceIdentifier ?? null,
      deviceSessionStamp: deviceSessionStamp ?? null,
      securityStamp: securityStamp ?? null,
      createdAt: now,
      lastUsedAt: now,
      absoluteExpiresAt: absoluteExpiresAtMs ?? null,
      clientType: clientType ?? null,
    })
    .onConflictDoUpdate({
      target: refreshTokens.token,
      set: {
        userId,
        expiresAt: expiresAtMs,
        deviceIdentifier: deviceIdentifier ?? null,
        deviceSessionStamp: deviceSessionStamp ?? null,
        securityStamp: securityStamp ?? null,
        lastUsedAt: now,
        absoluteExpiresAt: absoluteExpiresAtMs ?? null,
        clientType: clientType ?? null,
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
  const [row] = await getOrm(db)
    .select()
    .from(refreshTokens)
    .where(eq(refreshTokens.token, tokenKey))
    .limit(1);

  if (!row) return null;
  if ((row.expiresAt && row.expiresAt < now) || (row.absoluteExpiresAt && row.absoluteExpiresAt < now)) {
    await deleteRefreshTokenRecord(token);
    return null;
  }
  return mapRefreshToken(row);
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
    .update(refreshTokens)
    .set({
      expiresAt: sql`CASE
        WHEN ${refreshTokens.absoluteExpiresAt} IS NOT NULL AND ${refreshTokens.absoluteExpiresAt} < ${requestedExpiresAtMs}
        THEN ${refreshTokens.absoluteExpiresAt}
        ELSE ${requestedExpiresAtMs} END`,
      lastUsedAt: nowMs,
    })
    .where(and(
      eq(refreshTokens.token, tokenKey),
      gte(refreshTokens.expiresAt, nowMs),
      or(isNull(refreshTokens.absoluteExpiresAt), gte(refreshTokens.absoluteExpiresAt, nowMs)),
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
    .update(refreshTokens)
    .set({ securityStamp })
    .where(and(
      eq(refreshTokens.token, tokenKey),
      or(isNull(refreshTokens.securityStamp), eq(refreshTokens.securityStamp, '')),
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
    .update(refreshTokens)
    .set({ deviceSessionStamp })
    .where(and(
      eq(refreshTokens.token, tokenKey),
      or(isNull(refreshTokens.deviceSessionStamp), eq(refreshTokens.deviceSessionStamp, '')),
    ));
}

export async function deleteRefreshToken(db: D1Database, refreshTokenKey: RefreshTokenKeyFn, token: string): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  const orm = getOrm(db);
  await orm.delete(refreshTokens).where(eq(refreshTokens.token, token));
  await orm.delete(refreshTokens).where(eq(refreshTokens.token, tokenKey));
}

export async function deleteRefreshTokensByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await getOrm(db).delete(refreshTokens).where(eq(refreshTokens.userId, userId)).run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteRefreshTokensByDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<number> {
  const result = await getOrm(db)
    .delete(refreshTokens)
    .where(and(eq(refreshTokens.userId, userId), eq(refreshTokens.deviceIdentifier, deviceIdentifier)))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteExpiredRefreshTokens(db: D1Database, nowMs: number): Promise<void> {
  await getOrm(db).delete(refreshTokens).where(lt(refreshTokens.expiresAt, nowMs));
}
