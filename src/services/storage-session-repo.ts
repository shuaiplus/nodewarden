import { and, eq, gte, isNotNull, isNull, lt, or } from 'drizzle-orm';
import { sha256 } from 'hono/utils/crypto';

import { getOrm } from '../db/client';
import { session } from '../db/schema';
import { caseWhen } from '../db/sql';
import type { RefreshTokenRecord } from '../types';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

let lastCleanupAt = 0;

async function maybeCleanupExpiredRefreshTokens(db: D1Database, nowMs: number): Promise<void> {
  if (!shouldRunPeriodicCleanup(lastCleanupAt, LIMITS.cleanup.refreshTokenCleanupIntervalMs)) return;
  await deleteExpiredRefreshTokens(db, nowMs);
  lastCleanupAt = nowMs;
}

// Tokens are stored as their SHA-256, so a database read never yields a usable credential.
export async function hashedTokenKey(token: string): Promise<string> {
  return `sha256:${await sha256(token)}`;
}

export async function saveRefreshToken(
  db: D1Database,
  token: string,
  userId: string,
  expiresAtMs?: number,
  deviceIdentifier?: string | null,
  deviceSessionStamp?: string | null,
  securityStamp?: string | null,
  clientType?: string | null,
  absoluteExpiresAtMs?: number | null
): Promise<void> {
  const now = Date.now();
  await maybeCleanupExpiredRefreshTokens(db, now);
  const tokenKey = await hashedTokenKey(token);
  const expiresAt = expiresAtMs ?? (now + LIMITS.auth.refreshTokenDefaultSlidingTtlMs);
  const absoluteExpiresAt = absoluteExpiresAtMs ?? (now + LIMITS.auth.refreshTokenAbsoluteTtlMs);
  await getOrm(db)
    .insert(session)
    .values({
      id: generateUUID(),
      token: tokenKey,
      userId,
      expiresAt,
      createdAt: now,
      updatedAt: now,
      deviceIdentifier: deviceIdentifier ?? null,
      deviceSessionStamp: deviceSessionStamp ?? null,
      securityStamp: securityStamp ?? null,
      clientType: clientType ?? null,
      absoluteExpiresAt,
      lastUsedAt: now,
    })
    .onConflictDoUpdate({
      target: session.token,
      set: {
        userId,
        expiresAt,
        updatedAt: now,
        deviceIdentifier: deviceIdentifier ?? null,
        deviceSessionStamp: deviceSessionStamp ?? null,
        securityStamp: securityStamp ?? null,
        clientType: clientType ?? null,
        lastUsedAt: now,
        absoluteExpiresAt,
      },
    });
}

export async function getRefreshTokenRecord(db: D1Database, token: string): Promise<RefreshTokenRecord | null> {
  const now = Date.now();
  await maybeCleanupExpiredRefreshTokens(db, now);
  const tokenKey = await hashedTokenKey(token);
  const [row] = await getOrm(db).select().from(session).where(eq(session.token, tokenKey)).limit(1);
  if (!row) return null;
  if ((row.expiresAt && row.expiresAt < now) || (row.absoluteExpiresAt && row.absoluteExpiresAt < now)) {
    await deleteRefreshToken(db, token);
    return null;
  }
  return row;
}

export async function getRefreshTokenUserId(db: D1Database, token: string): Promise<string | null> {
  return (await getRefreshTokenRecord(db, token))?.userId ?? null;
}

export async function extendRefreshTokenExpiry(db: D1Database, token: string, requestedExpiresAtMs: number, nowMs = Date.now()): Promise<boolean> {
  const tokenKey = await hashedTokenKey(token);
  const result = await getOrm(db)
    .update(session)
    .set({
      expiresAt: caseWhen(
        and(isNotNull(session.absoluteExpiresAt), lt(session.absoluteExpiresAt, requestedExpiresAtMs)),
        session.absoluteExpiresAt,
        requestedExpiresAtMs,
      ),
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
  token: string,
  securityStamp: string
): Promise<void> {
  const tokenKey = await hashedTokenKey(token);
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
  token: string,
  deviceSessionStamp: string
): Promise<void> {
  const tokenKey = await hashedTokenKey(token);
  await getOrm(db)
    .update(session)
    .set({ deviceSessionStamp, updatedAt: Date.now() })
    .where(and(
      eq(session.token, tokenKey),
      or(isNull(session.deviceSessionStamp), eq(session.deviceSessionStamp, '')),
    ));
}

export async function deleteRefreshToken(db: D1Database, token: string): Promise<void> {
  const tokenKey = await hashedTokenKey(token);
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
  await getOrm(db).delete(session).where(or(
    lt(session.expiresAt, nowMs),
    and(isNotNull(session.absoluteExpiresAt), lt(session.absoluteExpiresAt, nowMs)),
  ));
}
