import { and, count, desc, eq, gte, inArray, isNotNull, isNull, lt, max, ne, or } from 'drizzle-orm';

import { getOrm, statementChunks } from '../db/client';
import { devices, trustedTwoFactorDeviceTokens } from '../db/schema';
import { caseWhen, coalesce, excluded } from '../db/sql';
import type { Device, TrustedDeviceTokenSummary } from '../types';
import { generateUUID } from '../utils/uuid';
import { hashedTokenKey } from './storage-session-repo';
import { getUser } from './storage-user-repo';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;

// Rows predating device session stamps carry null; callers compare the stamp as a string.
function mapDeviceRow(row: typeof devices.$inferSelect): Device {
  return { ...row, sessionStamp: row.sessionStamp ?? '' };
}

function deviceKey(userId: string, deviceIdentifier: string) {
  return and(eq(devices.userId, userId), eq(devices.deviceIdentifier, deviceIdentifier));
}

export async function upsertDevice(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  name: string,
  type: number,
  sessionStamp?: string,
  keys?: {
    encryptedUserKey?: string | null;
    encryptedPublicKey?: string | null;
    encryptedPrivateKey?: string | null;
  }
): Promise<void> {
  const now = new Date().toISOString();
  const existingDevice = await getDevice(db, userId, deviceIdentifier);
  const effectiveSessionStamp = String(sessionStamp || '').trim() || existingDevice?.sessionStamp || '';
  const effectiveName = String(name || '').trim() || String(existingDevice?.name || '').trim();
  const effectivePushUuid = String(existingDevice?.pushUuid || '').trim() || generateUUID();
  await getOrm(db)
    .insert(devices)
    .values({
      userId,
      deviceIdentifier,
      name: effectiveName,
      type,
      sessionStamp: effectiveSessionStamp,
      encryptedUserKey: keys?.encryptedUserKey ?? null,
      encryptedPublicKey: keys?.encryptedPublicKey ?? null,
      encryptedPrivateKey: keys?.encryptedPrivateKey ?? null,
      pushUuid: effectivePushUuid,
      banned: 0,
      bannedAt: null,
      deviceNote: existingDevice?.deviceNote ?? null,
      lastSeenAt: now,
      createdAt: now,
      updatedAt: now,
    })
    .onConflictDoUpdate({
      target: [devices.userId, devices.deviceIdentifier],
      set: {
        name: effectiveName,
        type,
        sessionStamp: caseWhen(or(isNull(devices.sessionStamp), eq(devices.sessionStamp, '')), excluded(devices.sessionStamp), devices.sessionStamp),
        encryptedUserKey: coalesce(excluded(devices.encryptedUserKey), devices.encryptedUserKey),
        encryptedPublicKey: coalesce(excluded(devices.encryptedPublicKey), devices.encryptedPublicKey),
        encryptedPrivateKey: coalesce(excluded(devices.encryptedPrivateKey), devices.encryptedPrivateKey),
        pushUuid: coalesce(devices.pushUuid, excluded(devices.pushUuid)),
        lastSeenAt: now,
        updatedAt: now,
      },
    });
}

export async function updateDeviceName(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  name: string
): Promise<boolean> {
  const result = await getOrm(db)
    .update(devices)
    .set({ deviceNote: String(name || '').trim() })
    .where(deviceKey(userId, deviceIdentifier))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function touchDeviceLastSeen(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<boolean> {
  const result = await getOrm(db)
    .update(devices)
    .set({ lastSeenAt: new Date().toISOString() })
    .where(deviceKey(userId, deviceIdentifier))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function rotateDeviceSessionStamp(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  sessionStamp: string
): Promise<boolean> {
  const result = await getOrm(db)
    .update(devices)
    .set({ sessionStamp, updatedAt: new Date().toISOString() })
    .where(deviceKey(userId, deviceIdentifier))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function updateDeviceKeys(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  keys: {
    encryptedUserKey?: string | null;
    encryptedPublicKey?: string | null;
    encryptedPrivateKey?: string | null;
  }
): Promise<boolean> {
  const result = await getOrm(db)
    .update(devices)
    .set({
      encryptedUserKey: keys.encryptedUserKey ?? null,
      encryptedPublicKey: keys.encryptedPublicKey ?? null,
      encryptedPrivateKey: keys.encryptedPrivateKey ?? null,
      updatedAt: new Date().toISOString(),
    })
    .where(deviceKey(userId, deviceIdentifier))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function clearDeviceKeys(
  db: D1Database,
  userId: string,
  deviceIdentifiers: string[]
): Promise<number> {
  const uniqueIds = Array.from(
    new Set(deviceIdentifiers.map((id) => String(id || '').trim()).filter(Boolean))
  );
  if (!uniqueIds.length) return 0;

  const orm = getOrm(db);
  const updatedAt = new Date().toISOString();
  const clear = (chunk: string[]) => orm
    .update(devices)
    .set({ encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null, updatedAt })
    .where(and(eq(devices.userId, userId), inArray(devices.deviceIdentifier, chunk)));
  const statements = statementChunks(uniqueIds, clear).map(clear);
  const results = await orm.batch(statements as [typeof statements[0], ...typeof statements]);
  return results.reduce((total, result) => total + Number(result.meta.changes ?? 0), 0);
}

export async function isKnownDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<boolean> {
  const [row] = await getOrm(db)
    .select({ userId: devices.userId })
    .from(devices)
    .where(deviceKey(userId, deviceIdentifier))
    .limit(1);
  return !!row;
}

export async function isKnownDeviceByEmail(db: D1Database, email: string, deviceIdentifier: string): Promise<boolean> {
  const user = await getUser(db, email);
  if (!user) return false;
  return isKnownDevice(db, user.id, deviceIdentifier);
}

export async function getDevicesByUserId(db: D1Database, userId: string): Promise<Device[]> {
  const rows = await getOrm(db)
    .select()
    .from(devices)
    .where(eq(devices.userId, userId))
    .orderBy(desc(coalesce(devices.lastSeenAt, devices.createdAt)), desc(devices.updatedAt));
  return rows.map(mapDeviceRow);
}

export async function getDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<Device | null> {
  const [row] = await getOrm(db)
    .select()
    .from(devices)
    .where(deviceKey(userId, deviceIdentifier))
    .limit(1);
  return row ? mapDeviceRow(row) : null;
}

export async function updateDevicePushToken(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  pushUuid: string,
  pushToken: string
): Promise<boolean> {
  const result = await getOrm(db)
    .update(devices)
    .set({ pushUuid, pushToken, updatedAt: new Date().toISOString() })
    .where(deviceKey(userId, deviceIdentifier))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function getDevicePushUuid(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<string | null> {
  const [row] = await getOrm(db)
    .select({ pushUuid: devices.pushUuid })
    .from(devices)
    .where(deviceKey(userId, deviceIdentifier))
    .limit(1);
  return row?.pushUuid ?? null;
}

export async function userHasPushDevice(db: D1Database, userId: string): Promise<boolean> {
  const [row] = await getOrm(db)
    .select({ userId: devices.userId })
    .from(devices)
    .where(and(
      eq(devices.userId, userId),
      isNotNull(devices.pushToken),
      ne(devices.pushToken, ''),
    ))
    .limit(1);
  return !!row;
}

export async function deleteDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<boolean> {
  const result = await getOrm(db).delete(devices).where(deviceKey(userId, deviceIdentifier)).run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function deleteDevicesByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await getOrm(db).delete(devices).where(eq(devices.userId, userId)).run();
  return Number(result.meta.changes ?? 0);
}

async function deleteExpiredTrustedTokens(db: D1Database, nowMs: number): Promise<void> {
  await getOrm(db).delete(trustedTwoFactorDeviceTokens).where(lt(trustedTwoFactorDeviceTokens.expiresAt, nowMs));
}

export async function getTrustedDeviceTokenSummariesByUserId(db: D1Database, userId: string): Promise<TrustedDeviceTokenSummary[]> {
  const now = Date.now();
  await deleteExpiredTrustedTokens(db, now);
  const rows = await getOrm(db)
    .select({
      deviceIdentifier: trustedTwoFactorDeviceTokens.deviceIdentifier,
      expiresAt: max(trustedTwoFactorDeviceTokens.expiresAt),
      tokenCount: count(),
    })
    .from(trustedTwoFactorDeviceTokens)
    .where(eq(trustedTwoFactorDeviceTokens.userId, userId))
    .groupBy(trustedTwoFactorDeviceTokens.deviceIdentifier)
    .orderBy(desc(max(trustedTwoFactorDeviceTokens.expiresAt)));

  return rows.map((row) => ({
    deviceIdentifier: row.deviceIdentifier,
    expiresAt: Number(row.expiresAt || 0),
    tokenCount: Number(row.tokenCount || 0),
  }));
}

export async function deleteTrustedTwoFactorTokensByDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<number> {
  const result = await getOrm(db)
    .delete(trustedTwoFactorDeviceTokens)
    .where(and(
      eq(trustedTwoFactorDeviceTokens.userId, userId),
      eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
    ))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteTrustedTwoFactorTokensByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await getOrm(db)
    .delete(trustedTwoFactorDeviceTokens)
    .where(eq(trustedTwoFactorDeviceTokens.userId, userId))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function updateTrustedTwoFactorTokensExpiryByDevice(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  expiresAtMs: number
): Promise<number> {
  const now = Date.now();
  await deleteExpiredTrustedTokens(db, now);
  const result = await getOrm(db)
    .update(trustedTwoFactorDeviceTokens)
    .set({ expiresAt: expiresAtMs })
    .where(and(
      eq(trustedTwoFactorDeviceTokens.userId, userId),
      eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
      gte(trustedTwoFactorDeviceTokens.expiresAt, now),
    ))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function saveTrustedTwoFactorDeviceToken(
  db: D1Database,
  token: string,
  userId: string,
  deviceIdentifier: string,
  expiresAtMs = Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
): Promise<void> {
  const tokenKey = await hashedTokenKey(token);
  await deleteExpiredTrustedTokens(db, Date.now());
  await getOrm(db)
    .insert(trustedTwoFactorDeviceTokens)
    .values({ token: tokenKey, userId, deviceIdentifier, expiresAt: expiresAtMs })
    .onConflictDoUpdate({
      target: trustedTwoFactorDeviceTokens.token,
      set: { userId, deviceIdentifier, expiresAt: expiresAtMs },
    });
}

export async function getTrustedTwoFactorDeviceTokenUserId(
  db: D1Database,
  token: string,
  deviceIdentifier: string
): Promise<string | null> {
  const now = Date.now();
  const tokenKey = await hashedTokenKey(token);
  const [row] = await getOrm(db)
    .select({
      userId: trustedTwoFactorDeviceTokens.userId,
      expiresAt: trustedTwoFactorDeviceTokens.expiresAt,
    })
    .from(trustedTwoFactorDeviceTokens)
    .where(and(
      eq(trustedTwoFactorDeviceTokens.token, tokenKey),
      eq(trustedTwoFactorDeviceTokens.deviceIdentifier, deviceIdentifier),
    ))
    .limit(1);

  if (!row) return null;
  if (row.expiresAt && row.expiresAt < now) {
    await getOrm(db).delete(trustedTwoFactorDeviceTokens).where(eq(trustedTwoFactorDeviceTokens.token, tokenKey));
    return null;
  }
  return row.userId;
}
