import { and, count, desc, eq, gte, inArray, isNotNull, lt, max, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { devices, trustedTwoFactorDeviceTokens } from '../db/schema';
import type { Device, TrustedDeviceTokenSummary, User } from '../types';
import { generateUUID } from '../utils/uuid';

type GetUserByEmail = (email: string) => Promise<User | null>;
type TrustedTokenKeyFn = (token: string) => Promise<string>;

function mapDeviceRow(row: typeof devices.$inferSelect): Device {
  return {
    userId: row.userId,
    deviceIdentifier: row.deviceIdentifier,
    name: row.name,
    deviceNote: row.deviceNote ?? null,
    type: row.type,
    sessionStamp: row.sessionStamp || '',
    encryptedUserKey: row.encryptedUserKey ?? null,
    encryptedPublicKey: row.encryptedPublicKey ?? null,
    encryptedPrivateKey: row.encryptedPrivateKey ?? null,
    pushUuid: row.pushUuid ?? null,
    pushToken: row.pushToken ?? null,
    lastSeenAt: row.lastSeenAt ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function deviceKey(userId: string, deviceIdentifier: string) {
  return and(eq(devices.userId, userId), eq(devices.deviceIdentifier, deviceIdentifier));
}

export async function upsertDevice(
  db: D1Database,
  getDeviceById: (userId: string, deviceIdentifier: string) => Promise<Device | null>,
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
  const existingDevice = await getDeviceById(userId, deviceIdentifier);
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
        sessionStamp: sql`CASE WHEN ${devices.sessionStamp} IS NULL OR ${devices.sessionStamp} = ${''} THEN excluded.session_stamp ELSE ${devices.sessionStamp} END`,
        encryptedUserKey: sql`coalesce(excluded.encrypted_user_key, ${devices.encryptedUserKey})`,
        encryptedPublicKey: sql`coalesce(excluded.encrypted_public_key, ${devices.encryptedPublicKey})`,
        encryptedPrivateKey: sql`coalesce(excluded.encrypted_private_key, ${devices.encryptedPrivateKey})`,
        pushUuid: sql`coalesce(${devices.pushUuid}, excluded.push_uuid)`,
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

  const result = await getOrm(db)
    .update(devices)
    .set({
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      updatedAt: new Date().toISOString(),
    })
    .where(and(eq(devices.userId, userId), inArray(devices.deviceIdentifier, uniqueIds)))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function isKnownDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<boolean> {
  const [row] = await getOrm(db)
    .select({ userId: devices.userId })
    .from(devices)
    .where(deviceKey(userId, deviceIdentifier))
    .limit(1);
  return !!row;
}

export async function isKnownDeviceByEmail(
  getUserByEmail: GetUserByEmail,
  isKnownDeviceForUser: (userId: string, deviceIdentifier: string) => Promise<boolean>,
  email: string,
  deviceIdentifier: string
): Promise<boolean> {
  const user = await getUserByEmail(email);
  if (!user) return false;
  return isKnownDeviceForUser(user.id, deviceIdentifier);
}

export async function getDevicesByUserId(db: D1Database, userId: string): Promise<Device[]> {
  const rows = await getOrm(db)
    .select()
    .from(devices)
    .where(eq(devices.userId, userId))
    .orderBy(sql`coalesce(${devices.lastSeenAt}, ${devices.createdAt}) desc`, desc(devices.updatedAt));
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

export async function clearDevicePushToken(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<{ pushUuid: string | null } | null> {
  const [existing] = await getOrm(db)
    .select({ pushUuid: devices.pushUuid })
    .from(devices)
    .where(deviceKey(userId, deviceIdentifier))
    .limit(1);
  if (!existing) return null;

  await getOrm(db)
    .update(devices)
    .set({ pushToken: null, updatedAt: new Date().toISOString() })
    .where(deviceKey(userId, deviceIdentifier));
  return { pushUuid: existing.pushUuid ?? null };
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
      sql`${devices.pushToken} <> ${''}`,
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
    .orderBy(desc(sql`max(${trustedTwoFactorDeviceTokens.expiresAt})`));

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
  trustedTokenKey: TrustedTokenKeyFn,
  token: string,
  userId: string,
  deviceIdentifier: string,
  expiresAtMs: number
): Promise<void> {
  const tokenKey = await trustedTokenKey(token);
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
  trustedTokenKey: TrustedTokenKeyFn,
  token: string,
  deviceIdentifier: string
): Promise<string | null> {
  const now = Date.now();
  const tokenKey = await trustedTokenKey(token);
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
