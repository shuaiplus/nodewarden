import type { Device, TrustedDeviceTokenSummary, User } from '../types';
import { generateUUID } from '../utils/uuid';

type GetUserByEmail = (email: string) => Promise<User | null>;
type TrustedTokenKeyFn = (token: string) => Promise<string>;

function mapDeviceRow(row: any): Device {
  return {
    userId: row.user_id,
    deviceIdentifier: row.device_identifier,
    name: row.name,
    deviceNote: row.device_note ?? null,
    type: row.type,
    sessionStamp: row.session_stamp || '',
    encryptedUserKey: row.encrypted_user_key ?? null,
    encryptedPublicKey: row.encrypted_public_key ?? null,
    encryptedPrivateKey: row.encrypted_private_key ?? null,
    pushUuid: row.push_uuid ?? null,
    pushToken: row.push_token ?? null,
    lastSeenAt: row.last_seen_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
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
  await db
    .prepare(
      'INSERT INTO devices(user_id, device_identifier, name, type, session_stamp, encrypted_user_key, encrypted_public_key, encrypted_private_key, push_uuid, banned, banned_at, device_note, last_seen_at, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, ?, ?, ?) ' +
        'ON CONFLICT(user_id, device_identifier) DO UPDATE SET name=excluded.name, type=excluded.type, ' +
        'session_stamp=CASE WHEN devices.session_stamp IS NULL OR devices.session_stamp = ? THEN excluded.session_stamp ELSE devices.session_stamp END, ' +
        'encrypted_user_key=COALESCE(excluded.encrypted_user_key, encrypted_user_key), ' +
        'encrypted_public_key=COALESCE(excluded.encrypted_public_key, encrypted_public_key), ' +
        'encrypted_private_key=COALESCE(excluded.encrypted_private_key, encrypted_private_key), ' +
        'push_uuid=COALESCE(push_uuid, excluded.push_uuid), ' +
        'last_seen_at=excluded.last_seen_at, ' +
        'updated_at=excluded.updated_at'
    )
    .bind(
      userId,
      deviceIdentifier,
      effectiveName,
      type,
      effectiveSessionStamp,
      keys?.encryptedUserKey ?? null,
      keys?.encryptedPublicKey ?? null,
      keys?.encryptedPrivateKey ?? null,
      effectivePushUuid,
      existingDevice?.deviceNote ?? null,
      now,
      now,
      now,
      ''
    )
    .run();
}

export async function updateDeviceName(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  name: string
): Promise<boolean> {
  const result = await db
    .prepare('UPDATE devices SET device_note = ? WHERE user_id = ? AND device_identifier = ?')
    .bind(String(name || '').trim(), userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function touchDeviceLastSeen(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare('UPDATE devices SET last_seen_at = ? WHERE user_id = ? AND device_identifier = ?')
    .bind(now, userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function rotateDeviceSessionStamp(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  sessionStamp: string
): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare('UPDATE devices SET session_stamp = ?, updated_at = ? WHERE user_id = ? AND device_identifier = ?')
    .bind(sessionStamp, now, userId, deviceIdentifier)
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
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      'UPDATE devices SET encrypted_user_key = ?, encrypted_public_key = ?, encrypted_private_key = ?, updated_at = ? ' +
        'WHERE user_id = ? AND device_identifier = ?'
    )
    .bind(
      keys.encryptedUserKey ?? null,
      keys.encryptedPublicKey ?? null,
      keys.encryptedPrivateKey ?? null,
      now,
      userId,
      deviceIdentifier
    )
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

  const placeholders = uniqueIds.map(() => '?').join(',');
  const result = await db
    .prepare(
      `UPDATE devices
       SET encrypted_user_key = NULL,
           encrypted_public_key = NULL,
           encrypted_private_key = NULL,
           updated_at = ?
       WHERE user_id = ? AND device_identifier IN (${placeholders})`
    )
    .bind(new Date().toISOString(), userId, ...uniqueIds)
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function isKnownDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
    .bind(userId, deviceIdentifier)
    .first<{ '1': number }>();
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
  const res = await db
    .prepare(
      'SELECT user_id, device_identifier, name, type, session_stamp, encrypted_user_key, encrypted_public_key, encrypted_private_key, push_uuid, push_token, banned, banned_at, device_note, last_seen_at, created_at, updated_at ' +
        'FROM devices WHERE user_id = ? ORDER BY COALESCE(last_seen_at, created_at) DESC, updated_at DESC'
    )
    .bind(userId)
    .all<any>();
  return (res.results || []).map(mapDeviceRow);
}

export async function getDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<Device | null> {
  const row = await db
    .prepare(
      'SELECT user_id, device_identifier, name, type, session_stamp, encrypted_user_key, encrypted_public_key, encrypted_private_key, push_uuid, push_token, banned, banned_at, device_note, last_seen_at, created_at, updated_at ' +
        'FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1'
    )
    .bind(userId, deviceIdentifier)
    .first<any>();
  return row ? mapDeviceRow(row) : null;
}

export async function updateDevicePushToken(
  db: D1Database,
  userId: string,
  deviceIdentifier: string,
  pushUuid: string,
  pushToken: string
): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      'UPDATE devices SET push_uuid = ?, push_token = ?, updated_at = ? ' +
        'WHERE user_id = ? AND device_identifier = ?'
    )
    .bind(pushUuid, pushToken, now, userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function clearDevicePushToken(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<{ pushUuid: string | null } | null> {
  const existing = await db
    .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
    .bind(userId, deviceIdentifier)
    .first<{ push_uuid: string | null }>();
  if (!existing) return null;

  await db
    .prepare('UPDATE devices SET push_token = NULL, updated_at = ? WHERE user_id = ? AND device_identifier = ?')
    .bind(new Date().toISOString(), userId, deviceIdentifier)
    .run();

  return { pushUuid: existing.push_uuid ?? null };
}

export async function getDevicePushUuid(
  db: D1Database,
  userId: string,
  deviceIdentifier: string
): Promise<string | null> {
  const row = await db
    .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
    .bind(userId, deviceIdentifier)
    .first<{ push_uuid: string | null }>();
  return row?.push_uuid ?? null;
}

export async function userHasPushDevice(db: D1Database, userId: string): Promise<boolean> {
  const row = await db
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND push_token IS NOT NULL AND push_token <> ? LIMIT 1')
    .bind(userId, '')
    .first<{ '1': number }>();
  return !!row;
}

export async function deleteDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM devices WHERE user_id = ? AND device_identifier = ?')
    .bind(userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function deleteDevicesByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
  return Number(result.meta.changes ?? 0);
}

export async function getTrustedDeviceTokenSummariesByUserId(db: D1Database, userId: string): Promise<TrustedDeviceTokenSummary[]> {
  const now = Date.now();
  await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(now).run();

  const res = await db
    .prepare(
      'SELECT device_identifier, MAX(expires_at) AS expires_at, COUNT(*) AS token_count ' +
        'FROM trusted_two_factor_device_tokens WHERE user_id = ? GROUP BY device_identifier ORDER BY expires_at DESC'
    )
    .bind(userId)
    .all<any>();

  return (res.results || []).map((row) => ({
    deviceIdentifier: row.device_identifier,
    expiresAt: Number(row.expires_at || 0),
    tokenCount: Number(row.token_count || 0),
  }));
}

export async function deleteTrustedTwoFactorTokensByDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ? AND device_identifier = ?')
    .bind(userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteTrustedTwoFactorTokensByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ?')
    .bind(userId)
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
  await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(now).run();
  const result = await db
    .prepare('UPDATE trusted_two_factor_device_tokens SET expires_at = ? WHERE user_id = ? AND device_identifier = ? AND expires_at >= ?')
    .bind(expiresAtMs, userId, deviceIdentifier, now)
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
  await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE expires_at < ?').bind(Date.now()).run();
  await db
    .prepare(
      'INSERT INTO trusted_two_factor_device_tokens(token, user_id, device_identifier, expires_at) VALUES(?, ?, ?, ?) ' +
        'ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, device_identifier=excluded.device_identifier, expires_at=excluded.expires_at'
    )
    .bind(tokenKey, userId, deviceIdentifier, expiresAtMs)
    .run();
}

export async function getTrustedTwoFactorDeviceTokenUserId(
  db: D1Database,
  trustedTokenKey: TrustedTokenKeyFn,
  token: string,
  deviceIdentifier: string
): Promise<string | null> {
  const now = Date.now();
  const tokenKey = await trustedTokenKey(token);
  const row = await db
    .prepare('SELECT user_id, expires_at FROM trusted_two_factor_device_tokens WHERE token = ? AND device_identifier = ?')
    .bind(tokenKey, deviceIdentifier)
    .first<{ user_id: string; expires_at: number }>();

  if (!row) return null;
  if (row.expires_at && row.expires_at < now) {
    await db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE token = ?').bind(tokenKey).run();
    return null;
  }
  return row.user_id;
}
