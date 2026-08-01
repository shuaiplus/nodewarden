import type { RefreshTokenRecord } from '../types';

type RefreshTokenKeyFn = (token: string) => Promise<string>;
type CleanupExpiredFn = (nowMs: number) => Promise<void>;

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
  await db
    .prepare(
      'INSERT INTO refresh_tokens(token, user_id, expires_at, device_identifier, device_session_stamp, security_stamp, created_at, last_used_at, absolute_expires_at, client_type) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(token) DO UPDATE SET user_id=excluded.user_id, expires_at=excluded.expires_at, device_identifier=excluded.device_identifier, ' +
        'device_session_stamp=excluded.device_session_stamp, security_stamp=excluded.security_stamp, last_used_at=excluded.last_used_at, ' +
        'absolute_expires_at=excluded.absolute_expires_at, client_type=excluded.client_type'
    )
    .bind(
      tokenKey,
      userId,
      expiresAtMs,
      deviceIdentifier ?? null,
      deviceSessionStamp ?? null,
      securityStamp ?? null,
      now,
      now,
      absoluteExpiresAtMs ?? null,
      clientType ?? null
    )
    .run();
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

  const row = await db
    .prepare(
      'SELECT user_id, expires_at, device_identifier, device_session_stamp, security_stamp, created_at, last_used_at, absolute_expires_at, client_type ' +
        'FROM refresh_tokens WHERE token = ?'
    )
    .bind(tokenKey)
    .first<{
      user_id: string;
      expires_at: number;
      device_identifier: string | null;
      device_session_stamp: string | null;
      security_stamp: string | null;
      created_at: number | null;
      last_used_at: number | null;
      absolute_expires_at: number | null;
      client_type: string | null;
    }>();

  if (!row) return null;
  if ((row.expires_at && row.expires_at < now) || (row.absolute_expires_at && row.absolute_expires_at < now)) {
    await deleteRefreshTokenRecord(token);
    return null;
  }
  return {
    userId: row.user_id,
    expiresAt: row.expires_at,
    deviceIdentifier: row.device_identifier ?? null,
    deviceSessionStamp: row.device_session_stamp ?? null,
    securityStamp: row.security_stamp ?? null,
    createdAt: row.created_at ?? null,
    lastUsedAt: row.last_used_at ?? null,
    absoluteExpiresAt: row.absolute_expires_at ?? null,
    clientType: row.client_type ?? null,
  };
}

export async function extendRefreshTokenExpiry(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  token: string,
  requestedExpiresAtMs: number,
  nowMs: number
): Promise<boolean> {
  const tokenKey = await refreshTokenKey(token);
  const result = await db
    .prepare(
      'UPDATE refresh_tokens SET ' +
        'expires_at = CASE ' +
        'WHEN absolute_expires_at IS NOT NULL AND absolute_expires_at < ? THEN absolute_expires_at ' +
        'ELSE ? END, ' +
        'last_used_at = ? ' +
        'WHERE token = ? AND expires_at >= ? AND (absolute_expires_at IS NULL OR absolute_expires_at >= ?)'
    )
    .bind(requestedExpiresAtMs, requestedExpiresAtMs, nowMs, tokenKey, nowMs, nowMs)
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
  await db
    .prepare('UPDATE refresh_tokens SET security_stamp = ? WHERE token = ? AND (security_stamp IS NULL OR security_stamp = ?)')
    .bind(securityStamp, tokenKey, '')
    .run();
}

export async function bindRefreshTokenDeviceStamp(
  db: D1Database,
  refreshTokenKey: RefreshTokenKeyFn,
  token: string,
  deviceSessionStamp: string
): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  await db
    .prepare('UPDATE refresh_tokens SET device_session_stamp = ? WHERE token = ? AND (device_session_stamp IS NULL OR device_session_stamp = ?)')
    .bind(deviceSessionStamp, tokenKey, '')
    .run();
}

export async function deleteRefreshToken(db: D1Database, refreshTokenKey: RefreshTokenKeyFn, token: string): Promise<void> {
  const tokenKey = await refreshTokenKey(token);
  await db.prepare('DELETE FROM refresh_tokens WHERE token = ?').bind(token).run();
  await db.prepare('DELETE FROM refresh_tokens WHERE token = ?').bind(tokenKey).run();
}

export async function deleteRefreshTokensByUserId(db: D1Database, userId: string): Promise<number> {
  const result = await db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').bind(userId).run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteRefreshTokensByDevice(db: D1Database, userId: string, deviceIdentifier: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM refresh_tokens WHERE user_id = ? AND device_identifier = ?')
    .bind(userId, deviceIdentifier)
    .run();
  return Number(result.meta.changes ?? 0);
}
