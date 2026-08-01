import type { AuthRequestRecord, AuthRequestType } from '../types';

const AUTH_REQUEST_EXPIRATION_MS = 15 * 60 * 1000;

function mapAuthRequestRow(row: any): AuthRequestRecord {
  return {
    id: row.id,
    userId: row.user_id,
    organizationId: row.organization_id ?? null,
    type: Number(row.type) as AuthRequestType,
    requestDeviceIdentifier: row.request_device_identifier,
    requestDeviceType: Number(row.request_device_type ?? 14),
    requestIpAddress: row.request_ip_address ?? null,
    requestCountryName: row.request_country_name ?? null,
    responseDeviceIdentifier: row.response_device_identifier ?? null,
    accessCode: row.access_code,
    publicKey: row.public_key,
    key: row.key ?? null,
    masterPasswordHash: row.master_password_hash ?? null,
    approved: row.approved == null ? null : Number(row.approved) === 1,
    creationDate: row.creation_date,
    responseDate: row.response_date ?? null,
    authenticationDate: row.authentication_date ?? null,
  };
}

export function isAuthRequestExpired(request: AuthRequestRecord, nowMs: number = Date.now()): boolean {
  return new Date(request.creationDate).getTime() + AUTH_REQUEST_EXPIRATION_MS <= nowMs;
}

const AUTH_REQUEST_SELECT =
  'SELECT id, user_id, organization_id, type, request_device_identifier, request_device_type, request_ip_address, request_country_name, ' +
  'response_device_identifier, access_code, public_key, key, master_password_hash, approved, creation_date, response_date, authentication_date ' +
  'FROM auth_requests';

export async function createAuthRequest(db: D1Database, request: AuthRequestRecord): Promise<void> {
  await db
    .prepare(
      'INSERT INTO auth_requests(' +
        'id, user_id, organization_id, type, request_device_identifier, request_device_type, request_ip_address, request_country_name, ' +
        'response_device_identifier, access_code, public_key, key, master_password_hash, approved, creation_date, response_date, authentication_date' +
        ') VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(
      request.id,
      request.userId,
      request.organizationId,
      request.type,
      request.requestDeviceIdentifier,
      request.requestDeviceType,
      request.requestIpAddress,
      request.requestCountryName,
      request.responseDeviceIdentifier,
      request.accessCode,
      request.publicKey,
      request.key,
      request.masterPasswordHash,
      request.approved == null ? null : (request.approved ? 1 : 0),
      request.creationDate,
      request.responseDate,
      request.authenticationDate
    )
    .run();
}

export async function getAuthRequestById(db: D1Database, id: string): Promise<AuthRequestRecord | null> {
  const row = await db.prepare(`${AUTH_REQUEST_SELECT} WHERE id = ? LIMIT 1`).bind(id).first<any>();
  return row ? mapAuthRequestRow(row) : null;
}

export async function getAuthRequestByIdForUser(db: D1Database, id: string, userId: string): Promise<AuthRequestRecord | null> {
  const row = await db.prepare(`${AUTH_REQUEST_SELECT} WHERE id = ? AND user_id = ? LIMIT 1`).bind(id, userId).first<any>();
  return row ? mapAuthRequestRow(row) : null;
}

export async function listAuthRequestsByUserId(db: D1Database, userId: string): Promise<AuthRequestRecord[]> {
  const res = await db.prepare(`${AUTH_REQUEST_SELECT} WHERE user_id = ? ORDER BY creation_date DESC`).bind(userId).all<any>();
  return (res.results || []).map(mapAuthRequestRow);
}

export async function listPendingAuthRequestsByUserId(db: D1Database, userId: string, nowMs: number = Date.now()): Promise<AuthRequestRecord[]> {
  const cutoff = new Date(nowMs - AUTH_REQUEST_EXPIRATION_MS).toISOString();
  const res = await db
    .prepare(
      'SELECT ar.id, ar.user_id, ar.organization_id, ar.type, ar.request_device_identifier, ar.request_device_type, ar.request_ip_address, ar.request_country_name, ' +
        'ar.response_device_identifier, ar.access_code, ar.public_key, ar.key, ar.master_password_hash, ar.approved, ar.creation_date, ar.response_date, ar.authentication_date ' +
        'FROM auth_requests ar ' +
        'JOIN (' +
        '  SELECT request_device_identifier, MAX(creation_date) AS latest_creation_date ' +
        '  FROM auth_requests ' +
        '  WHERE user_id = ? AND type IN (0, 1) AND approved IS NULL AND response_date IS NULL AND authentication_date IS NULL AND creation_date >= ? ' +
        '  GROUP BY request_device_identifier' +
        ') latest ON latest.request_device_identifier = ar.request_device_identifier AND latest.latest_creation_date = ar.creation_date ' +
        'WHERE ar.user_id = ? AND ar.type IN (0, 1) AND ar.approved IS NULL AND ar.response_date IS NULL AND ar.authentication_date IS NULL ' +
        'ORDER BY ar.creation_date DESC'
    )
    .bind(userId, cutoff, userId)
    .all<any>();
  return (res.results || []).map(mapAuthRequestRow).filter((request) => !isAuthRequestExpired(request, nowMs));
}

export async function updateAuthRequestResponse(
  db: D1Database,
  id: string,
  userId: string,
  update: {
    approved: boolean;
    responseDeviceIdentifier: string;
    key?: string | null;
    masterPasswordHash?: string | null;
    responseDate?: string;
  }
): Promise<boolean> {
  const result = await db
    .prepare(
      'UPDATE auth_requests SET approved = ?, response_device_identifier = ?, key = ?, master_password_hash = ?, response_date = ? ' +
        'WHERE id = ? AND user_id = ? AND approved IS NULL AND response_date IS NULL AND authentication_date IS NULL'
    )
    .bind(
      update.approved ? 1 : 0,
      update.responseDeviceIdentifier,
      update.approved ? (update.key ?? null) : null,
      update.approved ? (update.masterPasswordHash ?? null) : null,
      update.responseDate || new Date().toISOString(),
      id,
      userId
    )
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function markAuthRequestAuthenticated(db: D1Database, id: string, authenticationDate: string = new Date().toISOString()): Promise<boolean> {
  const result = await db
    .prepare('UPDATE auth_requests SET authentication_date = ? WHERE id = ? AND authentication_date IS NULL')
    .bind(authenticationDate, id)
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function pruneExpiredAuthRequests(db: D1Database, nowMs: number = Date.now()): Promise<number> {
  const cutoff = new Date(nowMs - AUTH_REQUEST_EXPIRATION_MS).toISOString();
  const result = await db.prepare('DELETE FROM auth_requests WHERE creation_date < ?').bind(cutoff).run();
  return Number(result.meta.changes ?? 0);
}
