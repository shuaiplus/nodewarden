export const EmergencyAccessType = {
  View: 0,
  Takeover: 1,
} as const;

export const EmergencyAccessStatus = {
  Invited: 0,
  Accepted: 1,
  Confirmed: 2,
  RecoveryInitiated: 3,
  RecoveryApproved: 4,
} as const;

export interface EmergencyAccessRecord {
  id: string;
  grantorId: string;
  granteeId: string | null;
  email: string | null;
  keyEncrypted: string | null;
  type: number;
  status: number;
  waitTimeDays: number;
  recoveryInitiatedAt: string | null;
  lastNotificationAt: string | null;
  createdAt: string;
  updatedAt: string;
}

interface EmergencyAccessRow {
  id: string;
  grantor_id: string;
  grantee_id: string | null;
  email: string | null;
  key_encrypted: string | null;
  type: number;
  status: number;
  wait_time_days: number;
  recovery_initiated_at: string | null;
  last_notification_at: string | null;
  created_at: string;
  updated_at: string;
}

function mapRow(row: EmergencyAccessRow): EmergencyAccessRecord {
  return {
    id: row.id,
    grantorId: row.grantor_id,
    granteeId: row.grantee_id,
    email: row.email,
    keyEncrypted: row.key_encrypted,
    type: row.type,
    status: row.status,
    waitTimeDays: row.wait_time_days,
    recoveryInitiatedAt: row.recovery_initiated_at,
    lastNotificationAt: row.last_notification_at,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

const SELECT = 'id, grantor_id, grantee_id, email, key_encrypted, type, status, wait_time_days, recovery_initiated_at, last_notification_at, created_at, updated_at';

export async function saveEmergencyAccess(db: D1Database, record: EmergencyAccessRecord): Promise<void> {
  await db.prepare(
    `INSERT INTO emergency_access (${SELECT}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(id) DO UPDATE SET
       grantor_id = excluded.grantor_id,
       grantee_id = excluded.grantee_id,
       email = excluded.email,
       key_encrypted = excluded.key_encrypted,
       type = excluded.type,
       status = excluded.status,
       wait_time_days = excluded.wait_time_days,
       recovery_initiated_at = excluded.recovery_initiated_at,
       last_notification_at = excluded.last_notification_at,
       updated_at = excluded.updated_at`
  ).bind(
    record.id,
    record.grantorId,
    record.granteeId,
    record.email,
    record.keyEncrypted,
    record.type,
    record.status,
    record.waitTimeDays,
    record.recoveryInitiatedAt,
    record.lastNotificationAt,
    record.createdAt,
    record.updatedAt
  ).run();
}

export async function getEmergencyAccess(db: D1Database, id: string): Promise<EmergencyAccessRecord | null> {
  const row = await db.prepare(`SELECT ${SELECT} FROM emergency_access WHERE id = ?`).bind(id).first<EmergencyAccessRow>();
  return row ? mapRow(row) : null;
}

export async function listByGrantor(db: D1Database, grantorId: string): Promise<EmergencyAccessRecord[]> {
  const res = await db.prepare(`SELECT ${SELECT} FROM emergency_access WHERE grantor_id = ? ORDER BY created_at DESC`).bind(grantorId).all<EmergencyAccessRow>();
  return (res.results || []).map(mapRow);
}

export async function listByGrantee(db: D1Database, granteeId: string): Promise<EmergencyAccessRecord[]> {
  const res = await db.prepare(`SELECT ${SELECT} FROM emergency_access WHERE grantee_id = ? ORDER BY created_at DESC`).bind(granteeId).all<EmergencyAccessRow>();
  return (res.results || []).map(mapRow);
}

export async function findInvite(db: D1Database, grantorId: string, email: string): Promise<EmergencyAccessRecord | null> {
  const row = await db.prepare(
    `SELECT ${SELECT} FROM emergency_access WHERE grantor_id = ? AND lower(email) = lower(?) LIMIT 1`
  ).bind(grantorId, email).first<EmergencyAccessRow>();
  return row ? mapRow(row) : null;
}

export async function deleteEmergencyAccess(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM emergency_access WHERE id = ?').bind(id).run();
}

export async function listRecoveryReady(db: D1Database, nowIso: string): Promise<EmergencyAccessRecord[]> {
  const res = await db.prepare(
    `SELECT ${SELECT} FROM emergency_access
     WHERE status = ? AND recovery_initiated_at IS NOT NULL`
  ).bind(EmergencyAccessStatus.RecoveryInitiated).all<EmergencyAccessRow>();
  return (res.results || []).map(mapRow).filter((record) => {
    if (!record.recoveryInitiatedAt) return false;
    const started = Date.parse(record.recoveryInitiatedAt);
    if (!Number.isFinite(started)) return false;
    return Date.parse(nowIso) - started >= record.waitTimeDays * 24 * 60 * 60 * 1000;
  });
}
