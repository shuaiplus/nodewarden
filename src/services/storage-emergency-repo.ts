import { and, desc, eq, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { emergencyAccess } from '../db/schema';

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

function mapRow(row: typeof emergencyAccess.$inferSelect): EmergencyAccessRecord {
  return {
    id: row.id,
    grantorId: row.grantorId,
    granteeId: row.granteeId,
    email: row.email,
    keyEncrypted: row.keyEncrypted,
    type: row.type,
    status: row.status,
    waitTimeDays: row.waitTimeDays,
    recoveryInitiatedAt: row.recoveryInitiatedAt,
    lastNotificationAt: row.lastNotificationAt,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export async function saveEmergencyAccess(db: D1Database, record: EmergencyAccessRecord): Promise<void> {
  await getOrm(db)
    .insert(emergencyAccess)
    .values(record)
    .onConflictDoUpdate({
      target: emergencyAccess.id,
      set: {
        grantorId: record.grantorId,
        granteeId: record.granteeId,
        email: record.email,
        keyEncrypted: record.keyEncrypted,
        type: record.type,
        status: record.status,
        waitTimeDays: record.waitTimeDays,
        recoveryInitiatedAt: record.recoveryInitiatedAt,
        lastNotificationAt: record.lastNotificationAt,
        updatedAt: record.updatedAt,
      },
    });
}

export async function getEmergencyAccess(db: D1Database, id: string): Promise<EmergencyAccessRecord | null> {
  const [row] = await getOrm(db).select().from(emergencyAccess).where(eq(emergencyAccess.id, id)).limit(1);
  return row ? mapRow(row) : null;
}

export async function listByGrantor(db: D1Database, grantorId: string): Promise<EmergencyAccessRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(emergencyAccess)
    .where(eq(emergencyAccess.grantorId, grantorId))
    .orderBy(desc(emergencyAccess.createdAt));
  return rows.map(mapRow);
}

export async function listByGrantee(db: D1Database, granteeId: string): Promise<EmergencyAccessRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(emergencyAccess)
    .where(eq(emergencyAccess.granteeId, granteeId))
    .orderBy(desc(emergencyAccess.createdAt));
  return rows.map(mapRow);
}

export async function findInvite(db: D1Database, grantorId: string, email: string): Promise<EmergencyAccessRecord | null> {
  const [row] = await getOrm(db)
    .select()
    .from(emergencyAccess)
    .where(and(
      eq(emergencyAccess.grantorId, grantorId),
      sql`lower(${emergencyAccess.email}) = lower(${email})`,
    ))
    .limit(1);
  return row ? mapRow(row) : null;
}

export async function deleteEmergencyAccess(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(emergencyAccess).where(eq(emergencyAccess.id, id));
}

export async function listRecoveryReady(db: D1Database, nowIso: string): Promise<EmergencyAccessRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(emergencyAccess)
    .where(and(
      eq(emergencyAccess.status, EmergencyAccessStatus.RecoveryInitiated),
      sql`${emergencyAccess.recoveryInitiatedAt} is not null`,
    ));
  return rows.map(mapRow).filter((record) => {
    if (!record.recoveryInitiatedAt) return false;
    const started = Date.parse(record.recoveryInitiatedAt);
    if (!Number.isFinite(started)) return false;
    return Date.parse(nowIso) - started >= record.waitTimeDays * 24 * 60 * 60 * 1000;
  });
}
