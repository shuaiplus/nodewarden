import { eq, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { twoFactor } from '../db/schema';
import { generateUUID } from '../utils/uuid';

export function credentialAccountStatement(db: D1Database, userId: string, passwordHash: string, securityStamp?: string): D1PreparedStatement {
  const now = Date.now();
  return db.prepare(`INSERT INTO account (id, account_id, provider_id, user_id, password, created_at, updated_at)
    SELECT ?, ?, 'credential', ?, ?, ?, ?
    WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND master_password_hash = ?${securityStamp === undefined ? '' : ' AND security_stamp = ?'})
    ON CONFLICT(provider_id, account_id) DO UPDATE SET password = excluded.password, updated_at = excluded.updated_at`)
    .bind(generateUUID(), userId, userId, passwordHash, now, now, userId, passwordHash, ...(securityStamp === undefined ? [] : [securityStamp]));
}

export async function upsertCredentialAccount(db: D1Database, userId: string, passwordHash: string, securityStamp?: string): Promise<boolean> {
  const result = await credentialAccountStatement(db, userId, passwordHash, securityStamp).run();
  return (result.meta.changes ?? 0) > 0;
}

export async function upsertTwoFactorSecret(db: D1Database, userId: string, secret: string, backupCodes: string, securityStamp?: string): Promise<boolean> {
  // Match the canonical factor at the write boundary, after any intervening reset or replacement.
  const guard = securityStamp === undefined ? sql`1` : sql`EXISTS (
    SELECT 1 FROM users WHERE id = ${userId} AND security_stamp = ${securityStamp}
      AND totp_secret = ${secret} AND totp_recovery_code = ${backupCodes}
  )`;
  const result = await getOrm(db).insert(twoFactor).select(sql`
    SELECT ${generateUUID()}, ${secret}, ${backupCodes}, ${userId} WHERE ${guard}
  `).onConflictDoUpdate({ target: twoFactor.userId, set: { secret, backupCodes } }).run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteTwoFactorSecret(db: D1Database, userId: string): Promise<void> {
  await getOrm(db).delete(twoFactor).where(eq(twoFactor.userId, userId));
}
