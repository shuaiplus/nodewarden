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
