import { and, eq, sql } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { account, users } from '../db/schema';
import { generateUUID } from '../utils/uuid';

// Copies the credential from the users row (at most one: id is its key) only while that row still holds
// this hash, and this stamp when given, so a lost update never installs a stale secret in Better Auth.
export function credentialAccountStatement(db: D1Database, userId: string, passwordHash: string, securityStamp?: string) {
  const now = Date.now();
  const orm = getOrm(db);
  return orm.insert(account).select(orm.select({
    id: sql`${generateUUID()}`.as('id'), accountId: users.id, providerId: sql`'credential'`.as('provider_id'), userId: users.id,
    password: users.masterPasswordHash, createdAt: sql`${now}`.as('created_at'), updatedAt: sql`${now}`.as('updated_at'),
  }).from(users).where(and(
    eq(users.id, userId), eq(users.masterPasswordHash, passwordHash),
    securityStamp === undefined ? undefined : eq(users.securityStamp, securityStamp),
  ))).onConflictDoUpdate({
    target: [account.providerId, account.accountId],
    set: { password: sql`excluded.password`, updatedAt: sql`excluded.updated_at` },
  });
}

export async function upsertCredentialAccount(db: D1Database, userId: string, passwordHash: string, securityStamp?: string): Promise<boolean> {
  const result = await credentialAccountStatement(db, userId, passwordHash, securityStamp);
  return (result.meta.changes ?? 0) > 0;
}
