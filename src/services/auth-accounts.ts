import { and, eq, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { account, twoFactor } from '../db/schema';
import { generateUUID } from '../utils/uuid';

export async function upsertCredentialAccount(db: D1Database, userId: string, passwordHash: string): Promise<void> {
  const now = Date.now();
  const orm = getOrm(db);
  const [existing] = await orm
    .select({ id: account.id })
    .from(account)
    .where(and(eq(account.userId, userId), eq(account.providerId, 'credential')))
    .limit(1);
  if (existing) {
    await orm.update(account).set({ password: passwordHash, updatedAt: now }).where(eq(account.id, existing.id));
    return;
  }
  await orm.insert(account).values({
    id: generateUUID(),
    accountId: userId,
    providerId: 'credential',
    userId,
    password: passwordHash,
    createdAt: now,
    updatedAt: now,
  });
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
