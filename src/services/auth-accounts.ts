import { and, eq } from 'drizzle-orm';

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

export async function upsertTwoFactorSecret(db: D1Database, userId: string, secret: string, backupCodes: string): Promise<void> {
  const orm = getOrm(db);
  const [existing] = await orm.select({ id: twoFactor.id }).from(twoFactor).where(eq(twoFactor.userId, userId)).limit(1);
  if (existing) {
    await orm.update(twoFactor).set({ secret, backupCodes }).where(eq(twoFactor.id, existing.id));
    return;
  }
  await orm.insert(twoFactor).values({
    id: generateUUID(),
    userId,
    secret,
    backupCodes,
  });
}

export async function deleteTwoFactorSecret(db: D1Database, userId: string): Promise<void> {
  await getOrm(db).delete(twoFactor).where(eq(twoFactor.userId, userId));
}
