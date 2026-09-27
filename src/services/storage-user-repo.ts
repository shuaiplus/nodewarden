import { and, asc, count, eq, isNull, notExists, sql, type SQL } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { users } from '../db/schema';
import type { User } from '../types';
import { twoFactorProviders } from './two-factor-providers';

function mapUserRow(row: typeof users.$inferSelect): User {
  return {
    id: row.id,
    email: row.email,
    emailVerified: !!row.emailVerified,
    name: row.name,
    masterPasswordHint: row.masterPasswordHint,
    masterPasswordHash: row.masterPasswordHash,
    key: row.key,
    privateKey: row.privateKey,
    publicKey: row.publicKey,
    kdfType: row.kdfType,
    kdfIterations: row.kdfIterations,
    kdfMemory: row.kdfMemory ?? undefined,
    kdfParallelism: row.kdfParallelism ?? undefined,
    securityStamp: row.securityStamp,
    role: row.role === 'admin' ? 'admin' : 'user',
    status: row.status === 'banned' ? 'banned' : 'active',
    verifyDevices: !!row.verifyDevices,
    totpSecret: row.totpSecret,
    totpRecoveryCode: row.totpRecoveryCode,
    twoFactorEmail: row.twoFactorEmail,
    yubikeyKey1: row.yubikeyKey1,
    yubikeyKey2: row.yubikeyKey2,
    yubikeyKey3: row.yubikeyKey3,
    yubikeyKey4: row.yubikeyKey4,
    yubikeyKey5: row.yubikeyKey5,
    yubikeyNfc: !!row.yubikeyNfc,
    apiKey: row.apiKey,
    userKeyId: row.userKeyId,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function userValues(user: User) {
  return {
    id: user.id,
    email: user.email.toLowerCase(),
    emailVerified: user.emailVerified ? 1 : 0,
    name: user.name,
    masterPasswordHint: user.masterPasswordHint,
    masterPasswordHash: user.masterPasswordHash,
    key: user.key,
    privateKey: user.privateKey,
    publicKey: user.publicKey,
    kdfType: user.kdfType,
    kdfIterations: user.kdfIterations,
    kdfMemory: user.kdfMemory ?? null,
    kdfParallelism: user.kdfParallelism ?? null,
    securityStamp: user.securityStamp,
    role: user.role,
    status: user.status,
    verifyDevices: user.verifyDevices ? 1 : 0,
    totpSecret: user.totpSecret,
    totpRecoveryCode: user.totpRecoveryCode,
    twoFactorEmail: user.twoFactorEmail,
    yubikeyKey1: user.yubikeyKey1,
    yubikeyKey2: user.yubikeyKey2,
    yubikeyKey3: user.yubikeyKey3,
    yubikeyKey4: user.yubikeyKey4,
    yubikeyKey5: user.yubikeyKey5,
    yubikeyNfc: user.yubikeyNfc ? 1 : 0,
    apiKey: user.apiKey,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}

export async function getUser(db: D1Database, email: string): Promise<User | null> {
  const [row] = await getOrm(db).select().from(users).where(eq(users.email, email.toLowerCase())).limit(1);
  return row ? mapUserRow(row) : null;
}

export async function getUserById(db: D1Database, id: string): Promise<User | null> {
  const [row] = await getOrm(db).select().from(users).where(eq(users.id, id)).limit(1);
  return row ? mapUserRow(row) : null;
}

export async function getUserCount(db: D1Database): Promise<number> {
  const [row] = await getOrm(db).select({ count: count() }).from(users);
  return Number(row?.count || 0);
}

export async function getAllUsers(db: D1Database): Promise<User[]> {
  const rows = await getOrm(db).select().from(users).orderBy(asc(users.createdAt));
  return rows.map(mapUserRow);
}

export async function getAllUsersWithTwoFactor(db: D1Database): Promise<Array<User & { hasTwoFactorPasskey: boolean }>> {
  const rows = await getOrm(db).select({
    user: users,
    hasTwoFactorPasskey: sql<number>`EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id = users.id AND w.purpose = 'twoFactor')`.mapWith(Boolean),
  }).from(users).orderBy(asc(users.createdAt));
  return rows.map(({ user, hasTwoFactorPasskey }) => ({ ...mapUserRow(user), hasTwoFactorPasskey }));
}

export type UserUpdateField = Exclude<keyof ReturnType<typeof userValues>,
  'id' | 'email' | 'emailVerified' | 'role' | 'status' | 'createdAt' | 'updatedAt' | 'twoFactorEmail' | 'totpRecoveryCode'>;

// Snapshot saves update only the intended fields and can never recreate a deleted account.
export async function saveUser(db: D1Database, user: User, fields: readonly UserUpdateField[] = ['name', 'masterPasswordHint'], originalSecurityStamp = user.securityStamp): Promise<boolean> {
  const values = userValues(user);
  const result = await getOrm(db).update(users)
    .set({ ...Object.fromEntries(fields.map(field => [field, values[field]])), updatedAt: new Date().toISOString() })
    .where(and(eq(users.id, user.id), eq(users.securityStamp, originalSecurityStamp))).run();
  return (result.meta.changes ?? 0) > 0;
}

export async function createUser(db: D1Database, user: User): Promise<void> {
  await getOrm(db).insert(users).values(userValues(user));
}

// One INSERT ... SELECT guarded by NOT EXISTS, so two concurrent first registrations cannot both
// create the first (administrator) account.
export async function createFirstUser(db: D1Database, user: User): Promise<boolean> {
  const orm = getOrm(db);
  const values = userValues(user);
  const literals = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, sql`${value}`.as(key)])) as { [K in keyof typeof values]: SQL.Aliased };
  const result = await orm.insert(users)
    .select(orm.select(literals).from(sql`(SELECT 1)`).where(notExists(orm.select({ id: users.id }).from(users).limit(1))))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

// One conditional UPDATE, so two devices backfilling at once cannot overwrite each other: the
// first write wins and the caller reports the rest as already set.
export async function setUserKeyIdIfUnset(db: D1Database, userId: string, userKeyId: string): Promise<boolean> {
  const result = await getOrm(db)
    .update(users)
    .set({ userKeyId, updatedAt: new Date().toISOString() })
    .where(and(eq(users.id, userId), isNull(users.userKeyId)))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteUserById(db: D1Database, id: string): Promise<boolean> {
  const result = await getOrm(db).delete(users).where(eq(users.id, id)).run();
  return (result.meta.changes ?? 0) > 0;
}

export async function searchUsersByEmailPrefix(db: D1Database, prefix: string, offset: number, limit: number) {
  const pattern = prefix.replace(/[\\%_]/g, (value) => `\\${value}`) + '%';
  const rows = await getOrm(db).select({
    user: { id: users.id, email: users.email, name: users.name, createdAt: users.createdAt, status: users.status, role: users.role },
    providers: {
      totpSecret: users.totpSecret, twoFactorEmail: users.twoFactorEmail, yubikeyKey1: users.yubikeyKey1, yubikeyKey2: users.yubikeyKey2,
      yubikeyKey3: users.yubikeyKey3, yubikeyKey4: users.yubikeyKey4, yubikeyKey5: users.yubikeyKey5,
    },
    hasTwoFactorPasskey: sql<number>`EXISTS (SELECT 1 FROM webauthn_credentials w WHERE w.user_id=users.id AND w.purpose='twoFactor')`.mapWith(Boolean),
  }).from(users).where(sql`${users.email} LIKE ${pattern} ESCAPE '\\'`).orderBy(asc(users.email)).limit(limit + 1).offset(offset);
  return rows.map(({ user, providers, hasTwoFactorPasskey }) => ({ ...user, twoFactor: twoFactorProviders(providers, hasTwoFactorPasskey).length > 0 }));
}
