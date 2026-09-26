import { and, asc, count, eq, isNull, sql } from 'drizzle-orm';

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

export async function createFirstUser(db: D1Database, user: User): Promise<boolean> {
  const values = userValues(user);
  const result = await getOrm(db).run(sql`
    INSERT INTO users (
      id, email, email_verified, name, master_password_hint, master_password_hash, key, private_key, public_key,
      kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices,
      totp_secret, totp_recovery_code, two_factor_email, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5,
      yubikey_nfc, api_key, created_at, updated_at
    )
    SELECT
      ${values.id}, ${values.email}, ${values.emailVerified}, ${values.name}, ${values.masterPasswordHint}, ${values.masterPasswordHash},
      ${values.key}, ${values.privateKey}, ${values.publicKey}, ${values.kdfType}, ${values.kdfIterations},
      ${values.kdfMemory}, ${values.kdfParallelism}, ${values.securityStamp}, ${values.role}, ${values.status},
      ${values.verifyDevices}, ${values.totpSecret}, ${values.totpRecoveryCode}, ${values.twoFactorEmail}, ${values.yubikeyKey1},
      ${values.yubikeyKey2}, ${values.yubikeyKey3}, ${values.yubikeyKey4}, ${values.yubikeyKey5},
      ${values.yubikeyNfc}, ${values.apiKey}, ${values.createdAt}, ${values.updatedAt}
    WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)
  `);
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
