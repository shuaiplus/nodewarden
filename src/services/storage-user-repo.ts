import { asc, count, eq, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { users } from '../db/schema';
import type { User } from '../types';

function mapUserRow(row: typeof users.$inferSelect): User {
  return {
    id: row.id,
    email: row.email,
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
    yubikeyKey1: row.yubikeyKey1,
    yubikeyKey2: row.yubikeyKey2,
    yubikeyKey3: row.yubikeyKey3,
    yubikeyKey4: row.yubikeyKey4,
    yubikeyKey5: row.yubikeyKey5,
    yubikeyNfc: !!row.yubikeyNfc,
    apiKey: row.apiKey,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function userValues(user: User) {
  return {
    id: user.id,
    email: user.email.toLowerCase(),
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

export async function saveUser(db: D1Database, user: User): Promise<void> {
  const values = userValues(user);
  await getOrm(db)
    .insert(users)
    .values(values)
    .onConflictDoUpdate({
      target: users.id,
      set: {
        email: values.email,
        name: values.name,
        masterPasswordHint: values.masterPasswordHint,
        masterPasswordHash: values.masterPasswordHash,
        key: values.key,
        privateKey: values.privateKey,
        publicKey: values.publicKey,
        kdfType: values.kdfType,
        kdfIterations: values.kdfIterations,
        kdfMemory: values.kdfMemory,
        kdfParallelism: values.kdfParallelism,
        securityStamp: values.securityStamp,
        role: values.role,
        status: values.status,
        verifyDevices: values.verifyDevices,
        totpSecret: values.totpSecret,
        totpRecoveryCode: values.totpRecoveryCode,
        yubikeyKey1: values.yubikeyKey1,
        yubikeyKey2: values.yubikeyKey2,
        yubikeyKey3: values.yubikeyKey3,
        yubikeyKey4: values.yubikeyKey4,
        yubikeyKey5: values.yubikeyKey5,
        yubikeyNfc: values.yubikeyNfc,
        apiKey: values.apiKey,
        updatedAt: values.updatedAt,
      },
    });
}

export async function createUser(db: D1Database, user: User): Promise<void> {
  await saveUser(db, user);
}

export async function createFirstUser(db: D1Database, user: User): Promise<boolean> {
  const values = userValues(user);
  const result = await getOrm(db).run(sql`
    INSERT INTO users (
      id, email, name, master_password_hint, master_password_hash, key, private_key, public_key,
      kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices,
      totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5,
      yubikey_nfc, api_key, created_at, updated_at
    )
    SELECT
      ${values.id}, ${values.email}, ${values.name}, ${values.masterPasswordHint}, ${values.masterPasswordHash},
      ${values.key}, ${values.privateKey}, ${values.publicKey}, ${values.kdfType}, ${values.kdfIterations},
      ${values.kdfMemory}, ${values.kdfParallelism}, ${values.securityStamp}, ${values.role}, ${values.status},
      ${values.verifyDevices}, ${values.totpSecret}, ${values.totpRecoveryCode}, ${values.yubikeyKey1},
      ${values.yubikeyKey2}, ${values.yubikeyKey3}, ${values.yubikeyKey4}, ${values.yubikeyKey5},
      ${values.yubikeyNfc}, ${values.apiKey}, ${values.createdAt}, ${values.updatedAt}
    WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)
  `);
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteUserById(db: D1Database, id: string): Promise<boolean> {
  const result = await getOrm(db).delete(users).where(eq(users.id, id)).run();
  return (result.meta.changes ?? 0) > 0;
}
