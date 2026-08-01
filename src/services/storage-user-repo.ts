import type { User } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;
const USER_SELECT_COLUMNS =
  'id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, ' +
  'kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, ' +
  'totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, api_key, created_at, updated_at';

function mapUserRow(row: any): User {
  return {
    id: row.id,
    email: row.email,
    name: row.name,
    masterPasswordHint: row.master_password_hint ?? null,
    masterPasswordHash: row.master_password_hash,
    key: row.key,
    privateKey: row.private_key,
    publicKey: row.public_key,
    kdfType: row.kdf_type,
    kdfIterations: row.kdf_iterations,
    kdfMemory: row.kdf_memory ?? undefined,
    kdfParallelism: row.kdf_parallelism ?? undefined,
    securityStamp: row.security_stamp,
    role: row.role === 'admin' ? 'admin' : 'user',
    status: row.status === 'banned' ? 'banned' : 'active',
    verifyDevices: row.verify_devices == null ? false : !!row.verify_devices,
    totpSecret: row.totp_secret ?? null,
    totpRecoveryCode: row.totp_recovery_code ?? null,
    yubikeyKey1: row.yubikey_key1 ?? null,
    yubikeyKey2: row.yubikey_key2 ?? null,
    yubikeyKey3: row.yubikey_key3 ?? null,
    yubikeyKey4: row.yubikey_key4 ?? null,
    yubikeyKey5: row.yubikey_key5 ?? null,
    yubikeyNfc: !!row.yubikey_nfc,
    apiKey: row.api_key ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getUser(db: D1Database, email: string): Promise<User | null> {
  const row = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users WHERE email = ?`)
    .bind(email.toLowerCase())
    .first<any>();
  if (!row) return null;
  return mapUserRow(row);
}

export async function getUserById(db: D1Database, id: string): Promise<User | null> {
  const row = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users WHERE id = ?`)
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapUserRow(row);
}

export async function getUserCount(db: D1Database): Promise<number> {
  const row = await db.prepare('SELECT COUNT(*) AS count FROM users').first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function getAllUsers(db: D1Database): Promise<User[]> {
  const res = await db
    .prepare(`SELECT ${USER_SELECT_COLUMNS} FROM users ORDER BY created_at ASC`)
    .all<any>();
  return (res.results || []).map((row) => mapUserRow(row));
}

export async function saveUser(db: D1Database, safeBind: SafeBind, user: User): Promise<void> {
  const email = user.email.toLowerCase();
  const stmt = db.prepare(
    'INSERT INTO users(id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, api_key, created_at, updated_at) ' +
    'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET ' +
    'email=excluded.email, name=excluded.name, master_password_hint=excluded.master_password_hint, master_password_hash=excluded.master_password_hash, key=excluded.key, private_key=excluded.private_key, public_key=excluded.public_key, ' +
    'kdf_type=excluded.kdf_type, kdf_iterations=excluded.kdf_iterations, kdf_memory=excluded.kdf_memory, kdf_parallelism=excluded.kdf_parallelism, security_stamp=excluded.security_stamp, role=excluded.role, status=excluded.status, verify_devices=excluded.verify_devices, totp_secret=excluded.totp_secret, totp_recovery_code=excluded.totp_recovery_code, yubikey_key1=excluded.yubikey_key1, yubikey_key2=excluded.yubikey_key2, yubikey_key3=excluded.yubikey_key3, yubikey_key4=excluded.yubikey_key4, yubikey_key5=excluded.yubikey_key5, yubikey_nfc=excluded.yubikey_nfc, api_key=excluded.api_key, updated_at=excluded.updated_at'
  );
  await safeBind(
    stmt,
    user.id,
    email,
    user.name,
    user.masterPasswordHint,
    user.masterPasswordHash,
    user.key,
    user.privateKey,
    user.publicKey,
    user.kdfType,
    user.kdfIterations,
    user.kdfMemory,
    user.kdfParallelism,
    user.securityStamp,
    user.role,
    user.status,
    user.verifyDevices ? 1 : 0,
    user.totpSecret,
    user.totpRecoveryCode,
    user.yubikeyKey1,
    user.yubikeyKey2,
    user.yubikeyKey3,
    user.yubikeyKey4,
    user.yubikeyKey5,
    user.yubikeyNfc ? 1 : 0,
    user.apiKey,
    user.createdAt,
    user.updatedAt
  ).run();
}

export async function createUser(db: D1Database, safeBind: SafeBind, user: User): Promise<void> {
  await saveUser(db, safeBind, user);
}

export async function createFirstUser(db: D1Database, safeBind: SafeBind, user: User): Promise<boolean> {
  const email = user.email.toLowerCase();
  const stmt = db.prepare(
    'INSERT INTO users(id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, api_key, created_at, updated_at) ' +
    'SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? ' +
    'WHERE NOT EXISTS (SELECT 1 FROM users LIMIT 1)'
  );
  const result = await safeBind(
    stmt,
    user.id,
    email,
    user.name,
    user.masterPasswordHint,
    user.masterPasswordHash,
    user.key,
    user.privateKey,
    user.publicKey,
    user.kdfType,
    user.kdfIterations,
    user.kdfMemory,
    user.kdfParallelism,
    user.securityStamp,
    user.role,
    user.status,
    user.verifyDevices ? 1 : 0,
    user.totpSecret,
    user.totpRecoveryCode,
    user.yubikeyKey1,
    user.yubikeyKey2,
    user.yubikeyKey3,
    user.yubikeyKey4,
    user.yubikeyKey5,
    user.yubikeyNfc ? 1 : 0,
    user.apiKey,
    user.createdAt,
    user.updatedAt
  ).run();

  return (result.meta.changes ?? 0) > 0;
}

export async function deleteUserById(db: D1Database, id: string): Promise<boolean> {
  const result = await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return (result.meta.changes ?? 0) > 0;
}
