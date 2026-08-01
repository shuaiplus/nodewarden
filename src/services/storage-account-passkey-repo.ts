import type { AccountPasskeyChallenge, AccountPasskeyChallengeScope, AccountPasskeyCredential } from '../types';

type SafeBindFn = (stmt: D1PreparedStatement, ...values: any[]) => D1PreparedStatement;

let accountPasskeySchemaReady = false;

const ACCOUNT_PASSKEY_CREDENTIAL_COLUMN_DEFS = [
  { name: 'id', sql: 'id TEXT' },
  { name: 'user_id', sql: "user_id TEXT NOT NULL DEFAULT ''" },
  { name: 'purpose', sql: "purpose TEXT NOT NULL DEFAULT 'login'" },
  { name: 'name', sql: "name TEXT NOT NULL DEFAULT 'Account passkey'" },
  { name: 'public_key', sql: "public_key TEXT NOT NULL DEFAULT ''" },
  { name: 'credential_id', sql: "credential_id TEXT NOT NULL DEFAULT ''" },
  { name: 'counter', sql: 'counter INTEGER NOT NULL DEFAULT 0' },
  { name: 'type', sql: 'type TEXT' },
  { name: 'aa_guid', sql: 'aa_guid TEXT' },
  { name: 'transports', sql: 'transports TEXT' },
  { name: 'encrypted_user_key', sql: 'encrypted_user_key TEXT' },
  { name: 'encrypted_public_key', sql: 'encrypted_public_key TEXT' },
  { name: 'encrypted_private_key', sql: 'encrypted_private_key TEXT' },
  { name: 'supports_prf', sql: 'supports_prf INTEGER NOT NULL DEFAULT 0' },
  { name: 'created_at', sql: "created_at TEXT NOT NULL DEFAULT ''" },
  { name: 'updated_at', sql: "updated_at TEXT NOT NULL DEFAULT ''" },
] as const;

const ACCOUNT_PASSKEY_CHALLENGE_COLUMNS = [
  'challenge_hash',
  'scope',
  'user_id',
  'expires_at',
  'used_at',
  'created_at',
] as const;

async function tableColumns(db: D1Database, tableName: 'webauthn_credentials' | 'webauthn_challenges'): Promise<Set<string>> {
  const result = await db.prepare(`PRAGMA table_info(${tableName})`).all<{ name: string }>();
  return new Set((result.results || []).map((row) => String(row.name || '').trim()).filter(Boolean));
}

async function ensureAccountPasskeySchema(db: D1Database): Promise<void> {
  if (accountPasskeySchemaReady) return;

  await db
    .prepare(
      'CREATE TABLE IF NOT EXISTS webauthn_credentials (' +
        "id TEXT PRIMARY KEY, user_id TEXT NOT NULL, purpose TEXT NOT NULL DEFAULT 'login', name TEXT NOT NULL, public_key TEXT NOT NULL, credential_id TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, " +
        'type TEXT, aa_guid TEXT, transports TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, supports_prf INTEGER NOT NULL DEFAULT 0, ' +
        'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
        'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)'
    )
    .run();
  let credentialColumns = await tableColumns(db, 'webauthn_credentials');
  for (const column of ACCOUNT_PASSKEY_CREDENTIAL_COLUMN_DEFS) {
    if (!credentialColumns.has(column.name)) {
      await db.prepare(`ALTER TABLE webauthn_credentials ADD COLUMN ${column.sql}`).run();
    }
  }
  credentialColumns = await tableColumns(db, 'webauthn_credentials');
  if (!credentialColumns.has('credential_id')) {
    throw new Error('webauthn_credentials schema is missing credential_id');
  }
  await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_id ON webauthn_credentials(id)').run();
  await db.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_updated ON webauthn_credentials(user_id, updated_at)').run();

  await db
    .prepare(
      'CREATE TABLE IF NOT EXISTS webauthn_challenges (' +
        'challenge_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, user_id TEXT, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)'
    )
    .run();
  const challengeColumns = await tableColumns(db, 'webauthn_challenges');
  const challengeSchemaComplete = ACCOUNT_PASSKEY_CHALLENGE_COLUMNS.every((column) => challengeColumns.has(column));
  if (!challengeSchemaComplete) {
    await db.prepare('DROP TABLE IF EXISTS webauthn_challenges').run();
    await db
      .prepare(
        'CREATE TABLE webauthn_challenges (' +
          'challenge_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, user_id TEXT, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)'
      )
      .run();
  }
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_scope ON webauthn_challenges(user_id, scope)').run();

  accountPasskeySchemaReady = true;
}

function parseTransports(value: string | null): string[] | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return null;
    return parsed.map((item) => String(item || '').trim()).filter(Boolean);
  } catch {
    return null;
  }
}

function mapCredentialRow(row: {
  id: string;
  user_id: string;
  purpose?: string | null;
  name: string;
  public_key: string;
  credential_id: string;
  counter: number;
  type: string | null;
  aa_guid: string | null;
  transports: string | null;
  encrypted_user_key: string | null;
  encrypted_public_key: string | null;
  encrypted_private_key: string | null;
  supports_prf: number;
  created_at: string;
  updated_at: string;
}): AccountPasskeyCredential {
  return {
    id: row.id,
    userId: row.user_id,
    purpose: row.purpose === 'twoFactor' ? 'twoFactor' : 'login',
    name: row.name,
    publicKey: row.public_key,
    credentialId: row.credential_id,
    counter: Number(row.counter || 0),
    type: row.type ?? null,
    aaGuid: row.aa_guid ?? null,
    transports: parseTransports(row.transports),
    encryptedUserKey: row.encrypted_user_key ?? null,
    encryptedPublicKey: row.encrypted_public_key ?? null,
    encryptedPrivateKey: row.encrypted_private_key ?? null,
    supportsPrf: !!row.supports_prf,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function mapChallengeRow(row: {
  challenge_hash: string;
  scope: AccountPasskeyChallengeScope;
  user_id: string | null;
  expires_at: number;
  used_at: number | null;
  created_at: number;
}): AccountPasskeyChallenge {
  return {
    challengeHash: row.challenge_hash,
    scope: row.scope,
    userId: row.user_id ?? null,
    expiresAt: Number(row.expires_at || 0),
    usedAt: row.used_at == null ? null : Number(row.used_at),
    createdAt: Number(row.created_at || 0),
  };
}

export async function saveAccountPasskeyCredential(
  db: D1Database,
  safeBind: SafeBindFn,
  credential: AccountPasskeyCredential
): Promise<void> {
  await ensureAccountPasskeySchema(db);
  await safeBind(
    db.prepare(
      'INSERT INTO webauthn_credentials(' +
        'id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, ' +
        'encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at' +
        ') VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(id) DO UPDATE SET ' +
        'purpose=excluded.purpose, name=excluded.name, public_key=excluded.public_key, credential_id=excluded.credential_id, counter=excluded.counter, ' +
        'type=excluded.type, aa_guid=excluded.aa_guid, transports=excluded.transports, encrypted_user_key=excluded.encrypted_user_key, ' +
        'encrypted_public_key=excluded.encrypted_public_key, encrypted_private_key=excluded.encrypted_private_key, supports_prf=excluded.supports_prf, updated_at=excluded.updated_at'
    ),
    credential.id,
    credential.userId,
    credential.purpose,
    credential.name,
    credential.publicKey,
    credential.credentialId,
    credential.counter,
    credential.type,
    credential.aaGuid,
    credential.transports ? JSON.stringify(credential.transports) : null,
    credential.encryptedUserKey,
    credential.encryptedPublicKey,
    credential.encryptedPrivateKey,
    credential.supportsPrf ? 1 : 0,
    credential.createdAt,
    credential.updatedAt
  ).run();
}

export async function listAccountPasskeyCredentialsByUserId(
  db: D1Database,
  userId: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<AccountPasskeyCredential[]> {
  await ensureAccountPasskeySchema(db);
  const rows = await db
    .prepare('SELECT * FROM webauthn_credentials WHERE user_id = ? AND purpose = ? ORDER BY created_at ASC')
    .bind(userId, purpose)
    .all<any>();
  return (rows.results || []).map(mapCredentialRow);
}

export async function getAccountPasskeyCredentialById(
  db: D1Database,
  userId: string,
  id: string
): Promise<AccountPasskeyCredential | null> {
  await ensureAccountPasskeySchema(db);
  const row = await db
    .prepare('SELECT * FROM webauthn_credentials WHERE user_id = ? AND id = ? LIMIT 1')
    .bind(userId, id)
    .first<any>();
  return row ? mapCredentialRow(row) : null;
}

export async function getAccountPasskeyCredentialByCredentialId(
  db: D1Database,
  credentialId: string
): Promise<AccountPasskeyCredential | null> {
  await ensureAccountPasskeySchema(db);
  const row = await db
    .prepare('SELECT * FROM webauthn_credentials WHERE credential_id = ? LIMIT 1')
    .bind(credentialId)
    .first<any>();
  return row ? mapCredentialRow(row) : null;
}

export async function countAccountPasskeyCredentialsByUserId(
  db: D1Database,
  userId: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<number> {
  await ensureAccountPasskeySchema(db);
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM webauthn_credentials WHERE user_id = ? AND purpose = ?')
    .bind(userId, purpose)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function updateAccountPasskeyCounter(
  db: D1Database,
  userId: string,
  credentialId: string,
  counter: number,
  updatedAt: string
): Promise<void> {
  await ensureAccountPasskeySchema(db);
  await db
    .prepare('UPDATE webauthn_credentials SET counter = ?, updated_at = ? WHERE user_id = ? AND credential_id = ?')
    .bind(counter, updatedAt, userId, credentialId)
    .run();
}

export async function updateAccountPasskeyEncryption(
  db: D1Database,
  userId: string,
  credentialId: string,
  encryptedUserKey: string,
  encryptedPublicKey: string,
  encryptedPrivateKey: string,
  updatedAt: string
): Promise<boolean> {
  await ensureAccountPasskeySchema(db);
  const result = await db
    .prepare(
      'UPDATE webauthn_credentials SET encrypted_user_key = ?, encrypted_public_key = ?, encrypted_private_key = ?, supports_prf = 1, updated_at = ? ' +
        "WHERE user_id = ? AND credential_id = ? AND purpose = 'login'"
    )
    .bind(encryptedUserKey, encryptedPublicKey, encryptedPrivateKey, updatedAt, userId, credentialId)
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function deleteAccountPasskeyCredential(
  db: D1Database,
  userId: string,
  id: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<boolean> {
  await ensureAccountPasskeySchema(db);
  const result = await db
    .prepare('DELETE FROM webauthn_credentials WHERE user_id = ? AND id = ? AND purpose = ?')
    .bind(userId, id, purpose)
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function saveAccountPasskeyChallenge(
  db: D1Database,
  challenge: AccountPasskeyChallenge
): Promise<void> {
  await ensureAccountPasskeySchema(db);
  await db.prepare('DELETE FROM webauthn_challenges WHERE expires_at < ? OR used_at IS NOT NULL').bind(Date.now()).run();
  await db
    .prepare(
      'INSERT INTO webauthn_challenges(challenge_hash, scope, user_id, expires_at, used_at, created_at) VALUES(?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(challenge_hash) DO UPDATE SET scope=excluded.scope, user_id=excluded.user_id, expires_at=excluded.expires_at, used_at=excluded.used_at, created_at=excluded.created_at'
    )
    .bind(
      challenge.challengeHash,
      challenge.scope,
      challenge.userId,
      challenge.expiresAt,
      challenge.usedAt,
      challenge.createdAt
    )
    .run();
}

export async function consumeAccountPasskeyChallenge(
  db: D1Database,
  challengeHash: string,
  scope: AccountPasskeyChallengeScope,
  userId: string | null,
  nowMs: number
): Promise<AccountPasskeyChallenge | null> {
  await ensureAccountPasskeySchema(db);
  const row = await db
    .prepare('SELECT * FROM webauthn_challenges WHERE challenge_hash = ? AND scope = ? LIMIT 1')
    .bind(challengeHash, scope)
    .first<any>();
  if (!row) return null;
  const challenge = mapChallengeRow(row);
  if (challenge.usedAt != null || challenge.expiresAt < nowMs) return null;
  if (userId !== null && challenge.userId !== userId) return null;
  if (userId === null && challenge.userId !== null) return null;

  const result = await db
    .prepare('UPDATE webauthn_challenges SET used_at = ? WHERE challenge_hash = ? AND used_at IS NULL')
    .bind(nowMs, challengeHash)
    .run();
  if (Number(result.meta.changes || 0) <= 0) return null;
  return { ...challenge, usedAt: nowMs };
}
