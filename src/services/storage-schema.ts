// IMPORTANT:
// This is the runtime D1 schema bootstrap. Keep it in sync with
// migrations/0001_init.sql. Any new table/column/index must be added to both
// places together.
//
// WHEN CHANGING THIS:
// - Bump STORAGE_SCHEMA_VERSION in src/services/storage.ts so existing installs
//   rerun these idempotent statements.
// - If the new table stores persistent data, update the backup export/import
//   contract in src/services/backup-archive.ts and backup-import.ts.
// - Keep statements idempotent; D1 may execute them again on later requests.
const SCHEMA_STATEMENTS: readonly string[] = [
  'CREATE TABLE IF NOT EXISTS users (' +
  'id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT, master_password_hint TEXT, master_password_hash TEXT NOT NULL, ' +
  'key TEXT NOT NULL, private_key TEXT, public_key TEXT, kdf_type INTEGER NOT NULL, ' +
  'kdf_iterations INTEGER NOT NULL, kdf_memory INTEGER, kdf_parallelism INTEGER, ' +
  'security_stamp TEXT NOT NULL, role TEXT NOT NULL DEFAULT \'user\', status TEXT NOT NULL DEFAULT \'active\', verify_devices INTEGER NOT NULL DEFAULT 0, totp_secret TEXT, totp_recovery_code TEXT, yubikey_key1 TEXT, yubikey_key2 TEXT, yubikey_key3 TEXT, yubikey_key4 TEXT, yubikey_key5 TEXT, yubikey_nfc INTEGER NOT NULL DEFAULT 0, api_key TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)',
  'ALTER TABLE users ADD COLUMN master_password_hint TEXT',
  'ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT \'user\'',
  'ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT \'active\'',
  'ALTER TABLE users ADD COLUMN verify_devices INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN totp_secret TEXT',
  'ALTER TABLE users ADD COLUMN totp_recovery_code TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_key1 TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_key2 TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_key3 TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_key4 TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_key5 TEXT',
  'ALTER TABLE users ADD COLUMN yubikey_nfc INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE users ADD COLUMN api_key TEXT',

  'CREATE TABLE IF NOT EXISTS domain_settings (' +
  'user_id TEXT PRIMARY KEY, equivalent_domains TEXT NOT NULL DEFAULT \'[]\', custom_equivalent_domains TEXT NOT NULL DEFAULT \'[]\', excluded_global_equivalent_domains TEXT NOT NULL DEFAULT \'[]\', updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'ALTER TABLE domain_settings ADD COLUMN custom_equivalent_domains TEXT NOT NULL DEFAULT \'[]\'',

  'CREATE TABLE IF NOT EXISTS user_revisions (' +
  'user_id TEXT PRIMARY KEY, revision_date TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',

  'CREATE TABLE IF NOT EXISTS ciphers (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, folder_id TEXT, name TEXT, notes TEXT, ' +
  'favorite INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL, reprompt INTEGER, key TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'ALTER TABLE ciphers ADD COLUMN archived_at TEXT',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_updated ON ciphers(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_archived ON ciphers(user_id, archived_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted ON ciphers(user_id, deleted_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_deleted_updated ON ciphers(user_id, deleted_at, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_ciphers_user_folder ON ciphers(user_id, folder_id)',

  'CREATE TABLE IF NOT EXISTS folders (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_folders_user_updated ON folders(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS attachments (' +
  'id TEXT PRIMARY KEY, cipher_id TEXT NOT NULL, file_name TEXT NOT NULL, size INTEGER NOT NULL, ' +
  'size_name TEXT NOT NULL, key TEXT, ' +
  'FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_attachments_cipher ON attachments(cipher_id)',

  'CREATE TABLE IF NOT EXISTS sends (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, type INTEGER NOT NULL, name TEXT NOT NULL, notes TEXT, data TEXT NOT NULL, ' +
  'key TEXT NOT NULL, password_hash TEXT, password_salt TEXT, password_iterations INTEGER, auth_type INTEGER NOT NULL DEFAULT 2, emails TEXT, ' +
  'max_access_count INTEGER, access_count INTEGER NOT NULL DEFAULT 0, disabled INTEGER NOT NULL DEFAULT 0, hide_email INTEGER, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, expiration_date TEXT, deletion_date TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated ON sends(user_id, updated_at)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_deletion ON sends(user_id, deletion_date)',
  'CREATE INDEX IF NOT EXISTS idx_sends_user_updated_id ON sends(user_id, updated_at, id)',
  'ALTER TABLE sends ADD COLUMN auth_type INTEGER NOT NULL DEFAULT 2',
  'ALTER TABLE sends ADD COLUMN emails TEXT',

  'CREATE TABLE IF NOT EXISTS refresh_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, device_identifier TEXT, device_session_stamp TEXT, security_stamp TEXT, created_at INTEGER, last_used_at INTEGER, absolute_expires_at INTEGER, client_type TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)',
  'ALTER TABLE refresh_tokens ADD COLUMN device_identifier TEXT',
  'ALTER TABLE refresh_tokens ADD COLUMN device_session_stamp TEXT',
  'ALTER TABLE refresh_tokens ADD COLUMN security_stamp TEXT',
  'ALTER TABLE refresh_tokens ADD COLUMN created_at INTEGER',
  'ALTER TABLE refresh_tokens ADD COLUMN last_used_at INTEGER',
  'ALTER TABLE refresh_tokens ADD COLUMN absolute_expires_at INTEGER',
  'ALTER TABLE refresh_tokens ADD COLUMN client_type TEXT',
  "UPDATE refresh_tokens SET security_stamp = (SELECT users.security_stamp FROM users WHERE users.id = refresh_tokens.user_id) WHERE security_stamp IS NULL OR security_stamp = ''",
  "UPDATE refresh_tokens SET created_at = CAST(strftime('%s','now') AS INTEGER) * 1000 WHERE created_at IS NULL",
  "UPDATE refresh_tokens SET last_used_at = created_at WHERE last_used_at IS NULL",
  'UPDATE refresh_tokens SET absolute_expires_at = expires_at WHERE absolute_expires_at IS NULL',

  'CREATE TABLE IF NOT EXISTS invites (' +
  'code TEXT PRIMARY KEY, created_by TEXT NOT NULL, used_by TEXT, expires_at TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE, ' +
  'FOREIGN KEY (used_by) REFERENCES users(id) ON DELETE SET NULL)',
  'ALTER TABLE invites ADD COLUMN used_by TEXT',
  'CREATE INDEX IF NOT EXISTS idx_invites_status_expires ON invites(status, expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_invites_created_by ON invites(created_by, created_at)',

  'CREATE TABLE IF NOT EXISTS audit_logs (' +
  'id TEXT PRIMARY KEY, actor_user_id TEXT, action TEXT NOT NULL, category TEXT NOT NULL DEFAULT \'system\', level TEXT NOT NULL DEFAULT \'info\', target_type TEXT, target_id TEXT, metadata TEXT, created_at TEXT NOT NULL, ' +
  'FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL)',
  'ALTER TABLE audit_logs ADD COLUMN category TEXT NOT NULL DEFAULT \'system\'',
  'ALTER TABLE audit_logs ADD COLUMN level TEXT NOT NULL DEFAULT \'info\'',
  'UPDATE audit_logs SET category = json_extract(metadata, \'$.category\') WHERE json_valid(metadata) AND json_extract(metadata, \'$.category\') IN (\'auth\', \'security\', \'device\', \'data\', \'system\')',
  'UPDATE audit_logs SET level = json_extract(metadata, \'$.level\') WHERE json_valid(metadata) AND json_extract(metadata, \'$.level\') IN (\'info\', \'warn\', \'error\', \'security\')',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_created ON audit_logs(actor_user_id, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_category_created ON audit_logs(category, created_at)',
  'CREATE INDEX IF NOT EXISTS idx_audit_logs_level_created ON audit_logs(level, created_at)',

  'CREATE TABLE IF NOT EXISTS devices (' +
  'user_id TEXT NOT NULL, device_identifier TEXT NOT NULL, name TEXT NOT NULL, type INTEGER NOT NULL, session_stamp TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, push_uuid TEXT, push_token TEXT, banned INTEGER NOT NULL DEFAULT 0, banned_at TEXT, device_note TEXT, last_seen_at TEXT, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'PRIMARY KEY (user_id, device_identifier), ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_updated ON devices(user_id, updated_at)',
  'ALTER TABLE devices ADD COLUMN session_stamp TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_user_key TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_public_key TEXT',
  'ALTER TABLE devices ADD COLUMN encrypted_private_key TEXT',
  'ALTER TABLE devices ADD COLUMN push_uuid TEXT',
  'ALTER TABLE devices ADD COLUMN push_token TEXT',
  'ALTER TABLE devices ADD COLUMN banned INTEGER NOT NULL DEFAULT 0',
  'ALTER TABLE devices ADD COLUMN banned_at TEXT',
  'ALTER TABLE devices ADD COLUMN device_note TEXT',
  'ALTER TABLE devices ADD COLUMN last_seen_at TEXT',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_last_seen ON devices(user_id, last_seen_at)',
  'CREATE INDEX IF NOT EXISTS idx_devices_user_push ON devices(user_id, push_token)',
  "UPDATE refresh_tokens SET device_session_stamp = (SELECT devices.session_stamp FROM devices WHERE devices.user_id = refresh_tokens.user_id AND devices.device_identifier = refresh_tokens.device_identifier) WHERE device_identifier IS NOT NULL AND (device_session_stamp IS NULL OR device_session_stamp = '') AND EXISTS (SELECT 1 FROM devices WHERE devices.user_id = refresh_tokens.user_id AND devices.device_identifier = refresh_tokens.device_identifier)",
  "UPDATE refresh_tokens SET client_type = CASE WHEN EXISTS (SELECT 1 FROM devices WHERE devices.user_id = refresh_tokens.user_id AND devices.device_identifier = refresh_tokens.device_identifier AND devices.type IN (0, 1)) THEN 'mobile' WHEN EXISTS (SELECT 1 FROM devices WHERE devices.user_id = refresh_tokens.user_id AND devices.device_identifier = refresh_tokens.device_identifier AND devices.type = 14) THEN 'web' ELSE 'other' END WHERE client_type IS NULL OR client_type = ''",

  'CREATE TABLE IF NOT EXISTS auth_requests (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, organization_id TEXT, type INTEGER NOT NULL, request_device_identifier TEXT NOT NULL, request_device_type INTEGER NOT NULL, ' +
  'request_ip_address TEXT, request_country_name TEXT, response_device_identifier TEXT, access_code TEXT NOT NULL, public_key TEXT NOT NULL, key TEXT, master_password_hash TEXT, ' +
  'approved INTEGER, creation_date TEXT NOT NULL, response_date TEXT, authentication_date TEXT, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_user_created ON auth_requests(user_id, creation_date)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_user_pending ON auth_requests(user_id, approved, response_date, authentication_date, creation_date)',
  'CREATE INDEX IF NOT EXISTS idx_auth_requests_device_pending ON auth_requests(user_id, request_device_identifier, creation_date)',

  'CREATE TABLE IF NOT EXISTS trusted_two_factor_device_tokens (' +
  'token TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_identifier TEXT NOT NULL, expires_at INTEGER NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_trusted_two_factor_device_tokens_user_device ON trusted_two_factor_device_tokens(user_id, device_identifier)',

  'CREATE TABLE IF NOT EXISTS totp_login_replays (' +
  'user_id TEXT NOT NULL, time_counter INTEGER NOT NULL, consumed_at INTEGER NOT NULL, ' +
  'PRIMARY KEY (user_id, time_counter), ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'CREATE INDEX IF NOT EXISTS idx_totp_login_replays_consumed_at ON totp_login_replays(consumed_at)',

  'CREATE TABLE IF NOT EXISTS webauthn_credentials (' +
  'id TEXT PRIMARY KEY, user_id TEXT NOT NULL, purpose TEXT NOT NULL DEFAULT \'login\', name TEXT NOT NULL, public_key TEXT NOT NULL, credential_id TEXT NOT NULL, counter INTEGER NOT NULL DEFAULT 0, ' +
  'type TEXT, aa_guid TEXT, transports TEXT, encrypted_user_key TEXT, encrypted_public_key TEXT, encrypted_private_key TEXT, supports_prf INTEGER NOT NULL DEFAULT 0, ' +
  'created_at TEXT NOT NULL, updated_at TEXT NOT NULL, ' +
  'FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)',
  'ALTER TABLE webauthn_credentials ADD COLUMN purpose TEXT NOT NULL DEFAULT \'login\'',
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user ON webauthn_credentials(user_id)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_updated ON webauthn_credentials(user_id, updated_at)',

  'CREATE TABLE IF NOT EXISTS webauthn_challenges (' +
  'challenge_hash TEXT PRIMARY KEY, scope TEXT NOT NULL, user_id TEXT, expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires ON webauthn_challenges(expires_at)',
  'CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_user_scope ON webauthn_challenges(user_id, scope)',

  'CREATE TABLE IF NOT EXISTS login_attempts_ip (' +
  'ip TEXT PRIMARY KEY, attempts INTEGER NOT NULL, locked_until INTEGER, updated_at INTEGER NOT NULL)',

  'CREATE TABLE IF NOT EXISTS used_attachment_download_tokens (' +
  'jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)',
];

async function executeSchemaStatement(db: D1Database, statement: string): Promise<void> {
  try {
    await db.prepare(statement).run();
  } catch (error) {
    const msg = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (msg.includes('already exists') || msg.includes('duplicate column name')) {
      return;
    }
    throw error;
  }
}

async function ensureAdminUserExists(db: D1Database): Promise<void> {
  const admin = await db.prepare("SELECT id FROM users WHERE role = 'admin' LIMIT 1").first<{ id: string }>();
  if (admin?.id) return;

  const firstUser = await db
    .prepare('SELECT id FROM users ORDER BY created_at ASC LIMIT 1')
    .first<{ id: string }>();
  if (!firstUser?.id) return;

  await db
    .prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?")
    .bind(new Date().toISOString(), firstUser.id)
    .run();
}

export async function ensureStorageSchema(db: D1Database): Promise<void> {
  await db.prepare('PRAGMA foreign_keys = ON').run();
  await db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
  for (const stmt of SCHEMA_STATEMENTS) {
    await executeSchemaStatement(db, stmt);
  }
  await ensureAdminUserExists(db);
}
