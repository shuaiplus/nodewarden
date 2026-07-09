import type { Env, User } from '../types';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getAttachmentObjectKey, getBlobStorageKind, putBlobObject } from './blob-store';
import { BACKUP_SETTINGS_CONFIG_KEY, normalizeImportedBackupSettingsValue } from './backup-config';
import {
  type BackupManifestAttachmentBlob,
  type BackupPayload,
  isSafeBackupAttachmentBlobName,
  parseBackupArchive,
  validateBackupPayloadContents,
} from './backup-archive';

// CONTRACT:
// Restore is intentionally whitelist-based. Old backups may contain retired
// fields, but only the columns listed here are imported. Keep this file in sync
// with src/services/backup-archive.ts whenever backup contents change.
//
// WHEN CHANGING THIS:
// - Update BackupTableName, BACKUP_TABLES, reset statements, prepared payloads,
//   shadow-table count validation, insert column lists, and frontend import
//   count types together.
// - Do not import users.api_key, even if an older backup contains it.
type SqlRow = Record<string, string | number | null>;
type BackupTableName =
  | 'config'
  | 'users'
  | 'domain_settings'
  | 'user_revisions'
  | 'trusted_two_factor_device_tokens'
  | 'webauthn_credentials'
  | 'folders'
  | 'ciphers'
  | 'attachments';

const BACKUP_TABLES: BackupTableName[] = [
  'config',
  'users',
  'domain_settings',
  'user_revisions',
  'trusted_two_factor_device_tokens',
  'webauthn_credentials',
  'folders',
  'ciphers',
  'attachments',
];

function shadowTableName(table: BackupTableName): string {
  return `${table}__restore`;
}

export interface BackupImportResultBody {
  object: 'instance-backup-import';
  imported: {
    config: number;
    users: number;
    domainSettings: number;
    userRevisions: number;
    trustedTwoFactorDeviceTokens: number;
    webauthnCredentials: number;
    folders: number;
    ciphers: number;
    attachments: number;
    attachmentFiles: number;
  };
  skipped: {
    reason: string | null;
    attachments: number;
    items: Array<{
      kind: 'attachment';
      path: string;
      sizeBytes: number;
    }>;
  };
}

export interface BackupImportExecutionResult {
  result: BackupImportResultBody;
  auditActorUserId: string | null;
}

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const response = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (response.results || []).map((row) => ({ ...row }));
}

async function getTableCreateSql(db: D1Database, table: BackupTableName): Promise<string> {
  const row = await db
    .prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?")
    .bind(table)
    .first<{ sql: string | null }>();
  const sql = String(row?.sql || '').trim();
  if (!sql) {
    throw new Error(`Restore shadow schema is missing table definition for ${table}`);
  }
  return sql;
}

function buildShadowTableCreateSql(createSql: string, table: BackupTableName): string {
  const tablePattern = new RegExp(`^CREATE TABLE(?:\\s+IF NOT EXISTS)?\\s+(?:\"${table}\"|${table})(?=\\s*\\()`, 'i');
  let next = createSql.replace(tablePattern, `CREATE TABLE "${shadowTableName(table)}"`);
  if (next === createSql) {
    throw new Error(`Restore shadow schema could not rewrite CREATE TABLE statement for ${table}`);
  }
  for (const currentTable of BACKUP_TABLES) {
    const referencePattern = new RegExp(`\\bREFERENCES\\s+(?:\"${currentTable}\"|${currentTable})(?=\\s*\\()`, 'gi');
    next = next.replace(
      referencePattern,
      `REFERENCES "${shadowTableName(currentTable)}"`
    );
  }
  return next;
}

async function resetRestoreArtifacts(db: D1Database): Promise<void> {
  const dropStatements = BACKUP_TABLES
    .slice()
    .reverse()
    .map((table) => db.prepare(`DROP TABLE IF EXISTS ${shadowTableName(table)}`));
  if (dropStatements.length) {
    await db.batch(dropStatements);
  }
}

async function createShadowTables(db: D1Database): Promise<void> {
  const createStatements: D1PreparedStatement[] = [];
  for (const table of BACKUP_TABLES) {
    const createSql = await getTableCreateSql(db, table);
    createStatements.push(db.prepare(buildShadowTableCreateSql(createSql, table)));
  }
  await db.batch(createStatements);
}

async function validateShadowTableCounts(
  db: D1Database,
  expectedCounts: Partial<Record<BackupTableName, number>>
): Promise<void> {
  await Promise.all(BACKUP_TABLES.map(async (table) => {
    const expected = expectedCounts[table] ?? 0;
    const row = await db.prepare(`SELECT COUNT(*) AS count FROM ${shadowTableName(table)}`).first<{ count: number }>();
    const actual = Number(row?.count || 0);
    if (actual !== expected) {
      throw new Error(`Restore shadow validation failed for ${table}: expected ${expected}, received ${actual}`);
    }
  }));
}

async function swapShadowTablesIntoPlace(db: D1Database): Promise<void> {
  const statements: D1PreparedStatement[] = [];
  // Commit by replacing live table contents from validated shadow tables.
  // This avoids D1 schema-rename edge cases while keeping current data intact
  // until the final batch succeeds.
  for (const sql of buildResetImportTargetStatements(db)) {
    statements.push(sql);
  }
  for (const table of BACKUP_TABLES) {
    statements.push(db.prepare(`INSERT INTO ${table} SELECT * FROM ${shadowTableName(table)}`));
  }
  await db.batch(statements);
}

async function ensureImportTargetIsFresh(db: D1Database): Promise<void> {
  const counts = await Promise.all([
    db.prepare('SELECT COUNT(*) AS count FROM ciphers').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM folders').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM attachments').first<{ count: number }>(),
    db.prepare('SELECT COUNT(*) AS count FROM sends').first<{ count: number }>(),
  ]);
  const total = counts.reduce((sum, row) => sum + Number(row?.count || 0), 0);
  if (total > 0) {
    throw new Error('Backup import requires a fresh instance with no vault or send data');
  }
}

function buildResetImportTargetStatements(db: D1Database): D1PreparedStatement[] {
  return [
    'DELETE FROM attachments',
    'DELETE FROM ciphers',
    'DELETE FROM folders',
    'DELETE FROM webauthn_credentials',
    'DELETE FROM trusted_two_factor_device_tokens',
    'DELETE FROM domain_settings',
    'DELETE FROM user_revisions',
    'DELETE FROM users',
    'DELETE FROM config',
  ].map((sql) => db.prepare(sql));
}

async function collectCurrentBlobKeys(db: D1Database): Promise<Set<string>> {
  const keys = new Set<string>();
  const attachmentRows = await queryRows(
    db,
    `SELECT a.id, a.cipher_id
     FROM attachments a
     INNER JOIN ciphers c ON c.id = a.cipher_id`
  );
  for (const row of attachmentRows) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    keys.add(getAttachmentObjectKey(cipherId, attachmentId));
  }
  return keys;
}

const KV_BLOB_SKIP_REASON = 'Cloudflare KV object size limit (25 MB)';
const BLOB_STORAGE_UNAVAILABLE_SKIP_REASON = 'Attachment storage is not configured';
const ATTACHMENT_RESTORE_FAILED_REASON = 'Some attachments could not be restored and were skipped';

interface BackupImportSkipSummary {
  reason: string | null;
  attachments: number;
  items: Array<{
    kind: 'attachment';
    path: string;
    sizeBytes: number;
  }>;
}

interface PreparedBackupImportPayload {
  payload: BackupPayload;
  skipped: BackupImportSkipSummary;
}

interface AttachmentRestoreResult {
  imported: number;
  restoredAttachments: SqlRow[];
  skipped: BackupImportSkipSummary;
}

interface RemoteAttachmentSource {
  loadAttachment(blobName: string): Promise<Uint8Array | null>;
}

export interface BackupRestoreProgressEvent {
  source: 'local' | 'remote';
  step: string;
  fileName: string;
  stageTitle: string;
  stageDetail: string;
  replaceExisting: boolean;
  done?: boolean;
  ok?: boolean;
  error?: string | null;
}

export type BackupRestoreProgressReporter = (event: BackupRestoreProgressEvent) => Promise<void> | void;

function attachmentRowKey(row: SqlRow): string {
  const attachmentId = String(row.id || '').trim();
  const cipherId = String(row.cipher_id || '').trim();
  return `${cipherId}/${attachmentId}`;
}

function cloneRows(rows: SqlRow[]): SqlRow[] {
  return rows.map((row) => ({ ...row }));
}

function normalizeAccountPasskeyPurpose(value: unknown): 'login' | 'twoFactor' {
  return value == null ? 'login' : String(value).trim() === 'twoFactor' ? 'twoFactor' : 'login';
}

function upsertConfigRow(rows: SqlRow[], key: string, value: string): SqlRow[] {
  let replaced = false;
  const nextRows = rows.map((row) => {
    if (String(row.key || '').trim() !== key) return { ...row };
    replaced = true;
    return { ...row, key, value };
  });
  if (!replaced) {
    nextRows.push({ key, value });
  }
  return nextRows;
}

async function prepareImportedConfigRows(
  env: Env,
  configRows: SqlRow[],
  userRows: SqlRow[]
): Promise<SqlRow[]> {
  let nextConfigRows = cloneRows(configRows || []);
  const rawBackupSettings = nextConfigRows.find((row) => String(row.key || '').trim() === BACKUP_SETTINGS_CONFIG_KEY);
  const normalizedBackupSettings = await normalizeImportedBackupSettingsValue(
    typeof rawBackupSettings?.value === 'string' ? rawBackupSettings.value : null,
    env,
    userRows.map((row) => ({
      id: String(row.id || '').trim(),
      publicKey: typeof row.public_key === 'string' ? row.public_key : null,
      role: String(row.role || '').trim() as User['role'],
      status: String(row.status || '').trim() as User['status'],
    })),
    'UTC'
  );
  if (normalizedBackupSettings !== null) {
    nextConfigRows = upsertConfigRow(nextConfigRows, BACKUP_SETTINGS_CONFIG_KEY, normalizedBackupSettings);
  }
  nextConfigRows = upsertConfigRow(nextConfigRows, 'registered', 'true');
  return nextConfigRows;
}

async function importPreparedBackupRows(db: D1Database, payload: BackupPayload['db'], env: Env): Promise<BackupPayload['db']> {
  const preparedDb: BackupPayload['db'] = {
    config: await prepareImportedConfigRows(env, payload.config || [], payload.users || []),
    users: cloneRows(payload.users || []).map((row) => ({
      ...row,
      verify_devices: row.verify_devices ?? 1,
      yubikey_nfc: row.yubikey_nfc ?? 0,
    })),
    domain_settings: cloneRows(payload.domain_settings || []),
    user_revisions: cloneRows(payload.user_revisions || []),
    trusted_two_factor_device_tokens: cloneRows(payload.trusted_two_factor_device_tokens || []),
    webauthn_credentials: cloneRows(payload.webauthn_credentials || []).map((row) => ({
      ...row,
      purpose: normalizeAccountPasskeyPurpose(row.purpose),
    })),
    folders: cloneRows(payload.folders || []),
    ciphers: cloneRows(payload.ciphers || []).map((row) => ({
      ...row,
      archived_at: row.archived_at ?? null,
    })),
    attachments: cloneRows(payload.attachments || []),
  };
  await importBackupRows(db, preparedDb, true);
  return preparedDb;
}

function prepareImportPayloadForTarget(env: Env, payload: BackupPayload, files: Record<string, Uint8Array>): PreparedBackupImportPayload {
  const storageKind = getBlobStorageKind(env);
  if (storageKind === 'r2') {
    return {
      payload,
      skipped: {
        reason: null,
        attachments: 0,
        items: [],
      },
    };
  }

  if (storageKind === null) {
    const skippedItems = (payload.db.attachments || []).map((row) => {
      const cipherId = String(row.cipher_id || '').trim();
      const attachmentId = String(row.id || '').trim();
      return {
        kind: 'attachment' as const,
        path: `attachments/${cipherId}/${attachmentId}.bin`,
        sizeBytes: Number(row.size || 0) || 0,
      };
    });

    const result = {
      payload: {
        ...payload,
        db: {
          ...payload.db,
          attachments: [],
        },
      },
      skipped: {
        reason: skippedItems.length ? BLOB_STORAGE_UNAVAILABLE_SKIP_REASON : null,
        attachments: skippedItems.length,
        items: skippedItems,
      },
    };
    return result;
  }

  const oversizedAttachmentPaths = new Set<string>();
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const entry of Object.keys(files)) {
    if (!entry.endsWith('.bin')) continue;
    const sizeBytes = files[entry].byteLength;
    if (sizeBytes <= KV_MAX_OBJECT_BYTES) continue;
    if (entry.startsWith('attachments/')) {
      oversizedAttachmentPaths.add(entry);
      skippedItems.push({ kind: 'attachment', path: entry, sizeBytes });
    }
  }

  const nextAttachments = (payload.db.attachments || []).filter((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) return false;
    return !oversizedAttachmentPaths.has(`attachments/${cipherId}/${attachmentId}.bin`);
  });

  const nextPayload: BackupPayload = {
    ...payload,
    db: {
      ...payload.db,
      attachments: nextAttachments,
    },
  };

  const needsKvBlobStorage = nextAttachments.length > 0;

  if (needsKvBlobStorage && !env.ATTACHMENTS_KV) {
    throw new Error('Backup restore requires ATTACHMENTS_KV when using KV blob storage');
  }

  const result = {
    payload: nextPayload,
    skipped: {
      reason: skippedItems.length ? KV_BLOB_SKIP_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
  return result;
}

function buildInsertStatements(db: D1Database, table: string, columns: string[], rows: SqlRow[], upsert = false): D1PreparedStatement[] {
  if (!rows.length) return [];
  const placeholders = `(${columns.map(() => '?').join(', ')})`;
  const sql = `INSERT ${upsert ? 'OR REPLACE ' : ''}INTO ${table} (${columns.join(', ')}) VALUES ${placeholders}`;
  return rows.map((row) => db.prepare(sql).bind(...columns.map((column) => row[column] ?? null)));
}

async function runInsertBatch(db: D1Database, table: string, statements: D1PreparedStatement[]): Promise<void> {
  if (!statements.length) return;
  try {
    await db.batch(statements);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Restore insert failed for ${table}: ${message}`);
  }
}

async function restoreBlobFiles(env: Env, db: BackupPayload['db'], files: Record<string, Uint8Array>): Promise<AttachmentRestoreResult> {
  const restoredAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    const key = `attachments/${cipherId}/${attachmentId}.bin`;
    const bytes = files[key];
    if (!bytes) {
      skippedItems.push({
        kind: 'attachment',
        path: key,
        sizeBytes: Number(row.size || 0) || 0,
      });
      continue;
    }
    try {
      await putBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId), bytes, {
        size: bytes.byteLength,
        contentType: 'application/octet-stream',
      });
      restoredAttachments.push(row);
    } catch {
      skippedItems.push({
        kind: 'attachment',
        path: key,
        sizeBytes: bytes.byteLength,
      });
    }
  }

  return {
    imported: restoredAttachments.length,
    restoredAttachments,
    skipped: {
      reason: skippedItems.length ? ATTACHMENT_RESTORE_FAILED_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

function buildAttachmentBlobLookup(manifest: BackupPayload['manifest']): Map<string, BackupManifestAttachmentBlob> {
  const lookup = new Map<string, BackupManifestAttachmentBlob>();
  for (const item of manifest.attachmentBlobs || []) {
    const cipherId = String(item.cipherId || '').trim();
    const attachmentId = String(item.attachmentId || '').trim();
    const blobName = String(item.blobName || '').trim();
    if (!cipherId || !attachmentId || !isSafeBackupAttachmentBlobName(blobName)) continue;
    lookup.set(`${cipherId}/${attachmentId}`, {
      ...item,
      cipherId,
      attachmentId,
      blobName,
    });
  }
  return lookup;
}

async function prepareRemoteAttachmentPayload(
  env: Env,
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  source: RemoteAttachmentSource
): Promise<PreparedBackupImportPayload> {
  const manifestLookup = buildAttachmentBlobLookup(payload.manifest);
  const storageKind = getBlobStorageKind(env);
  const nextAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const lookupKey = `${cipherId}/${attachmentId}`;
    const ref = manifestLookup.get(lookupKey);
    const sizeBytes = ref?.sizeBytes || Number(row.size || 0) || 0;
    const path = ref ? `attachments/${ref.blobName}` : `attachments/${lookupKey}`;
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;

    if (files[inlinePath]) {
      nextAttachments.push(row);
      continue;
    }
    if (!ref) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    if (storageKind === 'kv' && sizeBytes > KV_MAX_OBJECT_BYTES) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    if (storageKind === null) {
      skippedItems.push({ kind: 'attachment', path, sizeBytes });
      continue;
    }
    nextAttachments.push(row);
  }

  const result = {
    payload: {
      ...payload,
      db: {
        ...payload.db,
        attachments: nextAttachments,
      },
    },
    skipped: {
      reason: skippedItems.length ? 'Some remote attachments were unavailable and were skipped' : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
  return result;
}

async function removeAttachmentRows(db: D1Database, attachmentRows: SqlRow[], useShadowTable: boolean = false): Promise<void> {
  if (!attachmentRows.length) return;
  const tableName = useShadowTable ? shadowTableName('attachments') : 'attachments';
  const statements = attachmentRows
    .map((row) => {
      const attachmentId = String(row.id || '').trim();
      const cipherId = String(row.cipher_id || '').trim();
      if (!attachmentId || !cipherId) return null;
      return db.prepare(`DELETE FROM ${tableName} WHERE id = ? AND cipher_id = ?`).bind(attachmentId, cipherId);
    })
    .filter((statement): statement is D1PreparedStatement => !!statement);
  if (!statements.length) return;
  await db.batch(statements);
}

async function restoreRemoteAttachmentFiles(
  env: Env,
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  source: RemoteAttachmentSource
): Promise<{
  imported: number;
  skipped: BackupImportSkipSummary;
  restoredAttachments: SqlRow[];
}> {
  const manifestLookup = buildAttachmentBlobLookup(payload.manifest);
  const restoredAttachments: SqlRow[] = [];
  const skippedItems: BackupImportSkipSummary['items'] = [];

  for (const row of payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;
    const ref = manifestLookup.get(`${cipherId}/${attachmentId}`);
    if (!ref && !files[inlinePath]) {
      skippedItems.push({
        kind: 'attachment',
        path: `attachments/${cipherId}/${attachmentId}`,
        sizeBytes: Number(row.size || 0) || 0,
      });
      continue;
    }
    const bytes = files[inlinePath] || (ref ? await source.loadAttachment(ref.blobName) : null);
    if (!bytes) {
      skippedItems.push({
        kind: 'attachment',
        path: ref ? `attachments/${ref.blobName}` : inlinePath,
        sizeBytes: ref?.sizeBytes || Number(row.size || 0) || 0,
      });
      continue;
    }
    try {
      await putBlobObject(env, getAttachmentObjectKey(cipherId, attachmentId), bytes, {
        size: bytes.byteLength,
        contentType: 'application/octet-stream',
      });
      restoredAttachments.push(row);
    } catch {
      skippedItems.push({
        kind: 'attachment',
        path: ref ? `attachments/${ref.blobName}` : inlinePath,
        sizeBytes: bytes.byteLength,
      });
    }
  }

  return {
    imported: restoredAttachments.length,
    restoredAttachments,
    skipped: {
      reason: skippedItems.length ? ATTACHMENT_RESTORE_FAILED_REASON : null,
      attachments: skippedItems.length,
      items: skippedItems,
    },
  };
}

async function cleanupOrphanedBlobFiles(env: Env, beforeKeys: Set<string>, afterKeys: Set<string>): Promise<void> {
  const staleKeys = Array.from(beforeKeys).filter((key) => !afterKeys.has(key));
  for (const key of staleKeys) {
    await deleteBlobObject(env, key);
  }
}

async function importBackupRows(db: D1Database, payload: BackupPayload['db'], useShadowTables: boolean = false): Promise<void> {
  const tableName = (table: BackupTableName): string => (useShadowTables ? shadowTableName(table) : table);
  await runInsertBatch(
    db,
    tableName('config'),
    buildInsertStatements(db, tableName('config'), ['key', 'value'], payload.config || [], true)
  );
  await runInsertBatch(
    db,
    tableName('users'),
    buildInsertStatements(
      db,
      tableName('users'),
      ['id', 'email', 'name', 'master_password_hint', 'master_password_hash', 'key', 'private_key', 'public_key', 'kdf_type', 'kdf_iterations', 'kdf_memory', 'kdf_parallelism', 'security_stamp', 'role', 'status', 'verify_devices', 'totp_secret', 'totp_recovery_code', 'yubikey_key1', 'yubikey_key2', 'yubikey_key3', 'yubikey_key4', 'yubikey_key5', 'yubikey_nfc', 'created_at', 'updated_at'],
      payload.users || []
    )
  );
  await runInsertBatch(
    db,
    tableName('user_revisions'),
    buildInsertStatements(db, tableName('user_revisions'), ['user_id', 'revision_date'], payload.user_revisions || [], true)
  );
  await runInsertBatch(
    db,
    tableName('domain_settings'),
    buildInsertStatements(
      db,
      tableName('domain_settings'),
      ['user_id', 'equivalent_domains', 'custom_equivalent_domains', 'excluded_global_equivalent_domains', 'updated_at'],
      payload.domain_settings || [],
      true
    )
  );
  await runInsertBatch(
    db,
    tableName('trusted_two_factor_device_tokens'),
    buildInsertStatements(
      db,
      tableName('trusted_two_factor_device_tokens'),
      ['token', 'user_id', 'device_identifier', 'expires_at'],
      payload.trusted_two_factor_device_tokens || []
    )
  );
  await runInsertBatch(
    db,
    tableName('webauthn_credentials'),
    buildInsertStatements(
      db,
      tableName('webauthn_credentials'),
      ['id', 'user_id', 'purpose', 'name', 'public_key', 'credential_id', 'counter', 'type', 'aa_guid', 'transports', 'encrypted_user_key', 'encrypted_public_key', 'encrypted_private_key', 'supports_prf', 'created_at', 'updated_at'],
      payload.webauthn_credentials || []
    )
  );
  await runInsertBatch(
    db,
    tableName('folders'),
    buildInsertStatements(db, tableName('folders'), ['id', 'user_id', 'name', 'created_at', 'updated_at'], payload.folders || [])
  );
  await runInsertBatch(
    db,
    tableName('ciphers'),
    buildInsertStatements(
      db,
      tableName('ciphers'),
      ['id', 'user_id', 'type', 'folder_id', 'name', 'notes', 'favorite', 'data', 'reprompt', 'key', 'created_at', 'updated_at', 'archived_at', 'deleted_at'],
      payload.ciphers || []
    )
  );
  await runInsertBatch(
    db,
    tableName('attachments'),
    buildInsertStatements(db, tableName('attachments'), ['id', 'cipher_id', 'file_name', 'size', 'size_name', 'key'], payload.attachments || [])
  );
}

export async function importBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
  progress?: BackupRestoreProgressReporter,
  fileName: string = 'nodewarden_backup.zip'
): Promise<BackupImportExecutionResult> {
  const parsed = parseBackupArchive(archiveBytes);
  validateBackupPayloadContents(parsed.payload, parsed.files);
  const prepared = prepareImportPayloadForTarget(env, parsed.payload, parsed.files);

  try {
    await ensureImportTargetIsFresh(env.DB);
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  await resetRestoreArtifacts(env.DB);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    await progress?.({
      source: 'local',
      step: 'local_create_shadow',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_shadow_title',
      stageDetail: 'txt_backup_restore_progress_local_shadow_detail',
      replaceExisting,
    });
    await createShadowTables(env.DB);
    await progress?.({
      source: 'local',
      step: 'local_import_data',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_data_title',
      stageDetail: 'txt_backup_restore_progress_local_data_detail',
      replaceExisting,
    });
    const db = await importPreparedBackupRows(env.DB, prepared.payload.db, env);
    await validateShadowTableCounts(env.DB, {
      config: (db.config || []).length,
      users: (db.users || []).length,
      domain_settings: (db.domain_settings || []).length,
      user_revisions: (db.user_revisions || []).length,
      trusted_two_factor_device_tokens: (db.trusted_two_factor_device_tokens || []).length,
      webauthn_credentials: (db.webauthn_credentials || []).length,
      folders: (db.folders || []).length,
      ciphers: (db.ciphers || []).length,
      attachments: (db.attachments || []).length,
    });

    await progress?.({
      source: 'local',
      step: 'local_restore_files',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_files_title',
      stageDetail: 'txt_backup_restore_progress_local_files_detail',
      replaceExisting,
    });
    const restored = await restoreBlobFiles(env, db, parsed.files);
    const restoredAttachmentKeys = new Set((restored.restoredAttachments || []).map(attachmentRowKey));
    const failedRestoreRows = (db.attachments || []).filter((row) => !restoredAttachmentKeys.has(attachmentRowKey(row)));
    await removeAttachmentRows(env.DB, failedRestoreRows, true).catch(() => undefined);
    await validateShadowTableCounts(env.DB, {
      config: (db.config || []).length,
      users: (db.users || []).length,
      domain_settings: (db.domain_settings || []).length,
      user_revisions: (db.user_revisions || []).length,
      trusted_two_factor_device_tokens: (db.trusted_two_factor_device_tokens || []).length,
      webauthn_credentials: (db.webauthn_credentials || []).length,
      folders: (db.folders || []).length,
      ciphers: (db.ciphers || []).length,
      attachments: restored.restoredAttachments.length,
    });
    await progress?.({
      source: 'local',
      step: 'local_finalize',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_finalize_title',
      stageDetail: 'txt_backup_restore_progress_local_finalize_detail',
      replaceExisting,
    });
    await swapShadowTablesIntoPlace(env.DB);
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    if (replaceExisting && previousBlobKeys.size) {
      const nextBlobKeys = await collectCurrentBlobKeys(env.DB).catch(() => null);
      if (nextBlobKeys) {
        await cleanupOrphanedBlobFiles(env, previousBlobKeys, nextBlobKeys).catch(() => undefined);
      }
    }

    await progress?.({
      source: 'local',
      step: 'local_complete',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_finalize_title',
      stageDetail: 'txt_backup_restore_progress_local_finalize_detail',
      replaceExisting,
      done: true,
      ok: true,
    });
    return {
      auditActorUserId: (db.users || []).some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
      result: {
        object: 'instance-backup-import',
        imported: {
          config: (db.config || []).length,
          users: (db.users || []).length,
          domainSettings: (db.domain_settings || []).length,
          userRevisions: (db.user_revisions || []).length,
          trustedTwoFactorDeviceTokens: (db.trusted_two_factor_device_tokens || []).length,
          webauthnCredentials: (db.webauthn_credentials || []).length,
          folders: (db.folders || []).length,
          ciphers: (db.ciphers || []).length,
          attachments: restored.restoredAttachments.length,
          attachmentFiles: restored.imported,
        },
        skipped: {
          reason: restored.skipped.reason || prepared.skipped.reason,
          attachments: prepared.skipped.attachments + restored.skipped.attachments,
          items: [...prepared.skipped.items, ...restored.skipped.items],
        },
      },
    };
  } catch (error) {
    await progress?.({
      source: 'local',
      step: 'local_failed',
      fileName,
      stageTitle: 'txt_backup_restore_progress_local_finalize_title',
      stageDetail: 'txt_backup_restore_progress_local_finalize_detail',
      replaceExisting,
      done: true,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    throw error;
  }
}

export async function importRemoteBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
  source: RemoteAttachmentSource,
  progress?: BackupRestoreProgressReporter,
  fileName: string = 'nodewarden_backup.zip'
): Promise<BackupImportExecutionResult> {
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: true });
  const preparedRemote = await prepareRemoteAttachmentPayload(env, parsed.payload, parsed.files, source);
  validateBackupPayloadContents(preparedRemote.payload, parsed.files, { allowExternalAttachmentBlobs: true });

  try {
    await ensureImportTargetIsFresh(env.DB);
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  await resetRestoreArtifacts(env.DB);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    await progress?.({
      source: 'remote',
      step: 'remote_create_shadow',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_shadow_title',
      stageDetail: 'txt_backup_restore_progress_remote_shadow_detail',
      replaceExisting,
    });
    await createShadowTables(env.DB);
    await progress?.({
      source: 'remote',
      step: 'remote_import_data',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_data_title',
      stageDetail: 'txt_backup_restore_progress_remote_data_detail',
      replaceExisting,
    });
    const db = await importPreparedBackupRows(env.DB, preparedRemote.payload.db, env);
    await validateShadowTableCounts(env.DB, {
      config: (db.config || []).length,
      users: (db.users || []).length,
      domain_settings: (db.domain_settings || []).length,
      user_revisions: (db.user_revisions || []).length,
      trusted_two_factor_device_tokens: (db.trusted_two_factor_device_tokens || []).length,
      webauthn_credentials: (db.webauthn_credentials || []).length,
      folders: (db.folders || []).length,
      ciphers: (db.ciphers || []).length,
      attachments: (db.attachments || []).length,
    });

    await progress?.({
      source: 'remote',
      step: 'remote_restore_files',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_files_title',
      stageDetail: 'txt_backup_restore_progress_remote_files_detail',
      replaceExisting,
    });
    const restored = await restoreRemoteAttachmentFiles(env, preparedRemote.payload, parsed.files, source);
    const restoredAttachmentKeys = new Set((restored.restoredAttachments || []).map(attachmentRowKey));
    const failedRestoreRows = (db.attachments || []).filter((row) => !restoredAttachmentKeys.has(attachmentRowKey(row)));
    await removeAttachmentRows(env.DB, failedRestoreRows, true).catch(() => undefined);
    await validateShadowTableCounts(env.DB, {
      config: (db.config || []).length,
      users: (db.users || []).length,
      domain_settings: (db.domain_settings || []).length,
      user_revisions: (db.user_revisions || []).length,
      trusted_two_factor_device_tokens: (db.trusted_two_factor_device_tokens || []).length,
      webauthn_credentials: (db.webauthn_credentials || []).length,
      folders: (db.folders || []).length,
      ciphers: (db.ciphers || []).length,
      attachments: restored.restoredAttachments.length,
    });
    await progress?.({
      source: 'remote',
      step: 'remote_finalize',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_finalize_title',
      stageDetail: 'txt_backup_restore_progress_remote_finalize_detail',
      replaceExisting,
    });
    await swapShadowTablesIntoPlace(env.DB);
    await resetRestoreArtifacts(env.DB).catch(() => undefined);

    if (replaceExisting && previousBlobKeys.size) {
      const nextBlobKeys = await collectCurrentBlobKeys(env.DB).catch(() => null);
      if (nextBlobKeys) {
        await cleanupOrphanedBlobFiles(env, previousBlobKeys, nextBlobKeys).catch(() => undefined);
      }
    }

    await progress?.({
      source: 'remote',
      step: 'remote_complete',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_finalize_title',
      stageDetail: 'txt_backup_restore_progress_remote_finalize_detail',
      replaceExisting,
      done: true,
      ok: true,
    });
    const finalSkippedItems = [...preparedRemote.skipped.items, ...restored.skipped.items];
    const finalSkippedReason = finalSkippedItems.length
      ? restored.skipped.reason || preparedRemote.skipped.reason
      : null;

    return {
      auditActorUserId: (db.users || []).some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
      result: {
        object: 'instance-backup-import',
        imported: {
          config: (db.config || []).length,
          users: (db.users || []).length,
          domainSettings: (db.domain_settings || []).length,
          userRevisions: (db.user_revisions || []).length,
          trustedTwoFactorDeviceTokens: (db.trusted_two_factor_device_tokens || []).length,
          webauthnCredentials: (db.webauthn_credentials || []).length,
          folders: (db.folders || []).length,
          ciphers: (db.ciphers || []).length,
          attachments: restored.restoredAttachments.length,
          attachmentFiles: restored.imported,
        },
        skipped: {
          reason: finalSkippedReason,
          attachments: finalSkippedItems.length,
          items: finalSkippedItems,
        },
      },
    };
  } catch (error) {
    await progress?.({
      source: 'remote',
      step: 'remote_failed',
      fileName,
      stageTitle: 'txt_backup_restore_progress_remote_finalize_title',
      stageDetail: 'txt_backup_restore_progress_remote_finalize_detail',
      replaceExisting,
      done: true,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    throw error;
  }
}
