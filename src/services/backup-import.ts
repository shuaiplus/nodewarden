import { syncVaultAdminRoles } from './vault-admin-role';
import { and, count, eq, getColumns, getTableName, TableAliasProxyHandler } from 'drizzle-orm';
import type { SQLiteTable } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import { sqliteMaster } from '../db/migrate';
import { attachments, ciphers, config, domainSettings, folders, sends, userRevisions, users, webauthnCredentials } from '../db/schema';
import type { Env, User } from '../types';
import { KV_MAX_OBJECT_BYTES, deleteBlobObject, getAttachmentObjectKey, getBlobStorageKind, putBlobObject } from './blob-store';
import { BACKUP_SETTINGS_CONFIG_KEY, normalizeImportedBackupSettingsValue } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
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
// - Update BACKUP_TABLES, reset statements, prepared payloads,
//   shadow-table count validation, insert column lists, and frontend import
//   count types together.
// - Do not import users.api_key, even if an older backup contains it.
// - Do not import, clear, or replace runtime authentication state such as
//   devices, sessions, auth requests, or remembered 2FA device tokens.
type SqlRow = Record<string, string | number | null>;

// Restore order: every table follows the tables its rows reference.
const BACKUP_TABLES = {
  config,
  users,
  domain_settings: domainSettings,
  user_revisions: userRevisions,
  webauthn_credentials: webauthnCredentials,
  folders,
  ciphers,
  attachments,
};
type BackupTableName = keyof typeof BACKUP_TABLES;
const BACKUP_TABLE_NAMES = Object.keys(BACKUP_TABLES) as BackupTableName[];

function shadowTableName(table: string): string {
  return `${table}__restore`;
}

// A shadow copy has its live table's columns under the __restore name. Drizzle's alias proxy with
// replaceOriginalName renders that name in every position (FROM, INSERT INTO, DELETE FROM, column
// references), so the query builder addresses the copy although it has no schema entry of its own.
function shadowTable<T extends SQLiteTable>(table: T): T {
  return new Proxy(table, new TableAliasProxyHandler(shadowTableName(getTableName(table)), true));
}

export interface BackupImportResultBody {
  object: 'instance-backup-import';
  imported: {
    config: number;
    users: number;
    domainSettings: number;
    userRevisions: number;
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

async function resetRestoreArtifacts(db: D1Database): Promise<void> {
  // eslint-disable-next-line nodewarden/no-raw-sql -- shadow tables are DDL copies made at runtime, outside the drizzle schema
  await db.batch(BACKUP_TABLE_NAMES.slice().reverse().map((table) => db.prepare(`DROP TABLE IF EXISTS ${shadowTableName(table)}`)));
}

async function validateShadowTableCounts(
  db: D1Database,
  expectedCounts: Partial<Record<BackupTableName, number>>
): Promise<void> {
  const orm = getOrm(db);
  await Promise.all(BACKUP_TABLE_NAMES.map(async (table) => {
    const expected = expectedCounts[table] ?? 0;
    const actual = await orm.$count(shadowTable(BACKUP_TABLES[table]));
    if (actual !== expected) {
      throw new Error(`Restore shadow validation failed for ${table}: expected ${expected}, received ${actual}`);
    }
  }));
}

async function collectCurrentBlobKeys(db: D1Database): Promise<Set<string>> {
  const keys = new Set<string>();
  const attachmentRows = await getOrm(db)
    .select({ id: attachments.id, cipherId: attachments.cipherId })
    .from(attachments)
    .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId));
  for (const row of attachmentRows) {
    const cipherId = String(row.cipherId || '').trim();
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

// Writes archive rows into a table's shadow copy: one statement per row, one batch per table. Only the
// allowlisted columns come from the archive; every other column keeps its default.
async function restoreRows(db: D1Database, table: BackupTableName, columns: readonly string[], rows: SqlRow[], replace = false): Promise<void> {
  if (!rows.length) return;
  const orm = getOrm(db);
  const target: SQLiteTable = shadowTable(BACKUP_TABLES[table]);
  const imported = Object.entries(getColumns(target)).filter(([, column]) => columns.includes(column.name));
  // `replace` keeps the INSERT OR REPLACE semantics these tables always had. REPLACE turns a NULL in a
  // NOT NULL column into the column default, which drizzle binds for undefined. The shadow copy starts
  // empty, so only a key the archive repeats can conflict; skipping it leaves the count check to reject
  // the archive, as it did after REPLACE deduplicated the rows.
  const statements = rows.map((row) => {
    const insert = orm.insert(target).values(Object.fromEntries(imported.map(([key, column]) =>
      [key, row[column.name] ?? (replace && column.notNull ? undefined : null)])));
    return replace ? insert.onConflictDoNothing() : insert;
  });
  try {
    await orm.batch(statements as [typeof statements[0], ...typeof statements]);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Restore insert failed for ${shadowTableName(table)}: ${message}`);
  }
}

function buildAttachmentBlobLookup(manifest: BackupPayload['manifest']): Map<string, BackupManifestAttachmentBlob> {
  return new Map(manifest.attachmentBlobs
    .filter(({ cipherId, attachmentId, blobName }) => cipherId && attachmentId && isSafeBackupAttachmentBlobName(blobName))
    .map((item) => [`${item.cipherId}/${item.attachmentId}`, item]));
}

export async function importBackupArchiveBytes(
  archiveBytes: Uint8Array,
  env: Env,
  actorUserId: string,
  replaceExisting: boolean,
  source: RemoteAttachmentSource | null = null,
  progress?: BackupRestoreProgressReporter,
  fileName: string = 'nodewarden_backup.zip'
): Promise<BackupImportExecutionResult> {
  // A remote archive keeps attachment blobs at the destination instead of inline .bin entries, so its
  // rows are trimmed to what the source can supply before validation; a local archive validates as-is.
  const restoreSource = source ? 'remote' : 'local';
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: !!source });
  let prepared: PreparedBackupImportPayload;
  if (source) {
    const manifestLookup = buildAttachmentBlobLookup(parsed.payload.manifest);
    const storageKind = getBlobStorageKind(env);
    const nextAttachments: SqlRow[] = [];
    const skippedItems: BackupImportSkipSummary['items'] = [];

    for (const row of parsed.payload.db.attachments) {
      const cipherId = String(row.cipher_id || '').trim();
      const attachmentId = String(row.id || '').trim();
      const lookupKey = `${cipherId}/${attachmentId}`;
      const ref = manifestLookup.get(lookupKey);
      const sizeBytes = ref?.sizeBytes || Number(row.size || 0) || 0;
      const path = ref ? `attachments/${ref.blobName}` : `attachments/${lookupKey}`;
      const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;

      if (parsed.files[inlinePath]) {
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

    prepared = {
      payload: {
        ...parsed.payload,
        db: {
          ...parsed.payload.db,
          attachments: nextAttachments,
        },
      },
      skipped: {
        reason: skippedItems.length ? 'Some remote attachments were unavailable and were skipped' : null,
        attachments: skippedItems.length,
        items: skippedItems,
      },
    };
    validateBackupPayloadContents(prepared.payload, parsed.files, { allowExternalAttachmentBlobs: true });
  } else {
    validateBackupPayloadContents(parsed.payload, parsed.files);
    // Fit the attachments to this instance's blob storage: R2 takes every blob, KV only blobs within
    // its object size limit, and without storage every attachment row is skipped.
    const storageKind = getBlobStorageKind(env);
    if (storageKind === 'r2') {
      prepared = {
        payload: parsed.payload,
        skipped: {
          reason: null,
          attachments: 0,
          items: [],
        },
      };
    } else if (storageKind === null) {
      const skippedItems = parsed.payload.db.attachments.map((row) => {
        const cipherId = String(row.cipher_id || '').trim();
        const attachmentId = String(row.id || '').trim();
        return {
          kind: 'attachment' as const,
          path: `attachments/${cipherId}/${attachmentId}.bin`,
          sizeBytes: Number(row.size || 0) || 0,
        };
      });

      prepared = {
        payload: {
          ...parsed.payload,
          db: {
            ...parsed.payload.db,
            attachments: [],
          },
        },
        skipped: {
          reason: skippedItems.length ? BLOB_STORAGE_UNAVAILABLE_SKIP_REASON : null,
          attachments: skippedItems.length,
          items: skippedItems,
        },
      };
    } else {
      const oversizedAttachmentPaths = new Set<string>();
      const skippedItems: BackupImportSkipSummary['items'] = [];

      for (const entry of Object.keys(parsed.files)) {
        if (!entry.endsWith('.bin')) continue;
        const sizeBytes = parsed.files[entry].byteLength;
        if (sizeBytes <= KV_MAX_OBJECT_BYTES) continue;
        if (entry.startsWith('attachments/')) {
          oversizedAttachmentPaths.add(entry);
          skippedItems.push({ kind: 'attachment', path: entry, sizeBytes });
        }
      }

      const nextAttachments = parsed.payload.db.attachments.filter((row) => {
        const cipherId = String(row.cipher_id || '').trim();
        const attachmentId = String(row.id || '').trim();
        if (!cipherId || !attachmentId) return false;
        return !oversizedAttachmentPaths.has(`attachments/${cipherId}/${attachmentId}.bin`);
      });

      const nextPayload: BackupPayload = {
        ...parsed.payload,
        db: {
          ...parsed.payload.db,
          attachments: nextAttachments,
        },
      };

      const needsKvBlobStorage = nextAttachments.length > 0;

      if (needsKvBlobStorage && !env.ATTACHMENTS_KV) {
        throw new Error('Backup restore requires ATTACHMENTS_KV when using KV blob storage');
      }

      prepared = {
        payload: nextPayload,
        skipped: {
          reason: skippedItems.length ? KV_BLOB_SKIP_REASON : null,
          attachments: skippedItems.length,
          items: skippedItems,
        },
      };
    }
  }
  const report = (step: string, stage: string, outcome: Pick<BackupRestoreProgressEvent, 'done' | 'ok' | 'error'> = {}) => progress?.({
    source: restoreSource,
    step: `${restoreSource}_${step}`,
    fileName,
    stageTitle: `txt_backup_restore_progress_${restoreSource}_${stage}_title`,
    stageDetail: `txt_backup_restore_progress_${restoreSource}_${stage}_detail`,
    replaceExisting,
    ...outcome,
  });
  const orm = getOrm(env.DB);

  try {
    const counts = await Promise.all([
      orm.select({ count: count() }).from(ciphers),
      orm.select({ count: count() }).from(folders),
      orm.select({ count: count() }).from(attachments),
      orm.select({ count: count() }).from(sends),
    ]);
    const total = counts.reduce((sum, rows) => sum + Number(rows[0]?.count || 0), 0);
    if (total > 0) {
      throw new Error('Backup import requires a fresh instance with no vault or send data');
    }
  } catch (error) {
    if (!replaceExisting) {
      throw error instanceof Error ? error : new Error('Backup import requires a fresh instance');
    }
  }

  await resetRestoreArtifacts(env.DB);
  const previousBlobKeys = replaceExisting ? await collectCurrentBlobKeys(env.DB) : new Set<string>();
  try {
    await report('create_shadow', 'shadow');
    const createStatements: string[] = [];
    for (const table of BACKUP_TABLE_NAMES) {
      const [row] = await orm.select({ sql: sqliteMaster.sql }).from(sqliteMaster)
        .where(and(eq(sqliteMaster.type, 'table'), eq(sqliteMaster.name, table))).limit(1);
      const createSql = String(row?.sql || '').trim();
      if (!createSql) {
        throw new Error(`Restore shadow schema is missing table definition for ${table}`);
      }
      // Rename the copy and point its foreign keys at the other shadow tables.
      const tablePattern = new RegExp(`^CREATE TABLE(?:\\s+IF NOT EXISTS)?\\s+(?:\"${table}\"|\`${table}\`|${table})(?=\\s*\\()`, 'i');
      let shadowSql = createSql.replace(tablePattern, `CREATE TABLE "${shadowTableName(table)}"`);
      if (shadowSql === createSql) {
        throw new Error(`Restore shadow schema could not rewrite CREATE TABLE statement for ${table}`);
      }
      for (const currentTable of BACKUP_TABLE_NAMES) {
        const referencePattern = new RegExp(`\\bREFERENCES\\s+(?:\"${currentTable}\"|\`${currentTable}\`|${currentTable})(?=\\s*\\()`, 'gi');
        shadowSql = shadowSql.replace(
          referencePattern,
          `REFERENCES "${shadowTableName(currentTable)}"`
        );
      }
      createStatements.push(shadowSql);
    }
    // eslint-disable-next-line nodewarden/no-raw-sql -- shadow DDL is rewritten at runtime from the live tables' sqlite_master text
    await env.DB.batch(createStatements.map((statement) => env.DB.prepare(statement)));
    await report('import_data', 'data');
    let configRows = cloneRows(prepared.payload.db.config).filter(
      (row) => String(row.key || '').trim() !== YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY
    );
    const rawBackupSettings = configRows.find((row) => String(row.key || '').trim() === BACKUP_SETTINGS_CONFIG_KEY);
    const normalizedBackupSettings = await normalizeImportedBackupSettingsValue(
      typeof rawBackupSettings?.value === 'string' ? rawBackupSettings.value : null,
      env,
      prepared.payload.db.users.map((row) => ({
        id: String(row.id || '').trim(),
        publicKey: typeof row.public_key === 'string' ? row.public_key : null,
        role: String(row.role || '').trim() as User['role'],
        status: String(row.status || '').trim() as User['status'],
      })),
      'UTC'
    );
    if (normalizedBackupSettings !== null) {
      configRows = upsertConfigRow(configRows, BACKUP_SETTINGS_CONFIG_KEY, normalizedBackupSettings);
    }
    configRows = upsertConfigRow(configRows, 'registered', 'true');
    // Imported preferences must survive a later baseline replay, including archives without this marker.
    configRows = upsertConfigRow(configRows, 'migration.verify-devices-on', '1');
    const db: BackupPayload['db'] = {
      config: configRows,
      users: cloneRows(prepared.payload.db.users).map((row) => ({
        ...row,
        email_verified: row.email_verified ?? 1,
        verify_devices: row.verify_devices ?? 0,
        yubikey_nfc: row.yubikey_nfc ?? 0,
      })),
      domain_settings: cloneRows(prepared.payload.db.domain_settings),
      user_revisions: cloneRows(prepared.payload.db.user_revisions),
      // Archives from before passkey purposes hold login passkeys only.
      webauthn_credentials: cloneRows(prepared.payload.db.webauthn_credentials).map((row) => ({
        ...row,
        purpose: row.purpose == null ? 'login' : String(row.purpose).trim() === 'twoFactor' ? 'twoFactor' : 'login',
      })),
      folders: cloneRows(prepared.payload.db.folders),
      ciphers: cloneRows(prepared.payload.db.ciphers).map((row) => ({
        ...row,
        archived_at: row.archived_at ?? null,
      })),
      attachments: cloneRows(prepared.payload.db.attachments),
    };
    await restoreRows(env.DB, 'config', ['key', 'value'], db.config, true);
    await restoreRows(
      env.DB,
      'users',
      ['id', 'email', 'email_verified', 'name', 'master_password_hint', 'master_password_hash', 'key', 'private_key', 'public_key', 'kdf_type', 'kdf_iterations', 'kdf_memory', 'kdf_parallelism', 'security_stamp', 'role', 'status', 'verify_devices', 'totp_secret', 'totp_recovery_code', 'two_factor_email', 'yubikey_key1', 'yubikey_key2', 'yubikey_key3', 'yubikey_key4', 'yubikey_key5', 'yubikey_nfc', 'created_at', 'updated_at'],
      db.users
    );
    await restoreRows(env.DB, 'user_revisions', ['user_id', 'revision_date'], db.user_revisions, true);
    await restoreRows(
      env.DB,
      'domain_settings',
      ['user_id', 'equivalent_domains', 'custom_equivalent_domains', 'excluded_global_equivalent_domains', 'updated_at'],
      db.domain_settings,
      true
    );
    await restoreRows(
      env.DB,
      'webauthn_credentials',
      ['id', 'user_id', 'purpose', 'name', 'public_key', 'credential_id', 'counter', 'type', 'aa_guid', 'transports', 'encrypted_user_key', 'encrypted_public_key', 'encrypted_private_key', 'supports_prf', 'created_at', 'updated_at'],
      db.webauthn_credentials
    );
    await restoreRows(env.DB, 'folders', ['id', 'user_id', 'name', 'created_at', 'updated_at'], db.folders);
    await restoreRows(
      env.DB,
      'ciphers',
      ['id', 'user_id', 'type', 'folder_id', 'name', 'notes', 'favorite', 'data', 'reprompt', 'key', 'created_at', 'updated_at', 'archived_at', 'deleted_at'],
      db.ciphers
    );
    await restoreRows(env.DB, 'attachments', ['id', 'cipher_id', 'file_name', 'size', 'size_name', 'key'], db.attachments);
    await validateShadowTableCounts(env.DB, {
      config: db.config.length,
      users: db.users.length,
      domain_settings: db.domain_settings.length,
      user_revisions: db.user_revisions.length,
      webauthn_credentials: db.webauthn_credentials.length,
      folders: db.folders.length,
      ciphers: db.ciphers.length,
      attachments: db.attachments.length,
    });

    await report('restore_files', 'files');
    // Store each attachment blob; a row whose blob is missing or cannot be stored is skipped.
    const restoredAttachments: SqlRow[] = [];
    const restoreSkippedItems: BackupImportSkipSummary['items'] = [];
    if (source) {
      const manifestLookup = buildAttachmentBlobLookup(prepared.payload.manifest);
      for (const row of prepared.payload.db.attachments) {
        const cipherId = String(row.cipher_id || '').trim();
        const attachmentId = String(row.id || '').trim();
        const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;
        const ref = manifestLookup.get(`${cipherId}/${attachmentId}`);
        if (!ref && !parsed.files[inlinePath]) {
          restoreSkippedItems.push({
            kind: 'attachment',
            path: `attachments/${cipherId}/${attachmentId}`,
            sizeBytes: Number(row.size || 0) || 0,
          });
          continue;
        }
        const bytes = parsed.files[inlinePath] || (ref ? await source.loadAttachment(ref.blobName) : null);
        if (!bytes) {
          restoreSkippedItems.push({
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
          restoreSkippedItems.push({
            kind: 'attachment',
            path: ref ? `attachments/${ref.blobName}` : inlinePath,
            sizeBytes: bytes.byteLength,
          });
        }
      }
    } else {
      for (const row of db.attachments) {
        const cipherId = String(row.cipher_id || '').trim();
        const attachmentId = String(row.id || '').trim();
        if (!cipherId || !attachmentId) continue;
        const key = `attachments/${cipherId}/${attachmentId}.bin`;
        const bytes = parsed.files[key];
        if (!bytes) {
          restoreSkippedItems.push({
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
          restoreSkippedItems.push({
            kind: 'attachment',
            path: key,
            sizeBytes: bytes.byteLength,
          });
        }
      }
    }
    const restored: AttachmentRestoreResult = {
      imported: restoredAttachments.length,
      restoredAttachments,
      skipped: {
        reason: restoreSkippedItems.length ? ATTACHMENT_RESTORE_FAILED_REASON : null,
        attachments: restoreSkippedItems.length,
        items: restoreSkippedItems,
      },
    };
    const restoredAttachmentKeys = new Set(restored.restoredAttachments.map(attachmentRowKey));
    const failedRestoreRows = db.attachments.filter((row) => !restoredAttachmentKeys.has(attachmentRowKey(row)));
    // Drop the staged rows of attachments whose blobs were not restored. A failed drop is left to the
    // count validation below, which then rejects the restore.
    try {
      const staged = shadowTable(attachments);
      const drops = failedRestoreRows.flatMap((row) => {
        const attachmentId = String(row.id || '').trim();
        const cipherId = String(row.cipher_id || '').trim();
        return attachmentId && cipherId ? [orm.delete(staged).where(and(eq(staged.id, attachmentId), eq(staged.cipherId, cipherId)))] : [];
      });
      if (drops.length) {
        await orm.batch(drops as [typeof drops[0], ...typeof drops]);
      }
    } catch {
      // Reported by the count validation below.
    }
    await validateShadowTableCounts(env.DB, {
      config: db.config.length,
      users: db.users.length,
      domain_settings: db.domain_settings.length,
      user_revisions: db.user_revisions.length,
      webauthn_credentials: db.webauthn_credentials.length,
      folders: db.folders.length,
      ciphers: db.ciphers.length,
      attachments: restored.restoredAttachments.length,
    });
    await report('finalize', 'finalize');
    // Commit by replacing live table contents from validated shadow tables.
    // This avoids D1 schema-rename edge cases while keeping current data intact
    // until the final batch succeeds.
    const swap = [
      ...[attachments, ciphers, folders, webauthnCredentials, domainSettings, userRevisions, users, config].map((table) => orm.delete(table)),
      // Copies by column name, not SELECT *: a live table's physical column order can differ from its
      // schema order (users does), so a positional copy under drizzle's column list would misplace values.
      ...Object.values(BACKUP_TABLES).map(<T extends SQLiteTable>(live: T) => orm.insert(live).select(orm.select().from(shadowTable(live)))),
    ];
    await orm.batch(swap as [typeof swap[0], ...typeof swap]);
    await syncVaultAdminRoles(env);
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    if (replaceExisting && previousBlobKeys.size) {
      const nextBlobKeys = await collectCurrentBlobKeys(env.DB).catch(() => null);
      if (nextBlobKeys) {
        // Deleting orphaned blobs is best effort: the restore has already committed.
        try {
          for (const key of Array.from(previousBlobKeys).filter((blobKey) => !nextBlobKeys.has(blobKey))) {
            await deleteBlobObject(env, key);
          }
        } catch {
          // An orphaned blob only costs storage.
        }
      }
    }

    await report('complete', 'finalize', { done: true, ok: true });
    return {
      auditActorUserId: db.users.some((row) => String(row.id || '').trim() === actorUserId) ? actorUserId : null,
      result: {
        object: 'instance-backup-import',
        imported: {
          config: db.config.length,
          users: db.users.length,
          domainSettings: db.domain_settings.length,
          userRevisions: db.user_revisions.length,
          webauthnCredentials: db.webauthn_credentials.length,
          folders: db.folders.length,
          ciphers: db.ciphers.length,
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
    await report('failed', 'finalize', { done: true, ok: false, error: error instanceof Error ? error.message : String(error) });
    await resetRestoreArtifacts(env.DB).catch(() => undefined);
    throw error;
  }
}
