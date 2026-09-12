import { zipSync, unzipSync, type UnzipFileInfo } from 'fflate';
import type { Env } from '../types';
import { APP_VERSION } from '../../shared/app-version';
import { BACKUP_SETTINGS_CONFIG_KEY } from './backup-config';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY } from './yubico-config';
import { exportPortableBackupSettingsEnvelope } from './backup-settings-crypto';
import {
  getAttachmentObjectKey,
  getBlobStorageKind,
  getBlobObject,
} from './blob-store';

// CONTRACT:
// This file defines the exported instance-backup archive shape. Keep it in lock
// step with src/services/backup-import.ts and webapp/src/lib/api/backup.ts.
//
// WHEN CHANGING THIS:
// - Add persistent tables to BackupPayload, export SQL, manifest tableCounts,
//   and validateBackupPayloadContents().
// - Keep secrets and transient runtime rows sanitized before writing db.json.
// - Runtime authentication state (devices, sessions, auth requests, remembered
//   2FA devices, and one-time tokens) must never enter an instance backup.
// - users.api_key is intentionally not exported.
// - backup.settings.v1 is exported as portable-only; the current server runtime
//   envelope must not leave the instance.
type SqlRow = Record<string, string | number | null>;

const BACKUP_FORMAT_VERSION = 1;
const BACKUP_RUNNER_LOCK_CONFIG_KEY = 'backup.runner.lock.v1';
const BACKUP_FILE_HASH_PREFIX_LENGTH = 5;
// Worker-side backup export must stay well below Cloudflare CPU limits.
// Prefer store-only ZIP entries over heavier compression to keep exports reliable.
const BACKUP_TEXT_COMPRESSION_LEVEL = 0;
const BACKUP_JSON_INDENT = 2;
export const MAX_BACKUP_ARCHIVE_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_ARCHIVE_ENTRY_COUNT = 10_000;
const MAX_BACKUP_EXTRACTED_BYTES = 64 * 1024 * 1024;
const MAX_BACKUP_DB_JSON_BYTES = 32 * 1024 * 1024;
const MAX_BACKUP_PATH_SEGMENT_LENGTH = 128;
/**
 * 内联导出（本地下载 zip）时，`db.json` + 全部附件解压后的**总字节**上限。
 *
 * 内联导出会把每个附件整块读进内存，`zipSync` 再产出等大的一份，
 * 峰值内存约为该总量的 **2 倍**；Worker 每 isolate 内存上限 128 MB，
 * 因此取 32 MiB（峰值 ≈ 64 MiB），为同 isolate 内的其他数据留出一半余量。
 *
 * 注意：这**收紧了**原先的实际能力（旧代码按附件 ≤ 64 MiB 放行，峰值可达 128 MB）。
 * 要放宽只需调大写这里的值，但必须同时复核峰值内存 ≈ 2 倍总量。
 */
const MAX_BACKUP_INLINE_TOTAL_BYTES = 32 * 1024 * 1024;

export interface BackupManifest {
  formatVersion: 1;
  exportedAt: string;
  appVersion: string;
  storageKind: 'r2' | 'kv' | null;
  tableCounts: Record<string, number>;
  includes: {
    attachments: boolean;
  };
  blobSummary: {
    attachmentFiles: number;
    totalBytes: number;
    largestObjectBytes: number;
  };
  attachmentBlobs?: BackupManifestAttachmentBlob[];
}

export interface BackupManifestAttachmentBlob {
  cipherId: string;
  attachmentId: string;
  blobName: string;
  sizeBytes: number;
}

export interface BackupPayload {
  manifest: BackupManifest;
  db: {
    config: SqlRow[];
    users: SqlRow[];
    domain_settings: SqlRow[];
    user_revisions: SqlRow[];
    folders: SqlRow[];
    ciphers: SqlRow[];
    attachments: SqlRow[];
    webauthn_credentials?: SqlRow[];
  };
}

export interface BackupArchiveBundle {
  bytes: Uint8Array;
  fileName: string;
  manifest: BackupManifest;
}

export interface BackupFileIntegrityCheckResult {
  hasChecksumPrefix: boolean;
  expectedPrefix: string | null;
  actualPrefix: string;
  matches: boolean;
}

export interface BuildBackupArchiveOptions {
  includeAttachments?: boolean;
  /**
   * 把附件 blob 内联进归档（zip 内 `attachments/<cipherId>/<attachmentId>.bin`）。
   *
   * 默认为 false，因为**远端备份依赖外部增量上传**：`handlers/backup.ts` 用
   * `manifest.attachmentBlobs` 枚举待上传项、按 size 与远端已有对象比对去重，
   * 附件字节**不**进归档。若默认内联，会破坏该设计并把附件重复存一份。
   *
   * 本地导出（用户下载 zip）必须置 true —— 否则归档声称 `includes.attachments: true`
   * 却没有任何附件字节，且会被本地导入以 `missing required file` 拒绝。
   */
  inlineAttachmentBlobs?: boolean;
  progress?: BackupArchiveBuildProgressReporter;
  timeZone?: string;
}

export interface BackupArchiveBuildProgressEvent {
  step: string;
  fileName?: string;
  stageTitle: string;
  stageDetail: string;
  includeAttachments: boolean;
}

export type BackupArchiveBuildProgressReporter = (event: BackupArchiveBuildProgressEvent) => Promise<void>;

async function queryRows(db: D1Database, sql: string, ...values: unknown[]): Promise<SqlRow[]> {
  const result = await db.prepare(sql).bind(...values).all<SqlRow>();
  return (result.results || []).map((row) => ({ ...row }));
}

function sanitizeConfigRowsForExport(rows: SqlRow[]): SqlRow[] {
  const sanitized: SqlRow[] = [];
  for (const row of rows) {
    const key = String(row.key || '').trim();
    if (!key || key === BACKUP_RUNNER_LOCK_CONFIG_KEY || key === YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY) continue;

    if (key === BACKUP_SETTINGS_CONFIG_KEY) {
      const portableOnly = exportPortableBackupSettingsEnvelope(typeof row.value === 'string' ? row.value : null);
      if (portableOnly) sanitized.push({ ...row, value: portableOnly });
      continue;
    }

    sanitized.push({ ...row });
  }
  return sanitized;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function getDateParts(date: Date, timeZone: string): string {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  return `${pick('year')}${pick('month')}${pick('day')}_${pick('hour')}${pick('minute')}${pick('second')}`;
}

function buildBackupFileNameInTimeZone(
  date: Date = new Date(),
  checksumPrefix: string | null = null,
  timeZone: string = 'UTC'
): string {
  const parts = getDateParts(date, timeZone);
  const suffix = checksumPrefix ? `_${checksumPrefix}` : '';
  return `nodewarden_backup_${parts}${suffix}.zip`;
}

export function extractBackupFileChecksumPrefix(fileName: string): string | null {
  const normalized = String(fileName || '').trim();
  const match = normalized.match(/_([0-9a-f]{5})\.zip$/i);
  return match ? match[1].toLowerCase() : null;
}

export async function inspectBackupArchiveFileNameChecksum(
  bytes: Uint8Array,
  fileName: string
): Promise<BackupFileIntegrityCheckResult> {
  const expectedPrefix = extractBackupFileChecksumPrefix(fileName);
  const actualHash = await sha256Hex(bytes);
  const actualPrefix = actualHash.slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  return {
    hasChecksumPrefix: !!expectedPrefix,
    expectedPrefix,
    actualPrefix,
    matches: !expectedPrefix || actualPrefix === expectedPrefix,
  };
}

export async function verifyBackupArchiveFileNameChecksum(bytes: Uint8Array, fileName: string): Promise<boolean> {
  const result = await inspectBackupArchiveFileNameChecksum(bytes, fileName);
  return result.matches;
}

function validateArchiveSize(bytes: Uint8Array): void {
  if (bytes.byteLength > MAX_BACKUP_ARCHIVE_BYTES) {
    throw new Error(`Backup archive is too large. The current restore limit is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))} MiB`);
  }
}

function isSafeBackupPathSegment(value: string): boolean {
  if (!value || value.length > MAX_BACKUP_PATH_SEGMENT_LENGTH) return false;
  if (value === '.' || value === '..') return false;
  return /^[A-Za-z0-9._-]+$/.test(value);
}

export function isSafeBackupAttachmentBlobName(value: unknown): boolean {
  const normalized = String(value ?? '').trim();
  const parts = normalized.split('/');
  return parts.length === 2 && parts.every(isSafeBackupPathSegment);
}

function isSafeBackupAttachmentEntryName(value: string): boolean {
  if (!value.startsWith('attachments/') || !value.endsWith('.bin')) return false;
  const relative = value.slice('attachments/'.length, -'.bin'.length);
  return isSafeBackupAttachmentBlobName(relative);
}

function validateBackupEntryName(name: string): void {
  const normalized = String(name || '').trim();
  if (normalized !== name || !normalized) {
    throw new Error('Backup archive contains an invalid file name');
  }
  if (normalized.includes('\\') || normalized.includes('\0') || normalized.startsWith('/') || normalized.includes('//')) {
    throw new Error(`Backup archive contains an unsafe file name: ${normalized}`);
  }
  if (normalized !== 'manifest.json' && normalized !== 'db.json' && !isSafeBackupAttachmentEntryName(normalized)) {
    throw new Error(`Backup archive contains an unsupported file: ${normalized}`);
  }
}

function createBackupUnzipFilter(): (file: UnzipFileInfo) => boolean {
  let entryCount = 0;
  let totalOriginalBytes = 0;
  return (file: UnzipFileInfo): boolean => {
    entryCount += 1;
    if (entryCount > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
      throw new Error('Backup archive contains too many files');
    }
    validateBackupEntryName(file.name);
    const originalSize = Number(file.originalSize);
    if (!Number.isFinite(originalSize) || originalSize < 0) {
      throw new Error(`Backup archive contains an invalid file size: ${file.name}`);
    }
    if (file.name === 'db.json' && originalSize > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    totalOriginalBytes += originalSize;
    if (totalOriginalBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
    return true;
  };
}

function getRequiredZipEntries(db: BackupPayload['db']): string[] {
  const entries: string[] = [];
  for (const row of db.attachments) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    if (!cipherId || !attachmentId) continue;
    entries.push(`attachments/${cipherId}/${attachmentId}.bin`);
  }
  return entries;
}

function ensureRowArray(value: unknown, table: string): SqlRow[] {
  if (!Array.isArray(value)) {
    throw new Error(`Backup archive table ${table} is invalid`);
  }
  return value as SqlRow[];
}

function normalizeParsedBackupDb(value: unknown): BackupPayload['db'] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Backup archive database payload is invalid');
  }
  const source = value as Record<string, unknown>;
  // Restore uses an explicit allowlist. Extra tables from old or modified
  // archives, especially runtime authentication state, are intentionally ignored.
  return {
    config: source.config as SqlRow[],
    users: source.users as SqlRow[],
    domain_settings: source.domain_settings as SqlRow[],
    user_revisions: source.user_revisions as SqlRow[],
    folders: source.folders as SqlRow[],
    ciphers: source.ciphers as SqlRow[],
    attachments: source.attachments as SqlRow[],
    webauthn_credentials: source.webauthn_credentials as SqlRow[] | undefined,
  };
}

function createZipEntries(files: Record<string, Uint8Array>): Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> {
  const entries: Record<string, Uint8Array | [Uint8Array, { level: 0 | 1 | 6 }]> = {};
  for (const [path, bytes] of Object.entries(files)) {
    entries[path] = [bytes, { level: BACKUP_TEXT_COMPRESSION_LEVEL }];
  }
  return entries;
}

/**
 * 归档声明含附件、但附件字节存放在远端 —— 这是**远端备份的正常形态**（见
 * `BuildBackupArchiveOptions.inlineAttachmentBlobs`：远端依赖单独增量上传）。
 *
 * 本地导入要求附件内联，因此这种归档必然无法本地恢复。此时给出**可操作**的提示，
 * 而不是通用的 `missing required file`（后者无法告诉用户该怎么办）。
 *
 * 该文案已接入前端 i18n 映射表（`webapp/src/lib/i18n.ts` →
 * `txt_backup_error_archive_missing_attachment_files`）；修改文案时必须同步更新映射表。
 */
const MISSING_ATTACHMENT_FILES_MESSAGE =
  'Backup archive has no attachment files; restore it from the remote destination instead';

/**
 * 内联导出体积超限的文案前缀。
 *
 * 完整文案带具体字节数（数字随体积变化），无法用精确查表本地化，
 * 因此前端用「前缀 + 数字」正则匹配（`webapp/src/lib/i18n.ts` →
 * `txt_backup_error_archive_export_too_large`）；修改前缀时必须同步更新该正则。
 */
export const TOO_LARGE_TO_EXPORT_MESSAGE_PREFIX = 'Backup archive is too large to export';

/**
 * 内联导出时附件允许占用的字节预算（`db.json` 已从总量上限中扣除）。
 *
 * 必须**同时**满足两条约束，缺一就会产出「导出成功、但本地导入必然失败」的归档：
 * 1. **内存**：内联导出的峰值内存约为「解压后总量」的 2 倍，见 `MAX_BACKUP_INLINE_TOTAL_BYTES`；
 * 2. **可恢复性**：恢复侧按「所有条目解压后总字节」判定上限，见 `createBackupUnzipFilter`。
 *
 * 返回值可能为负：说明 `db.json` 自身已超出恢复侧的**单条目**上限
 * （`MAX_BACKUP_DB_JSON_BYTES`），此时任何附件都不允许内联。
 */
export function resolveInlineAttachmentBudgetBytes(dbPayloadBytes: number): number {
  return (
    Math.min(MAX_BACKUP_INLINE_TOTAL_BYTES, MAX_BACKUP_EXTRACTED_BYTES) - Math.max(0, dbPayloadBytes)
  );
}

/**
 * 由 manifest 声明的「外部附件」路径集合。
 *
 * 注意：这里**不看** `allowExternalAttachmentBlobs` —— 目的是区分「归档形态是远端元数据式」
 * 与「归档真的损坏了」。前者应给出可操作提示，后者才是通用报错。
 */
function declaredAttachmentBlobPaths(manifest: BackupManifest): Set<string> {
  return new Set(
    (manifest.attachmentBlobs || []).map(
      (item) =>
        `attachments/${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}.bin`
    )
  );
}

export interface ParseBackupArchiveOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function parseBackupArchive(
  bytes: Uint8Array,
  options: ParseBackupArchiveOptions = {}
): { payload: BackupPayload; files: Record<string, Uint8Array> } {
  validateArchiveSize(bytes);
  let zipped: Record<string, Uint8Array>;
  try {
    zipped = unzipSync(bytes, { filter: createBackupUnzipFilter() });
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('Backup archive ')) {
      throw error;
    }
    throw new Error('Invalid backup archive');
  }

  const entryNames = Object.keys(zipped);
  if (entryNames.length > MAX_BACKUP_ARCHIVE_ENTRY_COUNT) {
    throw new Error('Backup archive contains too many files');
  }

  let totalExtractedBytes = 0;
  for (const entry of entryNames) {
    validateBackupEntryName(entry);
    const entryBytes = zipped[entry];
    totalExtractedBytes += entryBytes.byteLength;
    if (entry === 'db.json' && entryBytes.byteLength > MAX_BACKUP_DB_JSON_BYTES) {
      throw new Error('Backup archive database payload is too large');
    }
    if (totalExtractedBytes > MAX_BACKUP_EXTRACTED_BYTES) {
      throw new Error('Backup archive expands beyond the current restore limit');
    }
  }

  const manifestBytes = zipped['manifest.json'];
  const dbBytes = zipped['db.json'];
  if (!manifestBytes || !dbBytes) {
    throw new Error('Backup archive is missing manifest.json or db.json');
  }

  const decoder = new TextDecoder();
  let manifest: BackupManifest;
  let rawDb: unknown;
  try {
    manifest = JSON.parse(decoder.decode(manifestBytes)) as BackupManifest;
    rawDb = JSON.parse(decoder.decode(dbBytes));
  } catch {
    throw new Error('Backup archive contains invalid JSON metadata');
  }

  if (manifest?.formatVersion !== BACKUP_FORMAT_VERSION) {
    throw new Error('Unsupported backup format version');
  }
  const db = normalizeParsedBackupDb(rawDb);

  const declaredBlobs = declaredAttachmentBlobPaths(manifest);
  // 只读集合（下面只用 `.has()`），因此可以直接复用同一个实例，不必再复制一层
  const externalAttachmentKeys = options.allowExternalAttachmentBlobs ? declaredBlobs : new Set<string>();
  const requiredEntries = getRequiredZipEntries(db).filter((entry) => !externalAttachmentKeys.has(entry));
  for (const entry of requiredEntries) {
    if (!zipped[entry]) {
      // 声明含附件却没内联 → 远端形态的归档，不是损坏；提示用户改用「从远端恢复」
      if (declaredBlobs.has(entry)) throw new Error(MISSING_ATTACHMENT_FILES_MESSAGE);
      throw new Error(`Backup archive is missing required file: ${entry}`);
    }
  }

  return {
    payload: { manifest, db },
    files: zipped,
  };
}

export interface ValidateBackupPayloadOptions {
  allowExternalAttachmentBlobs?: boolean;
}

export function validateBackupPayloadContents(
  payload: BackupPayload,
  files: Record<string, Uint8Array>,
  options: ValidateBackupPayloadOptions = {}
): void {
  const configRows = ensureRowArray(payload.db.config, 'config');
  const userRows = ensureRowArray(payload.db.users, 'users');
  const revisionRows = ensureRowArray(payload.db.user_revisions, 'user_revisions');
  const domainSettingsRows = ensureRowArray(payload.db.domain_settings || [], 'domain_settings');
  const folderRows = ensureRowArray(payload.db.folders, 'folders');
  const cipherRows = ensureRowArray(payload.db.ciphers, 'ciphers');
  const attachmentRows = ensureRowArray(payload.db.attachments, 'attachments');
  const accountPasskeyRows = ensureRowArray(payload.db.webauthn_credentials || [], 'webauthn_credentials');
  const declaredBlobs = declaredAttachmentBlobPaths(payload.manifest);
  // 同 parseBackupArchive：只读集合，直接复用
  const externalAttachmentKeys = options.allowExternalAttachmentBlobs ? declaredBlobs : new Set<string>();

  const userIds = new Set<string>();
  for (const row of userRows) {
    const id = String(row.id || '').trim();
    const email = String(row.email || '').trim();
    if (!id || !email) throw new Error('Backup archive contains an invalid user row');
    if (userIds.has(id)) throw new Error(`Backup archive contains duplicate user id: ${id}`);
    userIds.add(id);
  }

  for (const row of configRows) {
    const key = String(row.key || '').trim();
    if (!key) throw new Error('Backup archive contains an invalid config row');
  }

  for (const row of revisionRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains a revision for an unknown user: ${userId || '(empty)'}`);
    }
  }

  const domainSettingUserIds = new Set<string>();
  for (const row of domainSettingsRows) {
    const userId = String(row.user_id || '').trim();
    if (!userId || !userIds.has(userId)) {
      throw new Error(`Backup archive contains domain settings for an unknown user: ${userId || '(empty)'}`);
    }
    if (domainSettingUserIds.has(userId)) {
      throw new Error(`Backup archive contains duplicate domain settings for user: ${userId}`);
    }
    domainSettingUserIds.add(userId);
  }

  const folderIds = new Set<string>();
  for (const row of folderRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid folder row');
    if (folderIds.has(id)) throw new Error(`Backup archive contains duplicate folder id: ${id}`);
    folderIds.add(id);
  }

  const cipherIds = new Set<string>();
  for (const row of cipherRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const folderId = String(row.folder_id || '').trim();
    if (!id || !userIds.has(userId)) throw new Error('Backup archive contains an invalid cipher row');
    if (folderId && !folderIds.has(folderId)) {
      throw new Error(`Backup archive contains a cipher for an unknown folder: ${folderId}`);
    }
    if (cipherIds.has(id)) throw new Error(`Backup archive contains duplicate cipher id: ${id}`);
    cipherIds.add(id);
  }

  for (const row of attachmentRows) {
    const id = String(row.id || '').trim();
    const cipherId = String(row.cipher_id || '').trim();
    if (!id || !cipherId || !isSafeBackupPathSegment(id) || !isSafeBackupPathSegment(cipherId) || !cipherIds.has(cipherId)) {
      throw new Error('Backup archive contains an invalid attachment row');
    }
    const attachmentPath = `attachments/${cipherId}/${id}.bin`;
    if (!files[attachmentPath] && !externalAttachmentKeys.has(attachmentPath)) {
      if (declaredBlobs.has(attachmentPath)) throw new Error(MISSING_ATTACHMENT_FILES_MESSAGE);
      throw new Error(`Backup archive is missing required file: attachments/${cipherId}/${id}.bin`);
    }
  }

  const accountPasskeyIds = new Set<string>();
  const accountPasskeyCredentialIds = new Set<string>();
  for (const row of accountPasskeyRows) {
    const id = String(row.id || '').trim();
    const userId = String(row.user_id || '').trim();
    const purpose = row.purpose == null ? 'login' : String(row.purpose || '').trim();
    const credentialId = String(row.credential_id || '').trim();
    const publicKey = String(row.public_key || '').trim();
    if (!id || !userIds.has(userId) || !credentialId || !publicKey || (purpose !== 'login' && purpose !== 'twoFactor')) {
      throw new Error('Backup archive contains an invalid account passkey row');
    }
    if (accountPasskeyIds.has(id)) throw new Error(`Backup archive contains duplicate account passkey id: ${id}`);
    if (accountPasskeyCredentialIds.has(credentialId)) throw new Error(`Backup archive contains duplicate account passkey credential id: ${credentialId}`);
    accountPasskeyIds.add(id);
    accountPasskeyCredentialIds.add(credentialId);
  }

}

export async function buildBackupArchive(
  env: Env,
  date: Date = new Date(),
  options: BuildBackupArchiveOptions = {}
): Promise<BackupArchiveBundle> {
  const includeAttachments = options.includeAttachments !== false;
  await options.progress?.({
    step: 'collect_data',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_collect_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_collect_with_attachments_detail'
      : 'txt_backup_archive_progress_collect_detail',
    includeAttachments,
  });
  const encoder = new TextEncoder();
  const [configRows, userRows, domainSettingsRows, revisionRows, folderRows, cipherRows, attachmentRows, accountPasskeyRows] = await Promise.all([
    queryRows(env.DB, 'SELECT key, value FROM config ORDER BY key ASC'),
    queryRows(env.DB, 'SELECT id, email, name, master_password_hint, master_password_hash, key, private_key, public_key, kdf_type, kdf_iterations, kdf_memory, kdf_parallelism, security_stamp, role, status, verify_devices, totp_secret, totp_recovery_code, yubikey_key1, yubikey_key2, yubikey_key3, yubikey_key4, yubikey_key5, yubikey_nfc, created_at, updated_at FROM users ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at FROM domain_settings ORDER BY user_id ASC'),
    queryRows(env.DB, 'SELECT user_id, revision_date FROM user_revisions ORDER BY user_id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, name, created_at, updated_at FROM folders ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at FROM ciphers ORDER BY created_at ASC'),
    queryRows(env.DB, 'SELECT id, cipher_id, file_name, size, size_name, key FROM attachments ORDER BY cipher_id ASC, id ASC'),
    queryRows(env.DB, 'SELECT id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at FROM webauthn_credentials ORDER BY created_at ASC'),
  ]);
  const exportedConfigRows = sanitizeConfigRowsForExport(configRows);
  const exportedAttachmentRows = includeAttachments ? attachmentRows : [];
  const attachmentBlobs: BackupManifestAttachmentBlob[] = exportedAttachmentRows.map((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    return {
      cipherId,
      attachmentId,
      blobName: getAttachmentObjectKey(cipherId, attachmentId),
      sizeBytes: Number(row.size || 0) || 0,
    };
  });

  const manifestBase = {
    formatVersion: BACKUP_FORMAT_VERSION,
    exportedAt: date.toISOString(),
    appVersion: APP_VERSION,
    storageKind: getBlobStorageKind(env),
    tableCounts: {
      config: exportedConfigRows.length,
      users: userRows.length,
      domain_settings: domainSettingsRows.length,
      user_revisions: revisionRows.length,
      folders: folderRows.length,
      ciphers: cipherRows.length,
      attachments: exportedAttachmentRows.length,
      webauthn_credentials: accountPasskeyRows.length,
    },
    includes: {
      attachments: includeAttachments,
    },
    blobSummary: {
      attachmentFiles: attachmentBlobs.length,
      totalBytes: attachmentBlobs.reduce((sum, item) => sum + item.sizeBytes, 0),
      largestObjectBytes: attachmentBlobs.reduce((max, item) => Math.max(max, item.sizeBytes), 0),
    },
    attachmentBlobs: includeAttachments ? attachmentBlobs : [],
  } satisfies BackupManifest;

  const files: Record<string, Uint8Array> = {
    'manifest.json': encoder.encode(JSON.stringify(manifestBase, null, BACKUP_JSON_INDENT)),
    'db.json': encoder.encode(JSON.stringify({
      config: exportedConfigRows,
      users: userRows,
      domain_settings: domainSettingsRows,
      user_revisions: revisionRows,
      folders: folderRows,
      ciphers: cipherRows,
      attachments: exportedAttachmentRows,
      webauthn_credentials: accountPasskeyRows,
    }, null, BACKUP_JSON_INDENT)),
  };

  await options.progress?.({
    step: 'package_archive',
    fileName: '',
    stageTitle: 'txt_backup_archive_progress_package_title',
    stageDetail: includeAttachments
      ? 'txt_backup_archive_progress_package_with_attachments_detail'
      : 'txt_backup_archive_progress_package_detail',
    includeAttachments,
  });

  if (includeAttachments && options.inlineAttachmentBlobs) {
    // 本地导出：把附件字节内联进归档，使 zip 自包含、可被本地导入恢复。
    // 远端备份不走这里（它依赖外部增量上传，见 BuildBackupArchiveOptions 注释）。
    //
    // 先做体积预检：预算必须同时扣掉 db.json（恢复侧按解压后**总**字节判定）并留出内存余量，
    // 否则会产出一个自家人无法恢复的备份。详见 resolveInlineAttachmentBudgetBytes。
    const dbPayloadBytes = files['db.json'].byteLength;
    const totalAttachmentBytes = attachmentBlobs.reduce((sum, item) => sum + item.sizeBytes, 0);
    const inlineBudgetBytes = resolveInlineAttachmentBudgetBytes(dbPayloadBytes);
    if (totalAttachmentBytes > inlineBudgetBytes) {
      throw new Error(
        `${TOO_LARGE_TO_EXPORT_MESSAGE_PREFIX}: ${dbPayloadBytes} database bytes plus ${totalAttachmentBytes} attachment bytes exceed the ${Math.max(0, inlineBudgetBytes)} byte budget`
      );
    }

    for (const item of attachmentBlobs) {
      const object = await getBlobObject(env, item.blobName);
      if (!object?.body) {
        // 措辞与 durable/backup-transfer-runner.ts 保持一致：handlers/backup.ts 依赖
        // 'blob missing' 子串把它映射为 409 而不是 500
        throw new Error(`Attachment blob missing for ${item.blobName}`);
      }
      files[`attachments/${item.cipherId}/${item.attachmentId}.bin`] = new Uint8Array(
        await new Response(object.body).arrayBuffer()
      );
    }
  }

  const bytes = zipSync(createZipEntries(files));
  const fileHashPrefix = (await sha256Hex(bytes)).slice(0, BACKUP_FILE_HASH_PREFIX_LENGTH);
  const backupTimeZone = options.timeZone || 'UTC';
  const fileName = buildBackupFileNameInTimeZone(date, fileHashPrefix, backupTimeZone);
  await options.progress?.({
    step: 'archive_ready',
    fileName,
    stageTitle: 'txt_backup_archive_progress_ready_title',
    stageDetail: 'txt_backup_archive_progress_ready_detail',
    includeAttachments,
  });

  return {
    bytes,
    fileName,
    manifest: manifestBase,
  };
}
