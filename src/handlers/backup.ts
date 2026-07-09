import type { Env, User } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import {
  type BackupArchiveBundle,
  MAX_BACKUP_ARCHIVE_BYTES,
  buildBackupArchive,
  inspectBackupArchiveFileNameChecksum,
  isSafeBackupAttachmentBlobName,
  parseBackupArchive,
  verifyBackupArchiveFileNameChecksum,
} from '../services/backup-archive';
import {
  type BackupDestinationRecord,
  type BackupSettingsInput,
  type BackupSettings,
  type WebDavBackupDestination,
  getBackupLocalDateKey,
  getDefaultBackupSettings,
  getBackupSettingsRepairState,
  loadBackupSettings,
  normalizeBackupSettingsInput,
  normalizeImportedBackupSettings,
  redactBackupSettingsSecrets,
  repairBackupSettings,
  requireBackupDestination,
  saveBackupSettings,
  updateBackupDestinationRuntime,
} from '../services/backup-config';
import {
  type BackupImportExecutionResult,
  type BackupRestoreProgressReporter,
  importBackupArchiveBytes,
  importRemoteBackupArchiveBytes,
} from '../services/backup-import';
import {
  type RemoteBackupTransferSession,
  type RemoteBackupFile,
  createRemoteBackupTransferSession,
  deleteRemoteBackupFile,
  downloadRemoteBackupFile,
  ensureRemoteRestoreCandidate,
  listRemoteBackupEntries,
  pruneRemoteBackupArchives,
  uploadBackupArchive,
} from '../services/backup-uploader';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { getBlobObject } from '../services/blob-store';
import { notifyUserBackupProgress, notifyUserBackupRestoreProgress } from '../durable/notifications-hub';
import { getMultipartRequestMaxBytes } from '../utils/direct-upload';
import { verifyPasskeyUserVerificationToken } from '../utils/user-verification-token';
import { unzipSync } from 'fflate';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

function parseRequestContentLength(request: Request): number | null {
  const raw = request.headers.get('content-length');
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.floor(value);
}

async function requireBackupUserVerification(actorUser: User, masterPasswordHash: string, env: Env): Promise<Response | null> {
  const normalized = String(masterPasswordHash || '').trim();
  if (!normalized) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const auth = new AuthService(env);
  const valid = await auth.verifyPassword(normalized, actorUser.masterPasswordHash, actorUser.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }
  return null;
}

async function requireBackupRepairVerification(
  actorUser: User,
  body: { masterPasswordHash?: string; userVerificationToken?: string },
  env: Env
): Promise<Response | null> {
  const masterPasswordHash = String(body.masterPasswordHash || '').trim();
  if (masterPasswordHash) {
    return requireBackupUserVerification(actorUser, masterPasswordHash, env);
  }

  const userVerificationToken = String(body.userVerificationToken || '').trim();
  if (!userVerificationToken) {
    return errorResponse('masterPasswordHash or userVerificationToken is required', 400);
  }
  const valid = await verifyPasskeyUserVerificationToken(env, userVerificationToken, actorUser.id, 'backup.settings.repair');
  if (!valid) {
    return errorResponse('Invalid user verification token', 400);
  }
  return null;
}

async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null,
  request?: Request
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId,
    action,
    targetType,
    targetId,
    category: 'data',
    level: action.endsWith('.failed') ? 'error' : 'info',
    metadata: {
      ...(metadata || {}),
      ...(request ? auditRequestMetadata(request) : {}),
    },
  });
}

function getBackupDestinationSummary(destination: BackupDestinationRecord | null): Record<string, unknown> {
  if (!destination) {
    return {
      destinationId: null,
      destinationName: null,
      destinationType: null,
    };
  }
  return {
    destinationId: destination.id,
    destinationName: destination.name,
    destinationType: destination.type,
  };
}

function ensureBackupBlobName(value: string): string {
  const normalized = String(value || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!normalized) {
    throw new Error('Backup attachment blob is required');
  }
  if (!isSafeBackupAttachmentBlobName(normalized)) {
    throw new Error('Backup attachment blob is invalid');
  }
  return normalized;
}

function contentDispositionBackup(fileName: string | null | undefined): string {
  const fallback = 'nodewarden_backup.zip';
  const value = String(fileName || fallback)
    .replace(/[\\/\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

const REMOTE_ATTACHMENT_INDEX_PATH = 'attachments/.nodewarden-attachment-index.v1.json';

interface RemoteAttachmentIndexPayload {
  version: 1;
  blobs: Record<string, { sizeBytes: number; updatedAt: string }>;
}

const REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT = 50;
const REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE = 6;
const REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE = 18;
const REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE = 40;
const REMOTE_ATTACHMENT_RESTORE_BATCH_SIZE = 40;

function countRemotePathSegments(value: string): number {
  return String(value || '').replace(/\\/g, '/').split('/').filter(Boolean).length;
}

function getRemoteAttachmentSyncBatchSize(destination: BackupDestinationRecord): number {
  if (destination.type === 's3') {
    return REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE;
  }

  const remotePath = String((destination.destination as WebDavBackupDestination).remotePath || '');
  const fixedWebDavDirectoryCalls = countRemotePathSegments(remotePath) + 1; // remotePath plus the shared "attachments" dir.
  const available = REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT
    - REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE
    - fixedWebDavDirectoryCalls;

  if (available < 2) {
    throw new Error('WebDAV remote backup path is too deep for safe attachment batching');
  }

  return Math.max(1, Math.min(
    REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE,
    Math.floor(available / 2)
  ));
}

async function loadRemoteAttachmentIndex(session: RemoteBackupTransferSession): Promise<Map<string, number>> {
  try {
    const file = await session.download(REMOTE_ATTACHMENT_INDEX_PATH);
    const payload = JSON.parse(new TextDecoder().decode(file.bytes)) as RemoteAttachmentIndexPayload;
    if (payload?.version !== 1 || !payload.blobs || typeof payload.blobs !== 'object') {
      return new Map<string, number>();
    }
    return new Map(
      Object.entries(payload.blobs)
        .filter(([key, value]) => !!String(key || '').trim() && Number.isFinite(Number(value?.sizeBytes || 0)))
        .map(([key, value]) => [key, Number(value.sizeBytes || 0)])
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const normalized = message.toLowerCase();
    // Some WebDAV providers return non-standard codes such as 530 when the
    // attachment index does not exist yet. Treat these "missing file" style
    // responses as an empty index so first-time incremental backups can proceed.
    if (
      normalized.includes('404')
      || normalized.includes('403')
      || normalized.includes('530')
      || normalized.includes('not found')
      || normalized.includes('file not found')
      || normalized.includes('does not exist')
      || normalized.includes('please select a backup file')
    ) {
      return new Map<string, number>();
    }
    throw error;
  }
}

async function saveRemoteAttachmentIndex(
  session: RemoteBackupTransferSession,
  index: Map<string, number>
): Promise<void> {
  const payload: RemoteAttachmentIndexPayload = {
    version: 1,
    blobs: Object.fromEntries(
      Array.from(index.entries()).map(([blobName, sizeBytes]) => [
        blobName,
        {
          sizeBytes,
          updatedAt: new Date().toISOString(),
        },
      ])
    ),
  };
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  await session.putFile(REMOTE_ATTACHMENT_INDEX_PATH, bytes, {
    contentType: 'application/json; charset=utf-8',
  });
}

async function uploadRemoteAttachmentChunk(
  env: Env,
  destination: BackupDestinationRecord,
  attachments: Array<{ blobName: string }>
): Promise<void> {
  if (!attachments.length) return;
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('remote-attachment-sync');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/upload-attachment-chunk', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      destination,
      attachments,
    }),
  });
  if (!response.ok) {
    let message = `Attachment sync failed: ${response.status}`;
    try {
      const payload = await response.json<{ error?: string }>();
      if (payload?.error) {
        message = payload.error;
      }
    } catch {
      // Ignore JSON parse failures and preserve the status-based error.
    }
    throw new Error(message);
  }
}

async function verifyUploadedBackupArchive(
  session: RemoteBackupTransferSession,
  archive: BackupArchiveBundle
): Promise<'metadata' | 'download'> {
  try {
    const stat = await session.stat(archive.fileName);
    if (stat?.size === archive.bytes.byteLength) {
      return 'metadata';
    }
  } catch {
    // Fall through to a full read-back verification when lightweight metadata is unavailable.
  }

  const remoteFile = await session.download(archive.fileName);
  const checksumOk = await verifyBackupArchiveFileNameChecksum(remoteFile.bytes, archive.fileName);
  if (!checksumOk) {
    throw new Error('Remote backup ZIP checksum verification failed');
  }
  if (remoteFile.bytes.byteLength !== archive.bytes.byteLength) {
    throw new Error('Remote backup ZIP size verification failed');
  }
  return 'download';
}

export async function executeConfiguredBackup(
  env: Env,
  storage: StorageService,
  actorUserId: string | null,
  trigger: 'manual' | 'scheduled',
  destinationId?: string | null,
  keepAlive?: (() => Promise<void>) | null,
  progress?: ((event: {
    operation: 'backup-remote-run';
    step: string;
    fileName: string;
    stageTitle: string;
    stageDetail: string;
    done?: boolean;
    ok?: boolean;
    error?: string | null;
  }) => Promise<void>) | null,
  auditMetadata?: Record<string, unknown> | null
): Promise<{ fileName: string; fileSize: number; remotePath: string; provider: string }> {
  const maxArchiveUploadAttempts = 3;
  const touchLease = async () => {
    await keepAlive?.();
  };
  const currentSettings = await loadBackupSettings(storage, env, 'UTC');
  const destination = requireBackupDestination(currentSettings, destinationId);

  const now = new Date();
  await touchLease();
  destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
    ...runtime,
    lastAttemptAt: now.toISOString(),
    lastAttemptLocalDate: getBackupLocalDateKey(now, destination.schedule.timezone),
    lastErrorAt: null,
    lastErrorMessage: null,
  }));

  try {
    await touchLease();
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_prepare',
      fileName: '',
      stageTitle: 'txt_backup_remote_run_progress_prepare_title',
      stageDetail: 'txt_backup_remote_run_progress_prepare_detail',
    });
    await touchLease();
    const archive = await buildBackupArchive(env, now, {
      includeAttachments: destination.includeAttachments,
      timeZone: destination.schedule.timezone,
      progress: progress
        ? async (event) => {
          if (event.step === 'archive_ready') {
            return;
          }
          await progress({
            operation: 'backup-remote-run',
            step: `remote_run_${event.step}`,
            fileName: event.fileName || '',
            stageTitle: event.stageTitle,
            stageDetail: event.stageDetail,
          });
        }
        : undefined,
    });
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_sync_attachments',
      fileName: archive.fileName,
      stageTitle: 'txt_backup_remote_run_progress_sync_attachments_title',
      stageDetail: destination.includeAttachments
        ? 'txt_backup_remote_run_progress_sync_attachments_detail'
        : 'txt_backup_remote_run_progress_sync_attachments_skipped_detail',
    });
    const remoteSession = createRemoteBackupTransferSession(destination);
    if (destination.includeAttachments) {
      await touchLease();
      const remoteAttachmentIndex = await loadRemoteAttachmentIndex(remoteSession);
      const pendingAttachments = (archive.manifest.attachmentBlobs || [])
        .filter((attachment) => remoteAttachmentIndex.get(attachment.blobName) !== attachment.sizeBytes);
      const attachmentSyncBatchSize = getRemoteAttachmentSyncBatchSize(destination);
      for (let i = 0; i < pendingAttachments.length; i += attachmentSyncBatchSize) {
        await touchLease();
        const chunk = pendingAttachments
          .slice(i, i + attachmentSyncBatchSize)
          .map((attachment) => ({ blobName: attachment.blobName }));
        await uploadRemoteAttachmentChunk(env, destination, chunk);
      }
      if (pendingAttachments.length) {
        for (const attachment of pendingAttachments) {
          remoteAttachmentIndex.set(attachment.blobName, attachment.sizeBytes);
        }
        await touchLease();
        await saveRemoteAttachmentIndex(remoteSession, remoteAttachmentIndex);
      }
    }
    let upload: Awaited<ReturnType<typeof uploadBackupArchive>> | null = null;
    let uploadVerificationMethod: 'metadata' | 'download' | null = null;
    for (let attempt = 1; attempt <= maxArchiveUploadAttempts; attempt++) {
      await touchLease();
      await progress?.({
        operation: 'backup-remote-run',
        step: 'remote_run_upload_archive',
        fileName: archive.fileName,
        stageTitle: 'txt_backup_remote_run_progress_upload_title',
        stageDetail: 'txt_backup_remote_run_progress_upload_detail',
      });
      upload = await remoteSession.uploadArchive(archive.bytes, archive.fileName);
      try {
        await touchLease();
        await progress?.({
          operation: 'backup-remote-run',
          step: 'remote_run_verify_archive',
          fileName: archive.fileName,
          stageTitle: 'txt_backup_remote_run_progress_verify_title',
          stageDetail: 'txt_backup_remote_run_progress_verify_detail',
        });
        uploadVerificationMethod = await verifyUploadedBackupArchive(remoteSession, archive);
        break;
      } catch (error) {
        await remoteSession.deleteFile(archive.fileName).catch(() => undefined);
        if (attempt === maxArchiveUploadAttempts) {
          const message = error instanceof Error ? error.message : 'Remote backup ZIP verification failed';
          throw new Error(`Backup archive upload verification failed after ${maxArchiveUploadAttempts} attempts: ${message}`);
        }
      }
    }
    if (!upload) {
      throw new Error('Backup archive upload failed');
    }
    let prunedFileCount = 0;
    let pruneErrorMessage: string | null = null;
    try {
      await touchLease();
      await progress?.({
        operation: 'backup-remote-run',
        step: 'remote_run_cleanup',
        fileName: archive.fileName,
        stageTitle: 'txt_backup_remote_run_progress_cleanup_title',
        stageDetail: 'txt_backup_remote_run_progress_cleanup_detail',
      });
      prunedFileCount = await pruneRemoteBackupArchives(destination, destination.schedule.retentionCount, archive.fileName);
    } catch (error) {
      pruneErrorMessage = error instanceof Error ? error.message : 'Old backup cleanup failed';
    }

    await touchLease();
    destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
      ...runtime,
      lastSuccessAt: new Date().toISOString(),
      lastErrorAt: null,
      lastErrorMessage: null,
      lastUploadedFileName: archive.fileName,
      lastUploadedSizeBytes: archive.bytes.byteLength,
      lastUploadedDestination: upload.remotePath,
    }));

    await touchLease();
    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      provider: upload.provider,
      remotePath: upload.remotePath,
      fileName: archive.fileName,
      fileBytes: archive.bytes.byteLength,
      uploadVerificationAttempts: maxArchiveUploadAttempts,
      uploadVerificationMethod,
      prunedFileCount,
      pruneError: pruneErrorMessage,
      ...(auditMetadata || {}),
    });

    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_complete',
      fileName: archive.fileName,
      stageTitle: 'txt_backup_remote_run_progress_complete_title',
      stageDetail: 'txt_backup_remote_run_progress_complete_detail',
      done: true,
      ok: true,
    });

    return {
      fileName: archive.fileName,
      fileSize: archive.bytes.byteLength,
      remotePath: upload.remotePath,
      provider: upload.provider,
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Backup upload failed';
    await touchLease();
    destination.runtime = await updateBackupDestinationRuntime(storage, destination.id, (runtime) => ({
      ...runtime,
      lastErrorAt: new Date().toISOString(),
      lastErrorMessage: errorMessage,
    }));

    await touchLease();
    await writeAuditLog(storage, actorUserId, `admin.backup.remote.${trigger}.failed`, 'backup', null, {
      ...getBackupDestinationSummary(destination),
      error: errorMessage,
      ...(auditMetadata || {}),
    });
    await progress?.({
      operation: 'backup-remote-run',
      step: 'remote_run_failed',
      fileName: '',
      stageTitle: 'txt_backup_remote_run_progress_failed_title',
      stageDetail: 'txt_backup_remote_run_progress_failed_detail',
      done: true,
      ok: false,
      error: errorMessage,
    });
    throw error;
  }
}

interface DurableBackupRunResponse {
  result: {
    fileName: string;
    fileSize: number;
    remotePath: string;
    provider: string;
  };
  settings: BackupSettings;
}

async function runConfiguredBackupInDurableObject(
  env: Env,
  payload: {
    actorUserId: string | null;
    auditMetadata?: Record<string, unknown> | null;
    destinationId?: string | null;
    targetDeviceIdentifier?: string | null;
    trigger: 'manual' | 'scheduled';
  }
): Promise<DurableBackupRunResponse | null> {
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('configured-backup-runner');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/run-configured-backup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify(payload),
  });
  if (response.status === 409) {
    return null;
  }
  if (!response.ok) {
    let message = `Backup run failed: ${response.status}`;
    try {
      const body = await response.json<{ error?: string }>();
      if (body?.error) message = body.error;
    } catch {
      // Preserve the status-based message when the DO returns a non-JSON error.
    }
    throw new Error(message);
  }
  const body = await response.json<DurableBackupRunResponse>();
  if (!body?.result || !body?.settings) {
    throw new Error('Backup run response is invalid');
  }
  return body;
}

async function runScheduledBackupsInDurableObject(env: Env): Promise<void> {
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('configured-backup-runner');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/run-scheduled-backups', {
    method: 'POST',
  });
  if (response.status === 409) {
    return;
  }
  if (!response.ok) {
    let message = `Scheduled backup failed: ${response.status}`;
    try {
      const body = await response.json<{ error?: string }>();
      if (body?.error) message = body.error;
    } catch {
      // Preserve the status-based message when the DO returns a non-JSON error.
    }
    throw new Error(message);
  }
}

async function downloadRemoteAttachmentViaDurableObject(
  env: Env,
  destination: BackupDestinationRecord,
  blobName: string
): Promise<Uint8Array | null> {
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('remote-attachment-restore');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/download-remote-attachment', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      destination,
      blobName,
    }),
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Remote attachment download failed: ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function downloadRemoteAttachmentBatchViaDurableObject(
  env: Env,
  destination: BackupDestinationRecord,
  blobNames: string[]
): Promise<Map<string, Uint8Array>> {
  const names = Array.from(new Set(blobNames.map((blobName) => String(blobName || '').trim()).filter(Boolean)));
  const result = new Map<string, Uint8Array>();
  if (!names.length) return result;

  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('remote-attachment-restore');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/download-remote-attachment-batch', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify({
      destination,
      blobNames: names,
    }),
  });
  if (!response.ok) {
    throw new Error(`Remote attachment batch download failed: ${response.status}`);
  }

  const files = unzipSync(new Uint8Array(await response.arrayBuffer()));
  const manifestBytes = files['manifest.json'];
  if (!manifestBytes) return result;
  const manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as {
    entries?: Array<{ blobName?: string; path?: string }>;
  };
  for (const entry of manifest.entries || []) {
    const blobName = String(entry.blobName || '').trim();
    const path = String(entry.path || '').trim();
    const bytes = path ? files[path] : null;
    if (blobName && bytes) {
      result.set(blobName, bytes);
    }
  }
  return result;
}

function collectExternalRemoteAttachmentBlobNames(archiveBytes: Uint8Array): string[] {
  const parsed = parseBackupArchive(archiveBytes, { allowExternalAttachmentBlobs: true });
  const refs = new Map(
    (parsed.payload.manifest.attachmentBlobs || [])
      .map((item) => [`${String(item.cipherId || '').trim()}/${String(item.attachmentId || '').trim()}`, item])
  );
  const names: string[] = [];
  const seen = new Set<string>();

  for (const row of parsed.payload.db.attachments || []) {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const inlinePath = `attachments/${cipherId}/${attachmentId}.bin`;
    if (parsed.files[inlinePath]) continue;
    const ref = refs.get(`${cipherId}/${attachmentId}`);
    const blobName = String(ref?.blobName || '').trim();
    if (!isSafeBackupAttachmentBlobName(blobName)) continue;
    if (blobName && !seen.has(blobName)) {
      seen.add(blobName);
      names.push(blobName);
    }
  }

  return names;
}

function toImportStatusCode(message: string): number {
  const lower = message.toLowerCase();
  if (lower.includes('checksum')) return 400;
  if (lower.includes('invalid remote backup path') || lower.includes('please select a backup zip file')) return 409;
  if (lower.includes('invalid backup') || lower.includes('invalid json')) return 400;
  if (lower.includes('fresh instance')) return 409;
  if (lower.includes('not configured') || lower.includes('kv')) return 409;
  return 500;
}

export async function importAndAuditRemoteBackupFile(
  env: Env,
  storage: StorageService,
  actorUserId: string,
  remoteFile: RemoteBackupFile,
  destination: BackupDestinationRecord,
  remotePath: string,
  replaceExisting: boolean,
  checksumMismatchAccepted: boolean,
  auditMetadata: Record<string, unknown> | null = null,
  targetDeviceIdentifier: string | null = null,
  keepAlive?: (() => Promise<void>) | null
): Promise<BackupImportExecutionResult> {
  const touchLease = async () => {
    await keepAlive?.();
  };
  const restoreFileName = remoteFile.fileName || remotePath.split('/').pop() || remotePath;
  await touchLease();
  const externalAttachmentBlobNames = collectExternalRemoteAttachmentBlobNames(remoteFile.bytes);
  const externalAttachmentCache = new Map<string, Uint8Array | null>();
  const progress: BackupRestoreProgressReporter = async (event) => {
    await touchLease();
    await notifyUserBackupRestoreProgress(
      env,
      actorUserId,
      {
        operation: 'backup-restore',
        ...event,
      },
      targetDeviceIdentifier
    );
  };
  const result = await importRemoteBackupArchiveBytes(
    remoteFile.bytes,
    env,
    actorUserId,
    replaceExisting,
    {
      loadAttachment: async (blobName) => {
        await touchLease();
        const normalized = String(blobName || '').trim();
        if (!normalized) return null;
        if (externalAttachmentCache.has(normalized)) {
          return externalAttachmentCache.get(normalized) || null;
        }

        const start = Math.max(0, externalAttachmentBlobNames.indexOf(normalized));
        const batchNames = externalAttachmentBlobNames
          .slice(start, start + REMOTE_ATTACHMENT_RESTORE_BATCH_SIZE)
          .filter((name) => !externalAttachmentCache.has(name));
        if (!batchNames.includes(normalized)) {
          batchNames.unshift(normalized);
        }

        try {
          const batch = await downloadRemoteAttachmentBatchViaDurableObject(env, destination, batchNames);
          for (const name of batchNames) {
            externalAttachmentCache.set(name, batch.get(name) || null);
          }
        } catch {
          externalAttachmentCache.set(normalized, await downloadRemoteAttachmentViaDurableObject(env, destination, normalized).catch(() => null));
        }
        await touchLease();
        return externalAttachmentCache.get(normalized) || null;
      },
    },
    progress,
    restoreFileName
  );
  await writeAuditLog(storage, result.auditActorUserId, 'admin.backup.import', 'backup', null, {
    users: result.result.imported.users,
    ciphers: result.result.imported.ciphers,
    attachments: result.result.imported.attachmentFiles,
    skippedAttachments: result.result.skipped.attachments,
    skippedReason: result.result.skipped.reason,
    replaceExisting,
    ...getBackupDestinationSummary(destination),
    remotePath,
    bytes: remoteFile.bytes.byteLength,
    trigger: 'remote',
    checksumMismatchAccepted,
    ...(auditMetadata || {}),
  });
  return result;
}

async function restoreRemoteBackupInDurableObject(
  env: Env,
  payload: {
    actorUserId: string;
    allowChecksumMismatch?: boolean;
    auditMetadata?: Record<string, unknown> | null;
    destinationId?: string | null;
    path: string;
    replaceExisting?: boolean;
    targetDeviceIdentifier?: string | null;
  }
): Promise<BackupImportExecutionResult['result'] | null> {
  const id = env.BACKUP_TRANSFER_RUNNER.idFromName('configured-backup-runner');
  const stub = env.BACKUP_TRANSFER_RUNNER.get(id);
  const response = await stub.fetch('https://backup-transfer/internal/restore-remote-backup', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
    },
    body: JSON.stringify(payload),
  });
  if (response.status === 409) {
    return null;
  }
  if (!response.ok) {
    let message = `Remote backup restore failed: ${response.status}`;
    try {
      const body = await response.json<{ error?: string }>();
      if (body?.error) message = body.error;
    } catch {
      // Preserve the status-based message when the DO returns a non-JSON error.
    }
    throw new Error(message);
  }
  return response.json<BackupImportExecutionResult['result']>();
}

async function runImportAndAudit(
  env: Env,
  request: Request,
  actorUser: User,
  archiveBytes: Uint8Array,
  fileName: string,
  replaceExisting: boolean,
  metadata: Record<string, unknown>
): Promise<BackupImportExecutionResult> {
  const storage = new StorageService(env.DB);
  const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
  const progress: BackupRestoreProgressReporter = async (event) => {
    await notifyUserBackupRestoreProgress(
      env,
      actorUser.id,
      {
        operation: 'backup-restore',
        ...event,
      },
      targetDeviceIdentifier
    );
  };
  await progress({
    source: 'local',
    step: 'local_upload_received',
    fileName,
    stageTitle: 'txt_backup_restore_progress_local_upload_title',
    stageDetail: 'txt_backup_restore_progress_local_upload_detail',
    replaceExisting,
  });
  const imported = await importBackupArchiveBytes(archiveBytes, env, actorUser.id, replaceExisting, progress, fileName);
  await writeAuditLog(storage, imported.auditActorUserId, 'admin.backup.import', 'backup', null, {
    users: imported.result.imported.users,
    ciphers: imported.result.imported.ciphers,
    attachments: imported.result.imported.attachmentFiles,
    skippedAttachments: imported.result.skipped.attachments,
    skippedReason: imported.result.skipped.reason,
    replaceExisting,
    ...metadata,
  }, request);
  return imported;
}

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  await runScheduledBackupsInDurableObject(env);
}

export async function handleGetAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    return jsonResponse(redactBackupSettingsSecrets(settings));
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings could not be loaded', 409);
  }
}

export async function handleUpdateAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput & { masterPasswordHash?: string };
  try {
    body = await request.json<BackupSettingsInput & { masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Backup settings payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings are invalid', 400);
  }

  await saveBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.update', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleGetAdminBackupSettingsRepairState(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const state = await getBackupSettingsRepairState(storage, env, 'UTC');
    return jsonResponse({
      object: 'backup-settings-repair',
      needsRepair: state.needsRepair,
      portable: state.portable,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair state could not be loaded', 409);
  }
}

export async function handleRepairAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: BackupSettingsInput & { masterPasswordHash?: string; userVerificationToken?: string };
  try {
    body = await request.json<BackupSettingsInput & { masterPasswordHash?: string; userVerificationToken?: string }>();
  } catch {
    return errorResponse('Backup settings repair payload is invalid', 400);
  }

  const verificationError = await requireBackupRepairVerification(actorUser, body, env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  let previous;
  try {
    previous = await loadBackupSettings(storage, env, 'UTC');
  } catch {
    previous = getDefaultBackupSettings('UTC');
  }

  let next;
  try {
    next = normalizeBackupSettingsInput(body, previous);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings repair payload is invalid', 400);
  }

  await repairBackupSettings(storage, env, next);
  await writeAuditLog(storage, actorUser.id, 'admin.backup.settings.repair', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleRunAdminConfiguredBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    let body: { destinationId?: string; masterPasswordHash?: string } | null = null;
    try {
      if ((request.headers.get('Content-Type') || '').includes('application/json')) {
        body = await request.json<{ destinationId?: string; masterPasswordHash?: string }>();
      }
    } catch {
      return errorResponse('Backup run payload is invalid', 400);
    }

    const verificationError = await requireBackupUserVerification(actorUser, String(body?.masterPasswordHash || ''), env);
    if (verificationError) return verificationError;

    const outcome = await runConfiguredBackupInDurableObject(env, {
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(request),
      destinationId: body?.destinationId || null,
      targetDeviceIdentifier: String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null,
      trigger: 'manual',
    });
    if (!outcome) {
      return errorResponse('Another backup run is already in progress', 409);
    }
    return jsonResponse({
      object: 'backup-run',
      result: {
        fileName: outcome.result.fileName,
        fileSize: outcome.result.fileSize,
        provider: outcome.result.provider,
        remotePath: outcome.result.remotePath,
      },
      settings: redactBackupSettingsSecrets(outcome.settings),
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup run failed', 500);
  }
}

export async function handleListAdminRemoteBackups(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const url = new URL(request.url);
    const destination = requireBackupDestination(settings, url.searchParams.get('destinationId') || null);
    const listing = await listRemoteBackupEntries(destination, url.searchParams.get('path') || '');
    return jsonResponse({
      object: 'backup-remote-browser',
      destinationId: destination.id,
      destinationName: destination.name,
      ...listing,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup listing failed', 409);
  }
}

export async function handleDownloadAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup download payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    return new Response(remoteFile.bytes, {
      status: 200,
      headers: {
        'Content-Type': remoteFile.contentType || 'application/zip',
        'Content-Disposition': contentDispositionBackup(remoteFile.fileName),
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup download failed', 409);
  }
}

export async function handleInspectAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup integrity payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    const remoteFile = await downloadRemoteBackupFile(destination, path);
    const integrity = await inspectBackupArchiveFileNameChecksum(remoteFile.bytes, remoteFile.fileName || path);
    return jsonResponse({
      object: 'backup-remote-integrity',
      destinationId: destination.id,
      path,
      fileName: remoteFile.fileName || path.split('/').pop() || path,
      integrity,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup integrity inspection failed', 409);
  }
}

export async function handleDeleteAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: { destinationId?: string; path?: string; masterPasswordHash?: string };
  try {
    body = await request.json<{ destinationId?: string; path?: string; masterPasswordHash?: string }>();
  } catch {
    return errorResponse('Remote backup delete payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  const storage = new StorageService(env.DB);
  try {
    const settings = await loadBackupSettings(storage, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const destination = requireBackupDestination(settings, body.destinationId || null);
    await deleteRemoteBackupFile(destination, path);
    await writeAuditLog(storage, actorUser.id, 'admin.backup.remote.delete', 'backup', null, {
      ...getBackupDestinationSummary(destination),
      remotePath: path,
    }, request);
    return jsonResponse({ object: 'backup-remote-delete', deleted: true, path });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Remote backup delete failed', 409);
  }
}

export async function handleRestoreAdminRemoteBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  let body: {
    destinationId?: string;
    path?: string;
    replaceExisting?: boolean;
    allowChecksumMismatch?: boolean;
    masterPasswordHash?: string;
  };
  try {
    body = await request.json<{ destinationId?: string; path?: string; replaceExisting?: boolean }>();
  } catch {
    return errorResponse('Remote restore payload is invalid', 400);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(body.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;

  try {
    const path = ensureRemoteRestoreCandidate(String(body.path || ''));
    const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
    const imported = await restoreRemoteBackupInDurableObject(env, {
      actorUserId: actorUser.id,
      allowChecksumMismatch: !!body.allowChecksumMismatch,
      auditMetadata: auditRequestMetadata(request),
      destinationId: body.destinationId || null,
      path,
      replaceExisting: !!body.replaceExisting,
      targetDeviceIdentifier,
    });
    if (!imported) {
      return errorResponse('Another backup or restore run is already in progress', 409);
    }
    return jsonResponse(imported);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Remote backup restore failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function handleAdminExportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const storage = new StorageService(env.DB);
  const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
  let body: { includeAttachments?: boolean; masterPasswordHash?: string } | null = null;
  try {
    if ((request.headers.get('Content-Type') || '').includes('application/json')) {
      body = await request.json<{ includeAttachments?: boolean; masterPasswordHash?: string }>();
    }
  } catch {
    return errorResponse('Backup export payload is invalid', 400);
  }
  const verificationError = await requireBackupUserVerification(actorUser, String(body?.masterPasswordHash || ''), env);
  if (verificationError) return verificationError;
  let archive: BackupArchiveBundle;
  try {
    const progress = async (event: {
      step: string;
      fileName?: string;
      stageTitle: string;
      stageDetail: string;
      includeAttachments: boolean;
    }) => {
      await notifyUserBackupProgress(
        env,
        actorUser.id,
        {
          operation: 'backup-export',
          source: 'local',
          step: `export_${event.step}`,
          fileName: event.fileName || '',
          stageTitle: event.stageTitle,
          stageDetail: event.stageDetail,
        },
        targetDeviceIdentifier
      );
    };
    archive = await buildBackupArchive(env, new Date(), {
      includeAttachments: !!body?.includeAttachments,
      progress,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup export failed';
    await notifyUserBackupProgress(
      env,
      actorUser.id,
      {
        operation: 'backup-export',
        source: 'local',
        step: 'export_failed',
        fileName: '',
        stageTitle: 'txt_backup_export_progress_failed_title',
        stageDetail: 'txt_backup_export_progress_failed_detail',
        done: true,
        ok: false,
        error: message,
      },
      targetDeviceIdentifier
    );
    return errorResponse(message, message.includes('blob missing') ? 409 : 500);
  }

  await writeAuditLog(storage, actorUser.id, 'admin.backup.export', 'backup', null, {
    users: archive.manifest.tableCounts.users,
    ciphers: archive.manifest.tableCounts.ciphers,
    attachments: archive.manifest.tableCounts.attachments,
    compressedBytes: archive.bytes.byteLength,
    includesAttachments: archive.manifest.includes.attachments,
  }, request);

  return new Response(archive.bytes, {
    status: 200,
    headers: {
      'Content-Type': 'application/zip',
      'Content-Disposition': contentDispositionBackup(archive.fileName),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function handleDownloadAdminBackupAttachment(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    const url = new URL(request.url);
    let input: { blobName?: unknown; masterPasswordHash?: unknown } = {};
    if (request.method === 'POST') {
      try {
        input = await request.json<{ blobName?: unknown; masterPasswordHash?: unknown }>();
      } catch {
        return errorResponse('Backup attachment download payload is invalid', 400);
      }
    } else {
      input = {
        blobName: url.searchParams.get('blobName') || '',
        masterPasswordHash: url.searchParams.get('masterPasswordHash') || '',
      };
    }

    const verificationError = await requireBackupUserVerification(
      actorUser,
      String(input.masterPasswordHash || ''),
      env
    );
    if (verificationError) return verificationError;

    const blobName = ensureBackupBlobName(String(input.blobName || ''));
    const object = await getBlobObject(env, blobName);
    if (!object) {
      return errorResponse('Backup attachment blob not found', 404);
    }
    return new Response(object.body, {
      status: 200,
      headers: {
        'Content-Type': object.contentType || 'application/octet-stream',
        'Content-Length': String(object.size),
        'Cache-Control': 'no-store',
      },
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup attachment download failed', 400);
  }
}

export async function handleAdminImportBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const contentType = request.headers.get('Content-Type') || '';
  if (!contentType.includes('multipart/form-data')) {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }
  const declaredSize = parseRequestContentLength(request);
  if (declaredSize !== null && declaredSize > getMultipartRequestMaxBytes(MAX_BACKUP_ARCHIVE_BYTES)) {
    return errorResponse(`Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`, 413);
  }

  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return errorResponse('Content-Type must be multipart/form-data', 400);
  }

  const file = formData.get('file');
  if (!file || typeof file !== 'object' || !('arrayBuffer' in file)) {
    return errorResponse('Backup file is required', 400);
  }
  if ('size' in file && typeof (file as File).size === 'number' && (file as File).size > MAX_BACKUP_ARCHIVE_BYTES) {
    return errorResponse(`Backup file too large. Maximum size is ${Math.floor(MAX_BACKUP_ARCHIVE_BYTES / (1024 * 1024))}MB`, 413);
  }

  const verificationError = await requireBackupUserVerification(actorUser, String(formData.get('masterPasswordHash') || ''), env);
  if (verificationError) return verificationError;

  const replaceExisting = String(formData.get('replaceExisting') || '').trim() === '1';
  const allowChecksumMismatch = String(formData.get('allowChecksumMismatch') || '').trim() === '1';
  let archiveBytes: Uint8Array;
  try {
    archiveBytes = new Uint8Array(await (file as { arrayBuffer(): Promise<ArrayBuffer> }).arrayBuffer());
  } catch {
    return errorResponse('Unable to read backup file', 400);
  }

  try {
    const fileName = 'name' in file ? String((file as File).name || '') : '';
    const checksumOk = await verifyBackupArchiveFileNameChecksum(archiveBytes, fileName);
    if (!checksumOk && !allowChecksumMismatch) {
      return errorResponse('Backup file checksum does not match its filename', 400);
    }
    const imported = await runImportAndAudit(env, request, actorUser, archiveBytes, fileName || 'nodewarden_backup.zip', replaceExisting, {
      trigger: 'local',
      bytes: archiveBytes.byteLength,
      checksumMismatchAccepted: !checksumOk,
    });
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup import failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function seedDefaultBackupSettings(env: Env): Promise<void> {
  const storage = new StorageService(env.DB);
  const current = await storage.getConfigValue('backup.settings.v1');
  if (current) {
    await normalizeImportedBackupSettings(storage, env, 'UTC');
    return;
  }
  await saveBackupSettings(storage, env, getDefaultBackupSettings('UTC'));
}
