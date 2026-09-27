import type { Env, User } from '../types';
import { z } from 'zod';
import { bodyIssues, errorResponse, jsonResponse, parseBody } from '../utils/response';
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
} from '../services/backup-import';
import {
  type RemoteBackupFile,
  createRemoteBackupTransferSession,
  deleteRemoteBackupFile,
  downloadRemoteBackupFile,
  ensureRemoteRestoreCandidate,
  listRemoteBackupEntries,
  pruneRemoteBackupArchives,
  uploadBackupArchive,
} from '../services/backup-uploader';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { getBlobObject } from '../services/blob-store';
import { notifyUserBackupProgress, notifyUserBackupRestoreProgress } from '../durable/notifications-hub';
import { getMultipartRequestMaxBytes } from '../utils/direct-upload';
import { verifyPasskeyUserVerificationToken } from '../utils/user-verification-token';
import { unzipSync } from 'fflate';
import * as configRepo from '../services/storage-config-repo';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function requireBackupUserVerification(actorUser: User, masterPasswordHash: string | null | undefined, env: Env): Promise<Response | null> {
  const normalized = (masterPasswordHash ?? '').trim();
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

async function writeAuditLog(
  db: D1Database,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null,
  request?: Request
): Promise<void> {
  await writeAuditEvent(db, {
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

function contentDispositionBackup(fileName: string | null | undefined): string {
  const fallback = 'nodewarden_backup.zip';
  const value = String(fileName || fallback)
    .replace(/[\\/\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

const REMOTE_ATTACHMENT_INDEX_PATH = 'attachments/.nodewarden-attachment-index.v1.json';

const RemoteAttachmentIndexSchema = z.object({
  version: z.literal(1),
  blobs: z.record(z.string(), z.object({ sizeBytes: z.number(), updatedAt: z.string() })),
});

// Written by BackupTransferRunner.downloadRemoteAttachmentBatch next to the fetched files.
const RemoteAttachmentBatchManifestSchema = z.object({
  entries: z.array(z.object({ blobName: z.string(), path: z.string() })),
});

const REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT = 50;
const REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE = 6;
const REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE = 18;
const REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE = 40;
const REMOTE_ATTACHMENT_RESTORE_BATCH_SIZE = 40;

export async function executeConfiguredBackup(
  env: Env,
  db: D1Database,
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
  const currentSettings = await loadBackupSettings(db, env, 'UTC');
  const destination = requireBackupDestination(currentSettings, destinationId);

  const now = new Date();
  await touchLease();
  destination.runtime = await updateBackupDestinationRuntime(db, destination.id, (runtime) => ({
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
      let remoteAttachmentIndex: Map<string, number>;
      try {
        const file = await remoteSession.download(REMOTE_ATTACHMENT_INDEX_PATH);
        // An unreadable index re-uploads every attachment rather than trusting partial sizes.
        const index = RemoteAttachmentIndexSchema.safeParse(JSON.parse(new TextDecoder().decode(file.bytes)));
        remoteAttachmentIndex = new Map(index.success
          ? Object.entries(index.data.blobs).filter(([blobName]) => blobName.trim()).map(([blobName, { sizeBytes }]) => [blobName, sizeBytes])
          : []);
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
          remoteAttachmentIndex = new Map<string, number>();
        } else {
          throw error;
        }
      }
      const pendingAttachments = (archive.manifest.attachmentBlobs || [])
        .filter((attachment) => remoteAttachmentIndex.get(attachment.blobName) !== attachment.sizeBytes);
      // A WebDAV batch spends two subrequests per attachment after creating the remote path's
      // collections, all inside the Worker's external subrequest limit; S3 creates no collections.
      let attachmentSyncBatchSize: number = REMOTE_ATTACHMENT_SYNC_MAX_S3_BATCH_SIZE;
      if (destination.type !== 's3') {
        const remotePath = String((destination.destination as WebDavBackupDestination).remotePath || '');
        const fixedWebDavDirectoryCalls = remotePath.replace(/\\/g, '/').split('/').filter(Boolean).length + 1; // remotePath plus the shared "attachments" dir.
        const available = REMOTE_ATTACHMENT_SYNC_EXTERNAL_SUBREQUEST_LIMIT
          - REMOTE_ATTACHMENT_SYNC_SUBREQUEST_RESERVE
          - fixedWebDavDirectoryCalls;

        if (available < 2) {
          throw new Error('WebDAV remote backup path is too deep for safe attachment batching');
        }

        attachmentSyncBatchSize = Math.max(1, Math.min(
          REMOTE_ATTACHMENT_SYNC_MAX_WEB_DAV_BATCH_SIZE,
          Math.floor(available / 2)
        ));
      }
      for (let i = 0; i < pendingAttachments.length; i += attachmentSyncBatchSize) {
        await touchLease();
        const chunk = pendingAttachments
          .slice(i, i + attachmentSyncBatchSize)
          .map((attachment) => ({ blobName: attachment.blobName }));
        await backupTransferRunner(env, 'remote-attachment-sync').uploadAttachmentChunk(destination, chunk);
      }
      if (pendingAttachments.length) {
        for (const attachment of pendingAttachments) {
          remoteAttachmentIndex.set(attachment.blobName, attachment.sizeBytes);
        }
        await touchLease();
        const indexPayload: z.input<typeof RemoteAttachmentIndexSchema> = {
          version: 1,
          blobs: Object.fromEntries(
            Array.from(remoteAttachmentIndex.entries()).map(([blobName, sizeBytes]) => [
              blobName,
              {
                sizeBytes,
                updatedAt: new Date().toISOString(),
              },
            ])
          ),
        };
        await remoteSession.putFile(REMOTE_ATTACHMENT_INDEX_PATH, new TextEncoder().encode(JSON.stringify(indexPayload)), {
          contentType: 'application/json; charset=utf-8',
        });
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
        // A matching remote size is enough. When lightweight metadata is unavailable or differs, read the
        // archive back and check its checksum and size.
        const stat = await remoteSession.stat(archive.fileName).catch(() => null);
        if (stat?.size === archive.bytes.byteLength) {
          uploadVerificationMethod = 'metadata';
        } else {
          const remoteFile = await remoteSession.download(archive.fileName);
          const checksumOk = await verifyBackupArchiveFileNameChecksum(remoteFile.bytes, archive.fileName);
          if (!checksumOk) {
            throw new Error('Remote backup ZIP checksum verification failed');
          }
          if (remoteFile.bytes.byteLength !== archive.bytes.byteLength) {
            throw new Error('Remote backup ZIP size verification failed');
          }
          uploadVerificationMethod = 'download';
        }
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
    destination.runtime = await updateBackupDestinationRuntime(db, destination.id, (runtime) => ({
      ...runtime,
      lastSuccessAt: new Date().toISOString(),
      lastErrorAt: null,
      lastErrorMessage: null,
      lastUploadedFileName: archive.fileName,
      lastUploadedSizeBytes: archive.bytes.byteLength,
      lastUploadedDestination: upload.remotePath,
    }));

    await touchLease();
    await writeAuditLog(db, actorUserId, `admin.backup.remote.${trigger}`, 'backup', null, {
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
    destination.runtime = await updateBackupDestinationRuntime(db, destination.id, (runtime) => ({
      ...runtime,
      lastErrorAt: new Date().toISOString(),
      lastErrorMessage: errorMessage,
    }));

    await touchLease();
    await writeAuditLog(db, actorUserId, `admin.backup.remote.${trigger}.failed`, 'backup', null, {
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

function backupTransferRunner(env: Env, name: string) {
  return env.BACKUP_TRANSFER_RUNNER.get(env.BACKUP_TRANSFER_RUNNER.idFromName(name));
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
  db: D1Database,
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
  // Blob names the archive references without carrying them inline, fetched from the destination in batches.
  const parsed = parseBackupArchive(remoteFile.bytes, { allowExternalAttachmentBlobs: true });
  const refs = new Map(parsed.payload.manifest.attachmentBlobs.map((item) => [`${item.cipherId}/${item.attachmentId}`, item.blobName]));
  const externalAttachmentBlobNames = Array.from(new Set(parsed.payload.db.attachments.flatMap((row) => {
    const cipherId = String(row.cipher_id || '').trim();
    const attachmentId = String(row.id || '').trim();
    const blobName = refs.get(`${cipherId}/${attachmentId}`) ?? '';
    return parsed.files[`attachments/${cipherId}/${attachmentId}.bin`] || !isSafeBackupAttachmentBlobName(blobName) ? [] : [blobName];
  })));
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
  const result = await importBackupArchiveBytes(
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
          // The runner streams the batch as a zip whose manifest.json maps blob names to entries.
          const names = Array.from(new Set(batchNames.map((blobName) => String(blobName || '').trim()).filter(Boolean)));
          const batch = new Map<string, Uint8Array>();
          const stream = await backupTransferRunner(env, 'remote-attachment-restore').downloadRemoteAttachmentBatch(destination, names);
          const files = unzipSync(new Uint8Array(await new Response(stream).arrayBuffer()));
          const manifestBytes = files['manifest.json'];
          if (manifestBytes) {
            const { entries } = RemoteAttachmentBatchManifestSchema.parse(JSON.parse(new TextDecoder().decode(manifestBytes)));
            for (const { blobName, path } of entries) {
              if (blobName && files[path]) {
                batch.set(blobName, files[path]);
              }
            }
          }
          for (const name of batchNames) {
            externalAttachmentCache.set(name, batch.get(name) || null);
          }
        } catch {
          // A failed batch falls back to this attachment alone; if that fails too it restores as skipped.
          let single: Uint8Array | null = null;
          try {
            const stream = await backupTransferRunner(env, 'remote-attachment-restore').downloadRemoteAttachment(destination, normalized);
            single = stream ? new Uint8Array(await new Response(stream).arrayBuffer()) : null;
          } catch {
            // Stays null, so the attachment restores as skipped.
          }
          externalAttachmentCache.set(normalized, single);
        }
        await touchLease();
        return externalAttachmentCache.get(normalized) || null;
      },
    },
    progress,
    restoreFileName
  );
  await writeAuditLog(db, result.auditActorUserId, 'admin.backup.import', 'backup', null, {
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

export async function runScheduledBackupIfDue(env: Env): Promise<void> {
  await backupTransferRunner(env, 'configured-backup-runner').runScheduledBackups();
}

export async function handleGetAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    const settings = await loadBackupSettings(env.DB, env, 'UTC');
    return jsonResponse(redactBackupSettingsSecrets(settings));
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Backup settings could not be loaded', 409);
  }
}

const optionalString = z.string().nullish();
const remoteFileShape = { destinationId: optionalString, path: optionalString, masterPasswordHash: optionalString };

// Unparseable JSON and a non-object body both answer the endpoint's payload message.
function parseBackupBody<Shape extends z.ZodRawShape>(request: Request, shape: Shape, message: string) {
  return parseBody(request, z.object(shape, { error: message }), message);
}

// Settings saves merge into the stored settings; an unreadable store merges into the defaults.
async function normalizeBackupSettingsBody(env: Env, destinations: unknown): Promise<BackupSettings | Response> {
  const previous = await loadBackupSettings(env.DB, env, 'UTC').catch(() => getDefaultBackupSettings('UTC'));
  const next = normalizeBackupSettingsInput(destinations, previous);
  return next.success ? next.data : errorResponse(next.error.issues[0].message, 400, {}, bodyIssues(next.error));
}

export async function handleUpdateAdminBackupSettings(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  const body = await parseBackupBody(request, { destinations: z.unknown().optional(), masterPasswordHash: optionalString }, 'Backup settings payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  const next = await normalizeBackupSettingsBody(env, body.destinations);
  if (next instanceof Response) return next;

  await saveBackupSettings(env.DB, env, next);
  await writeAuditLog(env.DB, actorUser.id, 'admin.backup.settings.update', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleGetAdminBackupSettingsRepairState(request: Request, env: Env, actorUser: User): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    const state = await getBackupSettingsRepairState(env.DB, env, 'UTC');
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

  const body = await parseBackupBody(request, {
    destinations: z.unknown().optional(),
    masterPasswordHash: optionalString,
    userVerificationToken: optionalString,
  }, 'Backup settings repair payload is invalid');
  if (body instanceof Response) return body;

  // Repair accepts the master password hash or a user verification token issued for this repair.
  const masterPasswordHash = (body.masterPasswordHash ?? '').trim();
  if (masterPasswordHash) {
    const verificationError = await requireBackupUserVerification(actorUser, masterPasswordHash, env);
    if (verificationError) return verificationError;
  } else {
    const userVerificationToken = (body.userVerificationToken ?? '').trim();
    if (!userVerificationToken) {
      return errorResponse('masterPasswordHash or userVerificationToken is required', 400);
    }
    const valid = await verifyPasskeyUserVerificationToken(env, userVerificationToken, actorUser.id, 'backup.settings.repair');
    if (!valid) {
      return errorResponse('Invalid user verification token', 400);
    }
  }

  const next = await normalizeBackupSettingsBody(env, body.destinations);
  if (next instanceof Response) return next;

  await repairBackupSettings(env.DB, env, next);
  await writeAuditLog(env.DB, actorUser.id, 'admin.backup.settings.repair', 'backup', null, {
    destinationCount: next.destinations.length,
    scheduledDestinationCount: next.destinations.filter((destination) => destination.schedule.enabled).length,
  }, request);
  return jsonResponse(redactBackupSettingsSecrets(next));
}

export async function handleRunAdminConfiguredBackup(request: Request, env: Env, actorUser: User): Promise<Response> {
  if (!isAdmin(actorUser)) return errorResponse('Forbidden', 403);

  try {
    const body = await parseBackupBody(request, { destinationId: optionalString, masterPasswordHash: optionalString }, 'Backup run payload is invalid');
    if (body instanceof Response) return body;

    const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
    if (verificationError) return verificationError;

    const outcome = await backupTransferRunner(env, 'configured-backup-runner').runConfiguredBackup({
      actorUserId: actorUser.id,
      auditMetadata: auditRequestMetadata(request),
      destinationId: body.destinationId || null,
      targetDeviceIdentifier: String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null,
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

  try {
    const settings = await loadBackupSettings(env.DB, env, 'UTC');
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

  const body = await parseBackupBody(request, remoteFileShape, 'Remote backup download payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  try {
    const settings = await loadBackupSettings(env.DB, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(body.path ?? '');
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

  const body = await parseBackupBody(request, remoteFileShape, 'Remote backup integrity payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  try {
    const settings = await loadBackupSettings(env.DB, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(body.path ?? '');
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

  const body = await parseBackupBody(request, remoteFileShape, 'Remote backup delete payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  try {
    const settings = await loadBackupSettings(env.DB, env, 'UTC');
    const path = ensureRemoteRestoreCandidate(body.path ?? '');
    const destination = requireBackupDestination(settings, body.destinationId || null);
    await deleteRemoteBackupFile(destination, path);
    await writeAuditLog(env.DB, actorUser.id, 'admin.backup.remote.delete', 'backup', null, {
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

  const body = await parseBackupBody(request, {
    ...remoteFileShape,
    replaceExisting: z.boolean().nullish(),
    allowChecksumMismatch: z.boolean().nullish(),
  }, 'Remote restore payload is invalid');
  if (body instanceof Response) return body;

  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
  if (verificationError) return verificationError;

  try {
    const path = ensureRemoteRestoreCandidate(body.path ?? '');
    const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
    const imported = await backupTransferRunner(env, 'configured-backup-runner').restoreRemoteBackup({
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

  const targetDeviceIdentifier = String(request.headers.get('X-NodeWarden-Acting-Device-Id') || '').trim() || null;
  const body = await parseBackupBody(request, { includeAttachments: z.boolean().nullish(), masterPasswordHash: optionalString }, 'Backup export payload is invalid');
  if (body instanceof Response) return body;
  const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
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
      includeAttachments: !!body.includeAttachments,
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

  await writeAuditLog(env.DB, actorUser.id, 'admin.backup.export', 'backup', null, {
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
    // Read the request body only. Accepting these fields from the query string
    // would put the master-password authentication hash in the URL, where it is
    // captured by request logs, browser history and Referer headers.
    const body = await parseBackupBody(request, { blobName: optionalString, masterPasswordHash: optionalString }, 'Backup attachment download payload is invalid');
    if (body instanceof Response) return body;

    const verificationError = await requireBackupUserVerification(actorUser, body.masterPasswordHash, env);
    if (verificationError) return verificationError;

    const blobName = String(body.blobName || '').trim().replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    if (!blobName) {
      return errorResponse('Backup attachment blob is required', 400);
    }
    // Only <cipher>/<attachment> names with safe segments reach blob storage.
    if (!isSafeBackupAttachmentBlobName(blobName)) {
      return errorResponse('Backup attachment blob is invalid', 400);
    }
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
  // Refuse an oversized upload before reading it; a missing or malformed Content-Length falls through to the
  // file size check below.
  const declaredSize = Number(request.headers.get('content-length') || Number.NaN);
  if (Number.isFinite(declaredSize) && declaredSize >= 0 && Math.floor(declaredSize) > getMultipartRequestMaxBytes(MAX_BACKUP_ARCHIVE_BYTES)) {
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
    const restoreFileName = fileName || 'nodewarden_backup.zip';
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
      fileName: restoreFileName,
      stageTitle: 'txt_backup_restore_progress_local_upload_title',
      stageDetail: 'txt_backup_restore_progress_local_upload_detail',
      replaceExisting,
    });
    const imported = await importBackupArchiveBytes(archiveBytes, env, actorUser.id, replaceExisting, null, progress, restoreFileName);
    await writeAuditLog(env.DB, imported.auditActorUserId, 'admin.backup.import', 'backup', null, {
      users: imported.result.imported.users,
      ciphers: imported.result.imported.ciphers,
      attachments: imported.result.imported.attachmentFiles,
      skippedAttachments: imported.result.skipped.attachments,
      skippedReason: imported.result.skipped.reason,
      replaceExisting,
      trigger: 'local',
      bytes: archiveBytes.byteLength,
      checksumMismatchAccepted: !checksumOk,
    }, request);
    return jsonResponse(imported.result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Backup import failed';
    return errorResponse(message, toImportStatusCode(message));
  }
}

export async function seedDefaultBackupSettings(env: Env): Promise<void> {
  const current = await configRepo.getConfigValue(env.DB, 'backup.settings.v1');
  if (current) {
    await normalizeImportedBackupSettings(env.DB, env, 'UTC');
    return;
  }
  await saveBackupSettings(env.DB, env, getDefaultBackupSettings('UTC'));
}
