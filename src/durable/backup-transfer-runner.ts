import { DurableObject } from 'cloudflare:workers';
import type { Env } from '../types';
import type { BackupDestinationRecord, BackupSettings } from '../services/backup-config';
import {
  BACKUP_SCHEDULER_WINDOW_MINUTES,
  requireBackupDestination,
  hasBackupSlotBetween,
  isBackupDueNow,
  loadBackupSettings,
} from '../services/backup-config';
import {
  createRemoteBackupTransferSession,
  downloadRemoteBackupFile,
  ensureRemoteRestoreCandidate,
} from '../services/backup-uploader';
import type { BackupImportResultBody } from '../services/backup-import';
import { getBlobObject } from '../services/blob-store';
import { notifyUserBackupProgress, notifyUserBackupRestoreProgress } from './notifications-hub';
import { executeConfiguredBackup, importAndAuditRemoteBackupFile } from '../handlers/backup';
import { isSafeBackupAttachmentBlobName, verifyBackupArchiveFileNameChecksum } from '../services/backup-archive';
import { zipSync } from 'fflate';
import { withoutQueryParams } from '../db/client';

const BACKUP_JOB_STATE_KEY = 'backup.job.state.v1';
const BACKUP_JOB_LEASE_MS = 10 * 60 * 1000;
const BACKUP_JOB_HEARTBEAT_MS = 30 * 1000;
const REMOTE_ATTACHMENT_BATCH_LIMIT = 40;

interface BackupJobState {
  token: string;
  reason: string;
  acquiredAt: string;
  touchedAt: string;
  expiresAtMs: number;
}

export interface ConfiguredBackupRunRequest {
  actorUserId: string;
  auditMetadata: Record<string, unknown> | null;
  destinationId: string | null;
  targetDeviceIdentifier: string | null;
}

export interface ConfiguredBackupRunResult {
  result: Awaited<ReturnType<typeof executeConfiguredBackup>>;
  settings: BackupSettings;
}

export interface RemoteBackupRestoreRequest {
  actorUserId: string;
  allowChecksumMismatch: boolean;
  auditMetadata: Record<string, unknown> | null;
  destinationId: string | null;
  path: string;
  replaceExisting: boolean;
  targetDeviceIdentifier: string | null;
}

// Backup and restore jobs serialize through a storage-backed lease on the named runner instance;
// the job methods return null while another job holds it. Attachment transfers run here too so
// each chunk spends the Durable Object's own subrequest budget rather than the request's.
export class BackupTransferRunner extends DurableObject<Env> {
  private lastHeartbeatAt = 0;

  private async acquireJob(reason: string): Promise<string | null> {
    const nowMs = Date.now();
    const current = await this.ctx.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.expiresAtMs && current.expiresAtMs > nowMs) {
      return null;
    }

    const token = crypto.randomUUID();
    const nowIso = new Date(nowMs).toISOString();
    await this.ctx.storage.put<BackupJobState>(BACKUP_JOB_STATE_KEY, {
      token,
      reason,
      acquiredAt: nowIso,
      touchedAt: nowIso,
      expiresAtMs: nowMs + BACKUP_JOB_LEASE_MS,
    });
    this.lastHeartbeatAt = 0;
    return token;
  }

  private async touchJob(token: string): Promise<void> {
    const nowMs = Date.now();
    if (nowMs - this.lastHeartbeatAt < BACKUP_JOB_HEARTBEAT_MS) return;
    this.lastHeartbeatAt = nowMs;

    const current = await this.ctx.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.token !== token) return;

    await this.ctx.storage.put<BackupJobState>(BACKUP_JOB_STATE_KEY, {
      ...current,
      touchedAt: new Date(nowMs).toISOString(),
      expiresAtMs: nowMs + BACKUP_JOB_LEASE_MS,
    });
  }

  private async releaseJob(token: string): Promise<void> {
    const current = await this.ctx.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.token === token) {
      await this.ctx.storage.delete(BACKUP_JOB_STATE_KEY);
    }
  }

  async runConfiguredBackup(request: ConfiguredBackupRunRequest): Promise<ConfiguredBackupRunResult | null> {
    const token = await this.acquireJob(`manual:${request.actorUserId}`);
    if (!token) return null;

    try {
      await this.touchJob(token);
      const result = await executeConfiguredBackup(
        this.env,
        this.env.DB,
        request.actorUserId,
        'manual',
        request.destinationId,
        () => this.touchJob(token),
        (event) => notifyUserBackupProgress(this.env, request.actorUserId, event, request.targetDeviceIdentifier),
        request.auditMetadata,
      );
      return { result, settings: await loadBackupSettings(this.env.DB, this.env, 'UTC') };
    } finally {
      await this.releaseJob(token);
    }
  }

  async runScheduledBackups(): Promise<void> {
    const token = await this.acquireJob('scheduled');
    if (!token) return;

    try {
      await this.touchJob(token);
      let scanStartMs = Date.now();

      while (true) {
        await this.touchJob(token);
        const settings = await loadBackupSettings(this.env.DB, this.env, 'UTC');
        const now = new Date();
        const dueDestinations = settings.destinations.filter(
          (destination) =>
            isBackupDueNow(destination, now, BACKUP_SCHEDULER_WINDOW_MINUTES) ||
            hasBackupSlotBetween(destination, new Date(scanStartMs), now),
        );

        if (!dueDestinations.length) {
          break;
        }

        scanStartMs = now.getTime();
        for (const destination of dueDestinations) {
          await this.touchJob(token);
          // One failing destination must not stop the others; executeConfiguredBackup has already
          // recorded the error in that destination's runtime state for the admin page.
          await executeConfiguredBackup(this.env, this.env.DB, null, 'scheduled', destination.id, () =>
            this.touchJob(token),
          ).catch((error: unknown) =>
            console.error('Scheduled backup failed', destination.id, withoutQueryParams(error)),
          );
        }
      }
    } finally {
      await this.releaseJob(token);
    }
  }

  async restoreRemoteBackup(request: RemoteBackupRestoreRequest): Promise<BackupImportResultBody | null> {
    const token = await this.acquireJob(`restore:${request.actorUserId}`);
    if (!token) return null;

    try {
      await this.touchJob(token);
      const settings = await loadBackupSettings(this.env.DB, this.env, 'UTC');
      const destination = requireBackupDestination(settings, request.destinationId);
      const path = ensureRemoteRestoreCandidate(request.path);
      const restoreFileNameFromPath = path.split('/').pop() || path;

      await notifyUserBackupRestoreProgress(
        this.env,
        request.actorUserId,
        {
          operation: 'backup-restore',
          source: 'remote',
          step: 'remote_fetch_archive',
          fileName: restoreFileNameFromPath,
          stageTitle: 'txt_backup_restore_progress_remote_fetch_title',
          stageDetail: 'txt_backup_restore_progress_remote_fetch_detail',
          replaceExisting: request.replaceExisting,
        },
        request.targetDeviceIdentifier,
      );

      const remoteFile = await downloadRemoteBackupFile(destination, path);
      const checksumOk = await verifyBackupArchiveFileNameChecksum(remoteFile.bytes, remoteFile.fileName || path);
      if (!checksumOk && !request.allowChecksumMismatch) {
        throw new Error('Remote backup file checksum does not match its filename');
      }

      const imported = await importAndAuditRemoteBackupFile(
        this.env,
        this.env.DB,
        request.actorUserId,
        remoteFile,
        destination,
        path,
        request.replaceExisting,
        !checksumOk,
        request.auditMetadata,
        request.targetDeviceIdentifier,
        () => this.touchJob(token),
      );
      return imported.result;
    } finally {
      await this.releaseJob(token);
    }
  }

  // Attachment bytes return as streams: RPC streams bypass the 32 MiB message cap that a large
  // attachment or a 40-file batch would otherwise hit.
  async downloadRemoteAttachment(
    destination: BackupDestinationRecord,
    blobName: string,
  ): Promise<ReadableStream<Uint8Array> | null> {
    if (!isSafeBackupAttachmentBlobName(blobName)) {
      throw new Error('Remote attachment download payload is invalid');
    }
    const file = await downloadRemoteBackupFile(destination, `attachments/${blobName}`).catch(() => null);
    return file ? new Response(file.bytes).body : null;
  }

  async downloadRemoteAttachmentBatch(
    destination: BackupDestinationRecord,
    blobNames: string[],
  ): Promise<ReadableStream<Uint8Array>> {
    const names = Array.from(new Set(blobNames.filter(isSafeBackupAttachmentBlobName)));
    if (!names.length || names.length > REMOTE_ATTACHMENT_BATCH_LIMIT) {
      throw new Error('Remote attachment batch download payload is invalid');
    }

    const entries: Array<{ blobName: string; path: string }> = [];
    const files: Record<string, Uint8Array> = {};
    for (const [index, blobName] of names.entries()) {
      const file = await downloadRemoteBackupFile(destination, `attachments/${blobName}`).catch(() => null);
      if (!file) continue;
      const path = `files/${index}.bin`;
      entries.push({ blobName, path });
      files[path] = file.bytes;
    }
    files['manifest.json'] = new TextEncoder().encode(JSON.stringify({ version: 1, entries }));
    return new Response(zipSync(files)).body!;
  }

  async uploadAttachmentChunk(
    destination: BackupDestinationRecord,
    attachments: Array<{ blobName: string }>,
  ): Promise<void> {
    const remoteSession = createRemoteBackupTransferSession(destination);
    for (const { blobName } of attachments) {
      if (!isSafeBackupAttachmentBlobName(blobName)) {
        throw new Error('Attachment chunk payload is invalid');
      }
      const object = await getBlobObject(this.env, blobName);
      if (!object) {
        throw new Error(`Attachment blob missing for ${blobName}`);
      }
      const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
      await remoteSession.putFile(`attachments/${blobName}`, bytes, {
        contentType: object.contentType,
      });
    }
  }
}
