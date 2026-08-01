import type { Env } from '../types';
import type { BackupDestinationRecord } from '../services/backup-config';
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
import { getBlobObject } from '../services/blob-store';
import { StorageService } from '../services/storage';
import { notifyUserBackupProgress, notifyUserBackupRestoreProgress } from './notifications-hub';
import {
  executeConfiguredBackup,
  importAndAuditRemoteBackupFile,
} from '../handlers/backup';
import { isSafeBackupAttachmentBlobName, verifyBackupArchiveFileNameChecksum } from '../services/backup-archive';
import { zipSync } from 'fflate';

const BACKUP_JOB_STATE_KEY = 'backup.job.state.v1';
const BACKUP_JOB_LEASE_MS = 10 * 60 * 1000;
const BACKUP_JOB_HEARTBEAT_MS = 30 * 1000;

interface BackupJobState {
  token: string;
  reason: string;
  acquiredAt: string;
  touchedAt: string;
  expiresAtMs: number;
}

interface RemoteAttachmentChunkRequest {
  destination: BackupDestinationRecord;
  attachments: Array<{
    blobName: string;
  }>;
}

interface RemoteAttachmentDownloadRequest {
  destination: BackupDestinationRecord;
  blobName?: string | null;
}

interface RemoteAttachmentBatchDownloadRequest {
  destination: BackupDestinationRecord;
  blobNames?: string[] | null;
}

interface ConfiguredBackupRunRequest {
  actorUserId?: string | null;
  auditMetadata?: Record<string, unknown> | null;
  destinationId?: string | null;
  targetDeviceIdentifier?: string | null;
  trigger?: 'manual' | 'scheduled';
}

interface RemoteBackupRestoreRequest {
  actorUserId?: string | null;
  allowChecksumMismatch?: boolean;
  auditMetadata?: Record<string, unknown> | null;
  destinationId?: string | null;
  path?: string | null;
  replaceExisting?: boolean;
  targetDeviceIdentifier?: string | null;
}

function badRequest(message: string, status: number = 400): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}

export class BackupTransferRunner {
  private lastHeartbeatAt = 0;

  constructor(
    private readonly state: DurableObjectState,
    private readonly env: Env
  ) {
  }

  private async acquireJob(reason: string): Promise<string | null> {
    const nowMs = Date.now();
    const current = await this.state.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.expiresAtMs && current.expiresAtMs > nowMs) {
      return null;
    }

    const token = crypto.randomUUID();
    const nowIso = new Date(nowMs).toISOString();
    await this.state.storage.put<BackupJobState>(BACKUP_JOB_STATE_KEY, {
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

    const current = await this.state.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.token !== token) return;

    await this.state.storage.put<BackupJobState>(BACKUP_JOB_STATE_KEY, {
      ...current,
      touchedAt: new Date(nowMs).toISOString(),
      expiresAtMs: nowMs + BACKUP_JOB_LEASE_MS,
    });
  }

  private async releaseJob(token: string): Promise<void> {
    const current = await this.state.storage.get<BackupJobState>(BACKUP_JOB_STATE_KEY);
    if (current?.token === token) {
      await this.state.storage.delete(BACKUP_JOB_STATE_KEY);
    }
  }

  private async runConfiguredBackup(request: Request): Promise<Response> {
    let body: ConfiguredBackupRunRequest;
    try {
      body = await request.json<ConfiguredBackupRunRequest>();
    } catch {
      return badRequest('Backup run payload is invalid');
    }

    const trigger = body.trigger === 'scheduled' ? 'scheduled' : 'manual';
    const actorUserId = String(body.actorUserId || '').trim() || null;
    if (trigger === 'manual' && !actorUserId) {
      return badRequest('Manual backup run requires an actor');
    }

    const token = await this.acquireJob(`${trigger}:${actorUserId || 'system'}`);
    if (!token) {
      return badRequest('Another backup run is already in progress', 409);
    }

    try {
      await this.touchJob(token);
      const storage = new StorageService(this.env.DB);
      const progress = actorUserId
        ? async (event: {
          operation: 'backup-remote-run';
          step: string;
          fileName: string;
          stageTitle: string;
          stageDetail: string;
          done?: boolean;
          ok?: boolean;
          error?: string | null;
        }) => {
          await notifyUserBackupProgress(
            this.env,
            actorUserId,
            event,
            String(body.targetDeviceIdentifier || '').trim() || null
          );
        }
        : null;

      const result = await executeConfiguredBackup(
        this.env,
        storage,
        actorUserId,
        trigger,
        body.destinationId || null,
        () => this.touchJob(token),
        progress,
        body.auditMetadata || null
      );
      const settings = await loadBackupSettings(storage, this.env, 'UTC');

      return new Response(JSON.stringify({
        object: 'backup-runner-result',
        result,
        settings,
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    } catch (error) {
      return badRequest(error instanceof Error ? error.message : 'Backup run failed', 500);
    } finally {
      await this.releaseJob(token);
    }
  }

  private async runScheduledBackups(): Promise<Response> {
    const token = await this.acquireJob('scheduled');
    if (!token) {
      return badRequest('Another backup run is already in progress', 409);
    }

    let completed = 0;
    const failures: Array<{ destinationId: string; error: string }> = [];
    try {
      await this.touchJob(token);
      const storage = new StorageService(this.env.DB);
      let scanStartMs = Date.now();

      while (true) {
        await this.touchJob(token);
        const settings = await loadBackupSettings(storage, this.env, 'UTC');
        const now = new Date();
        const dueDestinations = settings.destinations.filter((destination) =>
          isBackupDueNow(destination, now, BACKUP_SCHEDULER_WINDOW_MINUTES)
          || hasBackupSlotBetween(destination, new Date(scanStartMs), now)
        );

        if (!dueDestinations.length) {
          break;
        }

        scanStartMs = now.getTime();
        for (const destination of dueDestinations) {
          await this.touchJob(token);
          try {
            await executeConfiguredBackup(
              this.env,
              storage,
              null,
              'scheduled',
              destination.id,
              () => this.touchJob(token)
            );
            completed += 1;
          } catch (error) {
            failures.push({
              destinationId: destination.id,
              error: error instanceof Error ? error.message : 'Scheduled backup failed',
            });
          }
        }
      }

      return new Response(JSON.stringify({
        ok: true,
        completed,
        failed: failures.length,
        failures,
      }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    } catch (error) {
      return badRequest(error instanceof Error ? error.message : 'Scheduled backup failed', 500);
    } finally {
      await this.releaseJob(token);
    }
  }

  private async restoreRemoteBackup(request: Request): Promise<Response> {
    let body: RemoteBackupRestoreRequest;
    try {
      body = await request.json<RemoteBackupRestoreRequest>();
    } catch {
      return badRequest('Remote restore payload is invalid');
    }

    const actorUserId = String(body.actorUserId || '').trim() || null;
    if (!actorUserId) {
      return badRequest('Remote restore requires an actor');
    }

    const token = await this.acquireJob(`restore:${actorUserId}`);
    if (!token) {
      return badRequest('Another backup or restore run is already in progress', 409);
    }

    try {
      await this.touchJob(token);
      const storage = new StorageService(this.env.DB);
      const settings = await loadBackupSettings(storage, this.env, 'UTC');
      const destination = requireBackupDestination(settings, body.destinationId || null);
      const path = ensureRemoteRestoreCandidate(String(body.path || ''));
      const restoreFileNameFromPath = path.split('/').pop() || path;
      const targetDeviceIdentifier = String(body.targetDeviceIdentifier || '').trim() || null;
      const replaceExisting = !!body.replaceExisting;

      await notifyUserBackupRestoreProgress(
        this.env,
        actorUserId,
        {
          operation: 'backup-restore',
          source: 'remote',
          step: 'remote_fetch_archive',
          fileName: restoreFileNameFromPath,
          stageTitle: 'txt_backup_restore_progress_remote_fetch_title',
          stageDetail: 'txt_backup_restore_progress_remote_fetch_detail',
          replaceExisting,
        },
        targetDeviceIdentifier
      );

      const remoteFile = await downloadRemoteBackupFile(destination, path);
      const checksumOk = await verifyBackupArchiveFileNameChecksum(remoteFile.bytes, remoteFile.fileName || path);
      if (!checksumOk && !body.allowChecksumMismatch) {
        return badRequest('Remote backup file checksum does not match its filename');
      }

      const result = await importAndAuditRemoteBackupFile(
        this.env,
        storage,
        actorUserId,
        remoteFile,
        destination,
        path,
        replaceExisting,
        !checksumOk,
        body.auditMetadata || null,
        targetDeviceIdentifier,
        () => this.touchJob(token)
      );

      return new Response(JSON.stringify(result.result), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    } catch (error) {
      return badRequest(error instanceof Error ? error.message : 'Remote backup restore failed', 500);
    } finally {
      await this.releaseJob(token);
    }
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (request.method !== 'POST') {
      return badRequest('Not found', 404);
    }

    if (url.pathname === '/internal/run-configured-backup') {
      return this.runConfiguredBackup(request);
    }

    if (url.pathname === '/internal/run-scheduled-backups') {
      return this.runScheduledBackups();
    }

    if (url.pathname === '/internal/restore-remote-backup') {
      return this.restoreRemoteBackup(request);
    }

    if (url.pathname === '/internal/download-remote-attachment') {
      let body: RemoteAttachmentDownloadRequest;
      try {
        body = await request.json<RemoteAttachmentDownloadRequest>();
      } catch {
        return badRequest('Remote attachment download payload is invalid');
      }
      const blobName = String(body?.blobName || '').trim();
      if (!body?.destination || !isSafeBackupAttachmentBlobName(blobName)) {
        return badRequest('Remote attachment download payload is invalid');
      }
      const file = await downloadRemoteBackupFile(body.destination, `attachments/${blobName}`).catch(() => null);
      if (!file) {
        return badRequest('Remote attachment not found', 404);
      }
      return new Response(file.bytes, {
        status: 200,
        headers: {
          'Content-Type': file.contentType || 'application/octet-stream',
          'Cache-Control': 'no-store',
        },
      });
    }

    if (url.pathname === '/internal/download-remote-attachment-batch') {
      let body: RemoteAttachmentBatchDownloadRequest;
      try {
        body = await request.json<RemoteAttachmentBatchDownloadRequest>();
      } catch {
        return badRequest('Remote attachment batch download payload is invalid');
      }
      const blobNames = Array.from(new Set(
        (Array.isArray(body?.blobNames) ? body.blobNames : [])
          .map((blobName) => String(blobName || '').trim())
          .filter(isSafeBackupAttachmentBlobName)
      ));
      if (!body?.destination || !blobNames.length || blobNames.length > 40) {
        return badRequest('Remote attachment batch download payload is invalid');
      }

      const encoder = new TextEncoder();
      const entries: Array<{ blobName: string; path: string }> = [];
      const files: Record<string, Uint8Array> = {};
      for (let i = 0; i < blobNames.length; i += 1) {
        const blobName = blobNames[i];
        const file = await downloadRemoteBackupFile(body.destination, `attachments/${blobName}`).catch(() => null);
        if (!file) continue;
        const path = `files/${i}.bin`;
        entries.push({ blobName, path });
        files[path] = file.bytes;
      }
      files['manifest.json'] = encoder.encode(JSON.stringify({ version: 1, entries }));

      return new Response(zipSync(files), {
        status: 200,
        headers: {
          'Content-Type': 'application/zip',
          'Cache-Control': 'no-store',
        },
      });
    }

    if (url.pathname !== '/internal/upload-attachment-chunk') {
      return badRequest('Not found', 404);
    }

    let body: RemoteAttachmentChunkRequest;
    try {
      body = await request.json<RemoteAttachmentChunkRequest>();
    } catch {
      return badRequest('Attachment chunk payload is invalid');
    }

    if (!body?.destination || !Array.isArray(body.attachments)) {
      return badRequest('Attachment chunk payload is invalid');
    }

    const remoteSession = createRemoteBackupTransferSession(body.destination);
    let uploaded = 0;

    for (const attachment of body.attachments) {
      const blobName = String(attachment?.blobName || '').trim();
      if (!isSafeBackupAttachmentBlobName(blobName)) {
        return badRequest('Attachment chunk payload is invalid');
      }

      const object = await getBlobObject(this.env, blobName);
      if (!object) {
        return badRequest(`Attachment blob missing for ${blobName}`, 409);
      }

      const bytes = new Uint8Array(await new Response(object.body).arrayBuffer());
      await remoteSession.putFile(`attachments/${blobName}`, bytes, {
        contentType: object.contentType,
      });
      uploaded += 1;
    }

    return new Response(JSON.stringify({
      ok: true,
      uploaded,
    }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  }
}
