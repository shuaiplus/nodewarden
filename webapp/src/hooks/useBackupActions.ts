import { useMemo } from 'preact/hooks';
import {
  type BackupExportClientProgressEvent,
  buildCompleteAdminBackupExport,
  deleteRemoteBackup,
  downloadRemoteBackup as fetchRemoteBackupPayload,
  getAdminBackupSettings,
  importAdminBackup,
  inspectRemoteBackupIntegrity,
  listRemoteBackups,
  restoreRemoteBackup as restoreRemoteBackupRequest,
  runAdminBackupNow,
  saveAdminBackupSettings,
} from '@/lib/api/backup';
import { downloadBytesAsFile } from '@/lib/download';
import { dispatchBackupProgress } from '@/lib/backup-restore-progress';
import type { AuthedFetch } from '@/lib/api/shared';

interface UseBackupActionsOptions {
  authedFetch: AuthedFetch;
  onImported?: () => void;
  onRestored?: () => void;
}

export default function useBackupActions(options: UseBackupActionsOptions) {
  const { authedFetch, onImported, onRestored } = options;

  return useMemo(
    () => ({
      async exportBackup(masterPasswordHash: string, includeAttachments: boolean = false) {
        const payload = await buildCompleteAdminBackupExport(
          authedFetch,
          masterPasswordHash,
          includeAttachments,
          async (event: BackupExportClientProgressEvent) => {
            dispatchBackupProgress(event);
          }
        );
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
        dispatchBackupProgress({
          operation: 'backup-export',
          source: 'local',
          step: 'export_complete',
          fileName: payload.fileName,
          stageTitle: 'txt_backup_export_progress_complete_title',
          stageDetail: 'txt_backup_export_progress_complete_detail',
          done: true,
          ok: true,
        });
      },

      async importBackup(masterPasswordHash: string, file: File, replaceExisting: boolean = false) {
        const result = await importAdminBackup(authedFetch, masterPasswordHash, file, replaceExisting);
        onImported?.();
        return result;
      },

      async importBackupAllowingChecksumMismatch(masterPasswordHash: string, file: File, replaceExisting: boolean = false) {
        const result = await importAdminBackup(authedFetch, masterPasswordHash, file, replaceExisting, true);
        onImported?.();
        return result;
      },

      async loadSettings() {
        return getAdminBackupSettings(authedFetch);
      },

      async saveSettings(masterPasswordHash: string, settings: Parameters<typeof saveAdminBackupSettings>[2]) {
        return saveAdminBackupSettings(authedFetch, masterPasswordHash, settings);
      },

      async runRemoteBackup(masterPasswordHash: string, destinationId?: string | null) {
        return runAdminBackupNow(authedFetch, masterPasswordHash, destinationId);
      },

      async listRemoteBackups(destinationId: string, path: string) {
        return listRemoteBackups(authedFetch, destinationId, path);
      },

      async downloadRemoteBackup(masterPasswordHash: string, destinationId: string, path: string, onProgress?: (percent: number | null) => void) {
        const payload = await fetchRemoteBackupPayload(authedFetch, masterPasswordHash, destinationId, path, onProgress);
        downloadBytesAsFile(payload.bytes, payload.fileName, payload.mimeType);
      },

      async inspectRemoteBackup(masterPasswordHash: string, destinationId: string, path: string) {
        return inspectRemoteBackupIntegrity(authedFetch, masterPasswordHash, destinationId, path);
      },

      async deleteRemoteBackup(masterPasswordHash: string, destinationId: string, path: string) {
        await deleteRemoteBackup(authedFetch, masterPasswordHash, destinationId, path);
      },

      async restoreRemoteBackup(masterPasswordHash: string, destinationId: string, path: string, replaceExisting: boolean = false) {
        const result = await restoreRemoteBackupRequest(authedFetch, masterPasswordHash, destinationId, path, replaceExisting);
        onRestored?.();
        return result;
      },

      async restoreRemoteBackupAllowingChecksumMismatch(masterPasswordHash: string, destinationId: string, path: string, replaceExisting: boolean = false) {
        const result = await restoreRemoteBackupRequest(authedFetch, masterPasswordHash, destinationId, path, replaceExisting, true);
        onRestored?.();
        return result;
      },
    }),
    [authedFetch, onImported, onRestored]
  );
}
