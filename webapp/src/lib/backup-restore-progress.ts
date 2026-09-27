export type BackupProgressOperation = 'backup-restore' | 'backup-export' | 'backup-remote-run';

export interface BackupProgressDetail {
  operation: BackupProgressOperation;
  source?: 'local' | 'remote';
  step: string;
  fileName: string;
  stageTitle?: string;
  stageDetail?: string;
  replaceExisting?: boolean;
  done?: boolean;
  ok?: boolean;
  error?: string | null;
  Date?: string;
}

export const BACKUP_PROGRESS_EVENT = 'nodewarden:backup-progress';

export function dispatchBackupProgress(detail: BackupProgressDetail): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new CustomEvent<BackupProgressDetail>(BACKUP_PROGRESS_EVENT, { detail }));
}
