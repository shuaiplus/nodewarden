// Shared backup settings types used by both Worker and webapp code.
//
// CONTRACT:
// Keep this file serializable and provider-neutral. Runtime state is operational
// metadata; destination fields can contain provider credentials and must be
// encrypted by src/services/backup-settings-crypto.ts before storage/export.
// User-facing provider names should use canonical values here. Legacy aliases
// belong in backend normalization, not in this shared type.
export const BACKUP_DEFAULT_TIMEZONE = 'UTC';
export const BACKUP_DEFAULT_RETENTION_COUNT = 30;
export const BACKUP_DEFAULT_S3_REGION = 'auto';
export const BACKUP_DEFAULT_S3_ROOT_PATH = '';
export const BACKUP_DEFAULT_WEBDAV_REMOTE_PATH = 'nodewarden';
export const BACKUP_DEFAULT_INTERVAL_HOURS = 24;
export const BACKUP_DEFAULT_START_TIME = '03:00';

export type BackupDestinationType = 's3' | 'webdav';
export type S3BackupAddressingStyle = 'path-style' | 'virtual-hosted-style';

export interface S3BackupDestination {
  endpoint: string;
  bucket: string;
  addressingStyle: S3BackupAddressingStyle;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  rootPath: string;
}

export interface WebDavBackupDestination {
  baseUrl: string;
  username: string;
  password: string;
  remotePath: string;
}

export type BackupDestinationConfig =
  | S3BackupDestination
  | WebDavBackupDestination;

export interface BackupRuntimeState {
  lastAttemptAt: string | null;
  lastAttemptLocalDate: string | null;
  lastSuccessAt: string | null;
  lastErrorAt: string | null;
  lastErrorMessage: string | null;
  lastUploadedFileName: string | null;
  lastUploadedSizeBytes: number | null;
  lastUploadedDestination: string | null;
}

export interface BackupScheduleConfig {
  enabled: boolean;
  intervalHours: number;
  startTime: string;
  timezone: string;
  retentionCount: number | null;
}

export interface BackupDestinationRecord {
  id: string;
  name: string;
  type: BackupDestinationType;
  includeAttachments: boolean;
  destination: BackupDestinationConfig;
  schedule: BackupScheduleConfig;
  runtime: BackupRuntimeState;
}

export interface BackupSettings {
  destinations: BackupDestinationRecord[];
}

export function createBackupRandomId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `backup-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

export function createDefaultBackupRuntimeState(): BackupRuntimeState {
  return {
    lastAttemptAt: null,
    lastAttemptLocalDate: null,
    lastSuccessAt: null,
    lastErrorAt: null,
    lastErrorMessage: null,
    lastUploadedFileName: null,
    lastUploadedSizeBytes: null,
    lastUploadedDestination: null,
  };
}

export function createDefaultBackupScheduleConfig(timezone: string = BACKUP_DEFAULT_TIMEZONE): BackupScheduleConfig {
  return {
    enabled: false,
    intervalHours: BACKUP_DEFAULT_INTERVAL_HOURS,
    startTime: BACKUP_DEFAULT_START_TIME,
    timezone,
    retentionCount: BACKUP_DEFAULT_RETENTION_COUNT,
  };
}

export function createDefaultBackupDestinationConfig(type: BackupDestinationType): BackupDestinationConfig {
  if (type === 's3') {
    return {
      endpoint: '',
      bucket: '',
      addressingStyle: 'path-style',
      region: BACKUP_DEFAULT_S3_REGION,
      accessKeyId: '',
      secretAccessKey: '',
      rootPath: BACKUP_DEFAULT_S3_ROOT_PATH,
    };
  }
  return {
    baseUrl: '',
    username: '',
    password: '',
    remotePath: BACKUP_DEFAULT_WEBDAV_REMOTE_PATH,
  };
}

export function createDefaultBackupDestinationName(type: BackupDestinationType, index: number): string {
  if (type === 's3') return `S3 ${index}`;
  return `WebDAV ${index}`;
}

export interface CreateBackupDestinationRecordOptions {
  id?: string;
  name?: string;
  timezone?: string;
}

export function createBackupDestinationRecord(
  type: BackupDestinationType,
  index: number,
  options: CreateBackupDestinationRecordOptions = {}
): BackupDestinationRecord {
  return {
    id: options.id || createBackupRandomId(),
    name: options.name || createDefaultBackupDestinationName(type, index),
    type,
    includeAttachments: false,
    destination: createDefaultBackupDestinationConfig(type),
    schedule: createDefaultBackupScheduleConfig(options.timezone || BACKUP_DEFAULT_TIMEZONE),
    runtime: createDefaultBackupRuntimeState(),
  };
}

export function createDefaultBackupSettings(
  timezone: string = BACKUP_DEFAULT_TIMEZONE,
  options: { destinationName?: string } = {}
): BackupSettings {
  return {
    destinations: [
      createBackupDestinationRecord('webdav', 1, {
        timezone,
        name: options.destinationName,
      }),
    ],
  };
}
