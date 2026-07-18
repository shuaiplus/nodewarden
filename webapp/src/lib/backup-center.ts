import {
  type BackupDestinationRecord,
  type BackupDestinationType,
  type BackupRuntimeState,
  type BackupSettings,
  createBackupDestinationRecord,
  createDefaultBackupSettings,
} from '@shared/backup-schema';
import type { RemoteBackupBrowserResponse, RemoteBackupItem } from './api/backup';
import { t } from './i18n';

export interface PersistedRemoteBrowserState {
  cache: Record<string, RemoteBackupBrowserResponse>;
  pathByDestination: Record<string, string>;
  pageByKey: Record<string, number>;
  selectedDestinationId: string | null;
  refreshedAt: Record<string, number>;
}

export const REMOTE_BROWSER_STORAGE_KEY = 'nodewarden.backup.remote-browser.v1';
export const REMOTE_BROWSER_ITEMS_PER_PAGE = 10;
export const REMOTE_BROWSER_REFRESH_TTL_MS = 5 * 60 * 1000; // 5 minutes

export const COMMON_TIME_ZONES = [
  'UTC',
  'Asia/Shanghai',
  'Asia/Tokyo',
  'Asia/Singapore',
  'Europe/London',
  'Europe/Berlin',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
];

export const WEEKDAY_OPTIONS = [
  { value: 1, label: 'txt_backup_weekday_monday' },
  { value: 2, label: 'txt_backup_weekday_tuesday' },
  { value: 3, label: 'txt_backup_weekday_wednesday' },
  { value: 4, label: 'txt_backup_weekday_thursday' },
  { value: 5, label: 'txt_backup_weekday_friday' },
  { value: 6, label: 'txt_backup_weekday_saturday' },
  { value: 0, label: 'txt_backup_weekday_sunday' },
] as const;

export function detectBrowserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}

function createLocalizedDestinationName(type: BackupDestinationType, index: number): string {
  if (type === 's3') return t('txt_backup_destination_name_default_s3', { index: String(index) });
  return t('txt_backup_destination_name_default_webdav', { index: String(index) });
}

export function createDraftDestinationRecord(type: BackupDestinationType, index: number): BackupDestinationRecord {
  return createBackupDestinationRecord(type, index, {
    timezone: detectBrowserTimeZone(),
    name: createLocalizedDestinationName(type, index),
  });
}

export function createDraftBackupSettings(): BackupSettings {
  return createDefaultBackupSettings(detectBrowserTimeZone(), {
    destinationName: createLocalizedDestinationName('webdav', 1),
  });
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_backup_never');
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

export function formatBytes(value: number | null | undefined): string {
  const n = Number(value || 0);
  if (!Number.isFinite(n) || n <= 0) return t('txt_backup_unknown_size');
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function isReplaceRequiredError(error: unknown): boolean {
  const message = error instanceof Error ? String(error.message || '') : '';
  return message.toLowerCase().includes('fresh instance');
}

export function isZipCandidate(item: RemoteBackupItem): boolean {
  return !item.isDirectory && /\.zip$/i.test(item.name || '');
}

function getRemoteItemSortTime(item: RemoteBackupItem): number {
  if (!item.modifiedAt) return 0;
  const parsed = new Date(item.modifiedAt);
  return Number.isFinite(parsed.getTime()) ? parsed.getTime() : 0;
}

export function compareRemoteItems(a: RemoteBackupItem, b: RemoteBackupItem): number {
  const aIsAttachmentsDir = a.isDirectory && a.name === 'attachments';
  const bIsAttachmentsDir = b.isDirectory && b.name === 'attachments';
  if (aIsAttachmentsDir !== bIsAttachmentsDir) return aIsAttachmentsDir ? -1 : 1;
  if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
  const timeDiff = getRemoteItemSortTime(b) - getRemoteItemSortTime(a);
  if (timeDiff !== 0) return timeDiff;
  return b.name.localeCompare(a.name, 'en');
}

export function getRemoteBrowserCacheKey(destinationId: string, path: string = ''): string {
  return `${destinationId}:${path}`;
}

function getRemoteBrowserStorageKey(userId?: string | null): string {
  const normalizedUserId = String(userId || '').trim();
  return normalizedUserId
    ? `${REMOTE_BROWSER_STORAGE_KEY}:${normalizedUserId}`
    : REMOTE_BROWSER_STORAGE_KEY;
}

function getRemoteBrowserStorage(): Storage | null {
  try {
    if (typeof window !== 'undefined' && window.localStorage) {
      return window.localStorage;
    }
  } catch {
    // Ignore storage access failures.
  }
  try {
    if (typeof window !== 'undefined' && window.sessionStorage) {
      return window.sessionStorage;
    }
  } catch {
    // Ignore storage access failures.
  }
  return null;
}

export function loadPersistedRemoteBrowserState(userId?: string | null): PersistedRemoteBrowserState {
  try {
    const storage = getRemoteBrowserStorage();
    const raw = storage?.getItem(getRemoteBrowserStorageKey(userId));
    if (!raw) {
      return {
        cache: {},
        pathByDestination: {},
        pageByKey: {},
        selectedDestinationId: null,
        refreshedAt: {},
      };
    }
    const parsed = JSON.parse(raw) as Partial<PersistedRemoteBrowserState>;
    return {
      cache: parsed.cache && typeof parsed.cache === 'object' ? parsed.cache : {},
      pathByDestination: parsed.pathByDestination && typeof parsed.pathByDestination === 'object' ? parsed.pathByDestination : {},
      pageByKey: parsed.pageByKey && typeof parsed.pageByKey === 'object' ? parsed.pageByKey : {},
      selectedDestinationId: typeof parsed.selectedDestinationId === 'string' ? parsed.selectedDestinationId : null,
      refreshedAt: parsed.refreshedAt && typeof parsed.refreshedAt === 'object' ? parsed.refreshedAt as Record<string, number> : {},
    };
  } catch {
    return {
      cache: {},
      pathByDestination: {},
      pageByKey: {},
      selectedDestinationId: null,
      refreshedAt: {},
    };
  }
}

export function persistRemoteBrowserState(userId: string | null | undefined, state: PersistedRemoteBrowserState): void {
  try {
    const storage = getRemoteBrowserStorage();
    storage?.setItem(getRemoteBrowserStorageKey(userId), JSON.stringify(state));
  } catch {
    // Ignore cache persistence failures.
  }
}

export function invalidateRemoteBrowserCacheForDestination(
  destinationId: string,
  cache: Record<string, RemoteBackupBrowserResponse>,
  pathByDestination: Record<string, string>,
  pageByKey: Record<string, number>
): PersistedRemoteBrowserState {
  return {
    cache: Object.fromEntries(Object.entries(cache).filter(([key]) => !key.startsWith(`${destinationId}:`))),
    pathByDestination: Object.fromEntries(Object.entries(pathByDestination).filter(([key]) => key !== destinationId)),
    pageByKey: Object.fromEntries(Object.entries(pageByKey).filter(([key]) => !key.startsWith(`${destinationId}:`))),
    selectedDestinationId: destinationId,
  };
}

export function getDestinationById(
  settings: BackupSettings | null,
  destinationId: string | null | undefined
): BackupDestinationRecord | null {
  if (!settings || !destinationId) return null;
  return settings.destinations.find((destination) => destination.id === destinationId) || null;
}

export function getVisibleDestinations(settings: BackupSettings | null | undefined): BackupDestinationRecord[] {
  return settings?.destinations || [];
}

export function getFirstVisibleDestinationId(settings: BackupSettings | null | undefined): string | null {
  return getVisibleDestinations(settings)[0]?.id || null;
}

export function getDestinationTypeLabel(type: BackupDestinationType): string {
  if (type === 's3') return t('txt_backup_protocol_s3');
  return t('txt_backup_protocol_webdav');
}
