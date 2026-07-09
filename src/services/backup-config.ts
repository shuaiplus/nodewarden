import type { Env, User } from '../types';
import { StorageService } from './storage';
import {
  type BackupSettingsPortableEnvelope,
  decryptBackupSettingsRuntime,
  encryptBackupSettingsEnvelope,
  parseBackupSettingsEnvelope,
} from './backup-settings-crypto';
import {
  BACKUP_DEFAULT_INTERVAL_HOURS,
  BACKUP_DEFAULT_START_TIME,
  BACKUP_DEFAULT_TIMEZONE,
  type BackupDestinationConfig,
  type BackupDestinationRecord,
  type BackupDestinationType,
  type BackupRuntimeState,
  type BackupScheduleConfig,
  type BackupSettings,
  type S3BackupAddressingStyle,
  type S3BackupDestination,
  type WebDavBackupDestination,
  createBackupRandomId,
  createDefaultBackupDestinationName,
  createDefaultBackupScheduleConfig,
  createDefaultBackupSettings as createSharedDefaultBackupSettings,
} from '../../shared/backup-schema';

export const BACKUP_SETTINGS_CONFIG_KEY = 'backup.settings.v1';
const BACKUP_RUNTIME_CONFIG_KEY = 'backup.runtime.v1';
export const BACKUP_SCHEDULER_WINDOW_MINUTES = 5;
export const REDACTED_BACKUP_SECRET = '********';
const MAX_BACKUP_DESTINATIONS = 24;

export type {
  BackupDestinationConfig,
  BackupDestinationRecord,
  BackupDestinationType,
  BackupRuntimeState,
  BackupScheduleConfig,
  BackupSettings,
  S3BackupAddressingStyle,
  S3BackupDestination,
  WebDavBackupDestination,
} from '../../shared/backup-schema';

export interface BackupSettingsInput {
  destinations?: unknown;
}

export interface BackupSettingsRepairState {
  needsRepair: boolean;
  portable: BackupSettingsPortableEnvelope | null;
}

function defaultScheduleConfig(timezone: string = 'UTC'): BackupScheduleConfig {
  return { ...createDefaultBackupScheduleConfig(assertValidTimeZone(timezone)) };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

function normalizePath(value: unknown): string {
  return asTrimmedString(value).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
}

function normalizeHostnameForPolicy(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

function parseIpv4Address(hostname: string): number[] | null {
  const parts = hostname.split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map((part) => {
    if (!/^\d{1,3}$/.test(part)) return -1;
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255 ? value : -1;
  });
  return octets.every((value) => value >= 0) ? octets : null;
}

function isBlockedIpv4Address(octets: number[]): boolean {
  const [a, b, c] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isBlockedIpv6Address(hostname: string): boolean {
  if (!hostname.includes(':')) return false;
  const normalized = hostname.toLowerCase();
  const mappedIpv4 = normalized.match(/::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mappedIpv4) {
    const octets = parseIpv4Address(mappedIpv4[1]);
    return !octets || isBlockedIpv4Address(octets);
  }
  const firstHextetText = normalized.split(':').find((part) => part.length > 0) || '0';
  const firstHextet = Number.parseInt(firstHextetText, 16);
  if (!Number.isFinite(firstHextet)) return true;
  return (
    firstHextet === 0 ||
    (firstHextet & 0xfe00) === 0xfc00 ||
    (firstHextet & 0xffc0) === 0xfe80 ||
    (firstHextet & 0xff00) === 0xff00 ||
    normalized.startsWith('2001:db8:')
  );
}

function assertBackupEndpointHostAllowed(hostname: string, label: string): void {
  const normalized = normalizeHostnameForPolicy(hostname);
  if (!normalized) throw new Error(`${label} host is required`);
  if (
    normalized === 'localhost' ||
    normalized === 'localhost.localdomain' ||
    normalized.endsWith('.localhost.localdomain') ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.home.arpa') ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.lan') ||
    normalized === 'metadata.google.internal' ||
    normalized === 'localtest.me' ||
    normalized.endsWith('.localtest.me') ||
    normalized === 'lvh.me' ||
    normalized.endsWith('.lvh.me') ||
    normalized === 'vcap.me' ||
    normalized.endsWith('.vcap.me') ||
    normalized === 'nip.io' ||
    normalized.endsWith('.nip.io') ||
    normalized === 'sslip.io' ||
    normalized.endsWith('.sslip.io') ||
    normalized === 'xip.io' ||
    normalized.endsWith('.xip.io')
  ) {
    throw new Error(`${label} host is not allowed`);
  }
  const ipv4 = parseIpv4Address(normalized);
  if (ipv4 && isBlockedIpv4Address(ipv4)) {
    throw new Error(`${label} host is not allowed`);
  }
  if (isBlockedIpv6Address(normalized)) {
    throw new Error(`${label} host is not allowed`);
  }
}

export function normalizeBackupEndpointUrl(value: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid URL`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`${label} must start with http:// or https://`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`${label} must not include credentials`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(`${label} must not include query or fragment`);
  }
  assertBackupEndpointHostAllowed(parsed.hostname, label);
  return parsed.toString().replace(/\/+$/, '');
}

function assertValidTimeZone(timezone: string): string {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(new Date());
    return timezone;
  } catch {
    throw new Error('Invalid backup timezone');
  }
}

function normalizeRetentionCount(value: unknown, fallback: number | null = 30): number | null {
  if (value === undefined) return fallback;
  if (value === null || String(value).trim() === '') return null;
  const count = Number(value);
  if (!Number.isInteger(count) || count < 1 || count > 1000) {
    throw new Error('Backup retention count must be between 1 and 1000');
  }
  return count;
}

function normalizeIntervalHours(value: unknown, fallback: number = BACKUP_DEFAULT_INTERVAL_HOURS): number {
  const raw = value === undefined || value === null || value === '' ? fallback : Number(value);
  if (!Number.isInteger(raw) || raw < 1 || raw > 99) {
    throw new Error('Backup interval hours must be between 1 and 99');
  }
  return raw;
}

function normalizeStartTime(value: unknown, fallback: string = BACKUP_DEFAULT_START_TIME): string {
  const raw = asTrimmedString(value) || fallback;
  const match = raw.match(/^(\d{1,2})(?::(\d{1,2}))?$/);
  if (!match) {
    throw new Error('Backup start time must be in HH:mm format');
  }
  const hour = Number(match[1]);
  const minute = Number(match[2] ?? '0');
  if (!Number.isInteger(hour) || !Number.isInteger(minute) || hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    throw new Error('Backup start time must be in HH:mm format');
  }
  return `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`;
}

function normalizeS3Destination(value: unknown, allowIncomplete = false): S3BackupDestination {
  const source = isPlainObject(value) ? value : {};
  const endpoint = asTrimmedString(source.endpoint);
  const bucket = asTrimmedString(source.bucket);
  const addressingStyleRaw = asTrimmedString(source.addressingStyle);
  const addressingStyle: S3BackupAddressingStyle =
    addressingStyleRaw === 'virtual-hosted-style' ? 'virtual-hosted-style' : 'path-style';
  const accessKeyId = asTrimmedString(source.accessKeyId);
  const secretAccessKey = asTrimmedString(source.secretAccessKey);
  const region = asTrimmedString(source.region) || 'auto';
  const rootPath = normalizePath(source.rootPath);

  if (!allowIncomplete || endpoint) {
    if (!endpoint) throw new Error('S3 endpoint is required');
    normalizeBackupEndpointUrl(endpoint, 'S3 endpoint');
  }
  if (!allowIncomplete || bucket) {
    if (!bucket) throw new Error('S3 bucket is required');
  }
  if (!allowIncomplete || accessKeyId) {
    if (!accessKeyId) throw new Error('S3 access key is required');
  }
  if (!allowIncomplete || secretAccessKey) {
    if (!secretAccessKey) throw new Error('S3 secret key is required');
  }

  return {
    endpoint: endpoint ? normalizeBackupEndpointUrl(endpoint, 'S3 endpoint') : '',
    bucket,
    addressingStyle,
    region,
    accessKeyId,
    secretAccessKey,
    rootPath,
  };
}

function normalizeWebDavDestination(value: unknown, allowIncomplete = false): WebDavBackupDestination {
  const source = isPlainObject(value) ? value : {};
  const baseUrl = asTrimmedString(source.baseUrl);
  const username = asTrimmedString(source.username);
  const password = String(source.password ?? '');
  const remotePath = normalizePath(source.remotePath);

  if (!allowIncomplete || baseUrl) {
    if (!baseUrl) throw new Error('WebDAV server URL is required');
    normalizeBackupEndpointUrl(baseUrl, 'WebDAV server URL');
  }
  if (!allowIncomplete || username) {
    if (!username) throw new Error('WebDAV username is required');
  }
  if (!allowIncomplete || password) {
    if (!password) throw new Error('WebDAV password is required');
  }

  return {
    baseUrl: baseUrl ? normalizeBackupEndpointUrl(baseUrl, 'WebDAV server URL') : '',
    username,
    password,
    remotePath,
  };
}

function normalizeDestination(
  destinationType: BackupDestinationType,
  destination: unknown,
  allowIncomplete = false
): BackupDestinationConfig {
  if (destinationType === 's3') return normalizeS3Destination(destination, allowIncomplete);
  return normalizeWebDavDestination(destination, allowIncomplete);
}

function shouldPreserveBackupSecret(value: unknown): boolean {
  if (value === undefined || value === null) return true;
  const raw = String(value);
  return raw === '' || raw === REDACTED_BACKUP_SECRET;
}

function withPreservedDestinationSecret(
  destinationType: BackupDestinationType,
  inputDestination: unknown,
  previous: BackupDestinationRecord | undefined
): unknown {
  const source = isPlainObject(inputDestination) ? { ...inputDestination } : {};
  if (destinationType === 's3') {
    const previousDestination = previous?.type === 's3' ? previous.destination as S3BackupDestination : null;
    if (shouldPreserveBackupSecret(source.secretAccessKey)) {
      source.secretAccessKey = previousDestination?.secretAccessKey || '';
    }
  } else {
    const previousDestination = previous?.type === 'webdav' ? previous.destination as WebDavBackupDestination : null;
    if (shouldPreserveBackupSecret(source.password)) {
      source.password = previousDestination?.password || '';
    }
  }
  return source;
}

function normalizeRuntime(value: unknown): BackupRuntimeState {
  const source = isPlainObject(value) ? value : {};
  const asIso = (input: unknown): string | null => {
    const raw = asTrimmedString(input);
    if (!raw) return null;
    const date = new Date(raw);
    return Number.isFinite(date.getTime()) ? date.toISOString() : null;
  };
  const asMaybeNumber = (input: unknown): number | null => {
    if (input === null || input === undefined || input === '') return null;
    const n = Number(input);
    return Number.isFinite(n) && n >= 0 ? Math.floor(n) : null;
  };
  return {
    lastAttemptAt: asIso(source.lastAttemptAt),
    lastAttemptLocalDate: asTrimmedString(source.lastAttemptLocalDate) || null,
    lastSuccessAt: asIso(source.lastSuccessAt),
    lastErrorAt: asIso(source.lastErrorAt),
    lastErrorMessage: asTrimmedString(source.lastErrorMessage) || null,
    lastUploadedFileName: asTrimmedString(source.lastUploadedFileName) || null,
    lastUploadedSizeBytes: asMaybeNumber(source.lastUploadedSizeBytes),
    lastUploadedDestination: asTrimmedString(source.lastUploadedDestination) || null,
  };
}

function defaultDestinationName(type: BackupDestinationType, index: number): string {
  return createDefaultBackupDestinationName(type, index);
}

function getDestinationType(raw: unknown): BackupDestinationType {
  const value = asTrimmedString(raw);
  if (value === 'e3') return 's3';
  if (value === 's3' || value === 'webdav') return value;
  throw new Error('Backup destination type is invalid');
}

function normalizeDestinationRecord(
  input: unknown,
  previousById: Map<string, BackupDestinationRecord>,
  index: number,
  fallbackTimezone: string
): BackupDestinationRecord {
  if (!isPlainObject(input)) {
    throw new Error('Backup destination is invalid');
  }

  const id = asTrimmedString(input.id) || createBackupRandomId();
  const type = getDestinationType(input.type);
  const previous = previousById.get(id);
  const runtime = previous?.runtime ? normalizeRuntime(previous.runtime) : normalizeRuntime(input.runtime);
  const name = asTrimmedString(input.name) || previous?.name || defaultDestinationName(type, index + 1);
  const scheduleSource = isPlainObject(input.schedule) ? input.schedule : {};
  const previousSchedule = previous?.schedule || defaultScheduleConfig(fallbackTimezone);
  const retentionSource = Object.prototype.hasOwnProperty.call(scheduleSource, 'retentionCount')
    ? scheduleSource.retentionCount
    : previousSchedule.retentionCount;
  const schedule: BackupScheduleConfig = {
    enabled: !!(scheduleSource.enabled ?? previousSchedule.enabled),
    intervalHours: normalizeIntervalHours(
      scheduleSource.intervalHours ?? previousSchedule.intervalHours,
      previousSchedule.intervalHours || BACKUP_DEFAULT_INTERVAL_HOURS
    ),
    startTime: normalizeStartTime(
      scheduleSource.startTime ?? previousSchedule.startTime,
      previousSchedule.startTime || BACKUP_DEFAULT_START_TIME
    ),
    timezone: assertValidTimeZone(asTrimmedString(scheduleSource.timezone ?? previousSchedule.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE),
    retentionCount: normalizeRetentionCount(retentionSource, previousSchedule.retentionCount),
  };

  const destination = normalizeDestination(
    type,
    withPreservedDestinationSecret(type, input.destination, previous),
    !schedule.enabled
  );

  return {
    id,
    name,
    type,
    includeAttachments: typeof input.includeAttachments === 'boolean'
      ? input.includeAttachments
      : previous?.includeAttachments ?? false,
    destination,
    schedule,
    runtime,
  };
}

function parseLegacyBackupSettings(rawValue: Record<string, unknown>, fallbackTimezone: string): BackupSettings {
  const legacyFrequency = asTrimmedString(rawValue.frequency).toLowerCase();
  const intervalHours = legacyFrequency === 'weekly'
    ? 24 * 7
    : legacyFrequency === 'monthly'
      ? 24 * 30
      : BACKUP_DEFAULT_INTERVAL_HOURS;
  const destinationTypeRaw = asTrimmedString(rawValue.destinationType);
  const destinationType: BackupDestinationType =
    destinationTypeRaw === 'e3' || destinationTypeRaw === 's3' || destinationTypeRaw === 'webdav'
      ? getDestinationType(destinationTypeRaw)
      : 'webdav';
  const destination = {
    id: createBackupRandomId(),
    name: defaultDestinationName(destinationType, 1),
    type: destinationType,
    includeAttachments: false,
    destination: normalizeDestination(destinationType, rawValue.destination),
    schedule: {
      enabled: !!rawValue.enabled,
      intervalHours,
      startTime: BACKUP_DEFAULT_START_TIME,
      timezone: assertValidTimeZone(asTrimmedString(rawValue.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE),
      retentionCount: 30,
    },
    runtime: normalizeRuntime(rawValue.runtime),
  } satisfies BackupDestinationRecord;

  return {
    destinations: [destination],
  };
}

function parseDestinations(
  rawDestinations: unknown,
  previousById: Map<string, BackupDestinationRecord>,
  fallbackTimezone: string
): BackupDestinationRecord[] {
  if (!Array.isArray(rawDestinations)) {
    throw new Error('Backup destinations are invalid');
  }
  if (rawDestinations.length > MAX_BACKUP_DESTINATIONS) {
    throw new Error(`You can save up to ${MAX_BACKUP_DESTINATIONS} backup destinations`);
  }

  const destinations = rawDestinations.map((entry, index) => normalizeDestinationRecord(entry, previousById, index, fallbackTimezone));
  const ids = new Set<string>();
  for (const destination of destinations) {
    if (ids.has(destination.id)) {
      throw new Error('Backup destination ids must be unique');
    }
    ids.add(destination.id);
  }
  return destinations;
}

function mapDestinationsById(destinations: BackupDestinationRecord[]): Map<string, BackupDestinationRecord> {
  return new Map(destinations.map((destination) => [destination.id, destination]));
}

function stripRuntimeFromSettings(settings: BackupSettings): BackupSettings {
  return {
    destinations: settings.destinations.map((destination) => ({
      ...destination,
      runtime: normalizeRuntime(null),
    })),
  };
}

function serializeRuntimeState(settings: BackupSettings): string {
  return JSON.stringify({
    version: 1,
    destinations: Object.fromEntries(
      settings.destinations.map((destination) => [destination.id, normalizeRuntime(destination.runtime)])
    ),
  });
}

async function loadBackupRuntimeStates(storage: StorageService): Promise<Map<string, BackupRuntimeState>> {
  const raw = await storage.getConfigValue(BACKUP_RUNTIME_CONFIG_KEY);
  if (!raw) return new Map();
  try {
    const parsed = JSON.parse(raw) as { destinations?: Record<string, unknown> };
    const entries = Object.entries(parsed.destinations || {})
      .filter(([id]) => !!asTrimmedString(id))
      .map(([id, runtime]) => [id, normalizeRuntime(runtime)] as const);
    return new Map(entries);
  } catch {
    return new Map();
  }
}

function mergeRuntimeStates(settings: BackupSettings, runtimes: Map<string, BackupRuntimeState>): BackupSettings {
  return {
    destinations: settings.destinations.map((destination) => ({
      ...destination,
      runtime: runtimes.get(destination.id) || normalizeRuntime(destination.runtime),
    })),
  };
}

export function getDefaultBackupSettings(timezone: string = 'UTC'): BackupSettings {
  return createSharedDefaultBackupSettings(assertValidTimeZone(timezone));
}

export function parseBackupSettings(raw: string | null, fallbackTimezone: string = 'UTC'): BackupSettings {
  if (!raw) return getDefaultBackupSettings(fallbackTimezone);
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (Array.isArray(parsed.destinations)) {
      const globalTimezone = assertValidTimeZone(asTrimmedString(parsed.timezone) || fallbackTimezone || BACKUP_DEFAULT_TIMEZONE);
      const globalEnabled = !!parsed.enabled;
      const activeDestinationIdRaw = asTrimmedString(parsed.activeDestinationId);
      const globalFrequency = asTrimmedString(parsed.frequency).toLowerCase();
      const globalIntervalHours = globalFrequency === 'weekly'
        ? 24 * 7
        : globalFrequency === 'monthly'
          ? 24 * 30
          : BACKUP_DEFAULT_INTERVAL_HOURS;
      const previousById = new Map<string, BackupDestinationRecord>();
      const normalizedEntries = (parsed.destinations as unknown[]).map((entry) => {
        if (!isPlainObject(entry)) return entry;
        if (isPlainObject(entry.schedule)) return entry;
        const entryId = asTrimmedString(entry.id);
        const scheduleEnabled = globalEnabled && (!activeDestinationIdRaw || entryId === activeDestinationIdRaw);
        return {
          ...entry,
          schedule: {
            enabled: scheduleEnabled,
            intervalHours: globalIntervalHours,
            startTime: BACKUP_DEFAULT_START_TIME,
            timezone: globalTimezone,
            retentionCount: 30,
          },
        };
      });
      return {
        destinations: parseDestinations(normalizedEntries, previousById, fallbackTimezone),
      };
    }
    return parseLegacyBackupSettings(parsed, fallbackTimezone);
  } catch {
    return getDefaultBackupSettings(fallbackTimezone);
  }
}

export function normalizeBackupSettingsInput(
  input: BackupSettingsInput,
  previous: BackupSettings
): BackupSettings {
  if (!isPlainObject(input)) {
    throw new Error('Backup settings payload is invalid');
  }

  const previousById = mapDestinationsById(previous.destinations);
  const rawDestinations = input.destinations ?? previous.destinations;
  const destinations = parseDestinations(rawDestinations, previousById, BACKUP_DEFAULT_TIMEZONE);

  return {
    destinations,
  };
}

export function serializeBackupSettings(settings: BackupSettings): string {
  return JSON.stringify(stripRuntimeFromSettings(settings));
}

export function redactBackupSettingsSecrets(settings: BackupSettings): BackupSettings {
  return {
    destinations: settings.destinations.map((destination) => {
      if (destination.type === 's3') {
        const config = destination.destination as S3BackupDestination;
        return {
          ...destination,
          destination: {
            ...config,
            secretAccessKey: config.secretAccessKey ? REDACTED_BACKUP_SECRET : '',
          },
        };
      }
      const config = destination.destination as WebDavBackupDestination;
      return {
        ...destination,
        destination: {
          ...config,
          password: config.password ? REDACTED_BACKUP_SECRET : '',
        },
      };
    }),
  };
}

export async function loadBackupSettings(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettings> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  const mergeRuntime = async (settings: BackupSettings): Promise<BackupSettings> => (
    mergeRuntimeStates(settings, await loadBackupRuntimeStates(storage))
  );
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return mergeRuntime(settings);
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return mergeRuntime(settings);
  }

  try {
    const decrypted = await decryptBackupSettingsRuntime(raw, env);
    return mergeRuntime(parseBackupSettings(decrypted, fallbackTimezone));
  } catch {
    throw new Error('Backup settings need administrator reactivation after restore');
  }
}

export async function saveBackupSettings(storage: StorageService, env: Env, settings: BackupSettings): Promise<void> {
  const users = await storage.getAllUsers();
  const encrypted = await encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
  await storage.setConfigValue(BACKUP_SETTINGS_CONFIG_KEY, encrypted);
  await saveBackupRuntimeStates(storage, settings);
}

export async function saveBackupRuntimeStates(storage: StorageService, settings: BackupSettings): Promise<void> {
  await storage.setConfigValue(BACKUP_RUNTIME_CONFIG_KEY, serializeRuntimeState(settings));
}

export async function updateBackupDestinationRuntime(
  storage: StorageService,
  destinationId: string,
  mutator: (runtime: BackupRuntimeState) => BackupRuntimeState
): Promise<BackupRuntimeState> {
  const runtimes = await loadBackupRuntimeStates(storage);
  const current = runtimes.get(destinationId) || normalizeRuntime(null);
  const next = normalizeRuntime(mutator(current));
  runtimes.set(destinationId, next);
  await storage.setConfigValue(BACKUP_RUNTIME_CONFIG_KEY, JSON.stringify({
    version: 1,
    destinations: Object.fromEntries(runtimes.entries()),
  }));
  return next;
}

export async function normalizeImportedBackupSettings(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<void> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) return;
  const users = await storage.getAllUsers();
  const normalized = await normalizeImportedBackupSettingsValue(raw, env, users, fallbackTimezone);
  if (normalized !== null) {
    await storage.setConfigValue(BACKUP_SETTINGS_CONFIG_KEY, normalized);
  }
}

export async function normalizeImportedBackupSettingsValue(
  raw: string | null,
  env: Env,
  users: Pick<User, 'id' | 'publicKey' | 'role' | 'status'>[],
  fallbackTimezone: string = 'UTC'
): Promise<string | null> {
  if (!raw) return null;
  const envelope = parseBackupSettingsEnvelope(raw);
  if (envelope) {
    try {
      const decrypted = await decryptBackupSettingsRuntime(raw, env);
      const settings = parseBackupSettings(decrypted, fallbackTimezone);
      return encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
    } catch {
      // Keep imported portable recovery data intact until an admin signs in and repairs it.
      return raw;
    }
  }
  const settings = parseBackupSettings(raw, fallbackTimezone);
  return encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
}

export async function getBackupSettingsRepairState(storage: StorageService, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettingsRepairState> {
  const raw = await storage.getConfigValue(BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return { needsRepair: false, portable: null };
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(storage, env, settings);
    return { needsRepair: false, portable: null };
  }

  try {
    await decryptBackupSettingsRuntime(raw, env);
    return { needsRepair: false, portable: null };
  } catch {
    return {
      needsRepair: true,
      portable: envelope.portable,
    };
  }
}

export async function repairBackupSettings(storage: StorageService, env: Env, settings: BackupSettings): Promise<void> {
  await saveBackupSettings(storage, env, settings);
}

export function findBackupDestination(
  settings: BackupSettings,
  destinationId: string | null | undefined
): BackupDestinationRecord | null {
  const normalizedId = asTrimmedString(destinationId);
  if (!normalizedId) return null;
  return settings.destinations.find((destination) => destination.id === normalizedId) || null;
}

export function requireBackupDestination(settings: BackupSettings, destinationId?: string | null): BackupDestinationRecord {
  const destination = destinationId ? findBackupDestination(settings, destinationId) : settings.destinations[0] || null;
  if (!destination) {
    throw new Error('Backup destination not found');
  }
  return destination;
}

function getDateTimeParts(date: Date, timezone: string): { year: string; month: string; day: string; hour: string; minute: string } {
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: timezone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(date);
  const pick = (type: string): string => parts.find((part) => part.type === type)?.value || '';
  return {
    year: pick('year'),
    month: pick('month'),
    day: pick('day'),
    hour: pick('hour'),
    minute: pick('minute'),
  };
}

export function getBackupLocalDateKey(date: Date, timezone: string): string {
  const parts = getDateTimeParts(date, timezone);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

export function getBackupLocalTime(date: Date, timezone: string): string {
  const parts = getDateTimeParts(date, timezone);
  return `${parts.hour}:${parts.minute}`;
}

function parseLocalDateKey(dateKey: string): { year: number; month: number; day: number } | null {
  const match = String(dateKey || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
  return { year, month, day };
}

function getUtcDateForLocalTime(timezone: string, year: number, month: number, day: number, hour: number, minute: number): Date {
  const utcGuess = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  const actual = getDateTimeParts(new Date(utcGuess), timezone);
  const actualUtc = Date.UTC(
    Number(actual.year),
    Number(actual.month) - 1,
    Number(actual.day),
    Number(actual.hour),
    Number(actual.minute),
    0,
    0
  );
  const desiredUtc = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  return new Date(utcGuess - (actualUtc - desiredUtc));
}

function getBackupSlotStartsForLocalDay(
  dateKey: string,
  timezone: string,
  startTime: string,
  intervalHours: number
): Date[] {
  const parsedDate = parseLocalDateKey(dateKey);
  const parsedTime = normalizeStartTime(startTime).split(':').map((value) => Number(value));
  if (!parsedDate || parsedTime.length !== 2) return [];

  const [hour, minute] = parsedTime;
  const firstSlot = getUtcDateForLocalTime(timezone, parsedDate.year, parsedDate.month, parsedDate.day, hour, minute);
  const nextLocalDay = new Date(Date.UTC(parsedDate.year, parsedDate.month - 1, parsedDate.day, 0, 0, 0, 0));
  nextLocalDay.setUTCDate(nextLocalDay.getUTCDate() + 1);
  const nextDay = getUtcDateForLocalTime(
    timezone,
    nextLocalDay.getUTCFullYear(),
    nextLocalDay.getUTCMonth() + 1,
    nextLocalDay.getUTCDate(),
    0,
    0
  );
  const intervalMs = intervalHours * 60 * 60 * 1000;
  const slots: Date[] = [];

  for (let slotMs = firstSlot.getTime(); slotMs < nextDay.getTime(); slotMs += intervalMs) {
    slots.push(new Date(slotMs));
  }
  return slots;
}

export function hasBackupSlotBetween(
  destination: BackupDestinationRecord,
  startInclusive: Date,
  endExclusive: Date
): boolean {
  if (!destination.schedule.enabled) return false;
  const startMs = startInclusive.getTime();
  const endMs = endExclusive.getTime();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) return false;

  const lastSuccessAt = destination.runtime.lastSuccessAt ? new Date(destination.runtime.lastSuccessAt) : null;
  const lastSuccessMs = lastSuccessAt && Number.isFinite(lastSuccessAt.getTime())
    ? lastSuccessAt.getTime()
    : Number.NEGATIVE_INFINITY;

  const dayCursor = new Date(startMs);
  dayCursor.setUTCHours(0, 0, 0, 0);
  const endDay = new Date(endMs);
  endDay.setUTCHours(0, 0, 0, 0);
  const checkedLocalDateKeys = new Set<string>();

  while (dayCursor.getTime() <= endDay.getTime() + 24 * 60 * 60 * 1000) {
    const localDateKey = getBackupLocalDateKey(dayCursor, destination.schedule.timezone);
    if (!checkedLocalDateKeys.has(localDateKey)) {
      checkedLocalDateKeys.add(localDateKey);
      const slotStarts = getBackupSlotStartsForLocalDay(
        localDateKey,
        destination.schedule.timezone,
        destination.schedule.startTime,
        destination.schedule.intervalHours
      );
      for (const slotStart of slotStarts) {
        const slotStartMs = slotStart.getTime();
        if (slotStartMs < startMs || slotStartMs >= endMs) continue;
        if (lastSuccessMs >= slotStartMs) continue;
        return true;
      }
    }
    dayCursor.setUTCDate(dayCursor.getUTCDate() + 1);
  }

  return false;
}

export function isBackupDueNow(
  destination: BackupDestinationRecord,
  now: Date,
  windowMinutes: number = BACKUP_SCHEDULER_WINDOW_MINUTES
): boolean {
  if (!destination.schedule.enabled) return false;
  const toleranceMs = Math.max(1, windowMinutes) * 60 * 1000;
  const lastSuccessAt = destination.runtime.lastSuccessAt ? new Date(destination.runtime.lastSuccessAt) : null;
  const lastSuccessMs = lastSuccessAt && Number.isFinite(lastSuccessAt.getTime())
    ? lastSuccessAt.getTime()
    : Number.NEGATIVE_INFINITY;
  const localDateKey = getBackupLocalDateKey(now, destination.schedule.timezone);
  const slotStarts = getBackupSlotStartsForLocalDay(
    localDateKey,
    destination.schedule.timezone,
    destination.schedule.startTime,
    destination.schedule.intervalHours
  );

  for (const slotStart of slotStarts) {
    const slotStartMs = slotStart.getTime();
    if (now.getTime() < slotStartMs || now.getTime() >= slotStartMs + toleranceMs) continue;
    if (lastSuccessMs >= slotStartMs) return false;
    return true;
  }
  return false;
}
