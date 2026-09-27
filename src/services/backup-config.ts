import { convertIPv4MappedIPv6ToIPv4, convertIPv4ToBinary, convertIPv6ToBinary, isIPv4MappedIPv6 } from 'hono/utils/ipaddr';
import { z } from 'zod';
import type { Env, User } from '../types';
import {
  type BackupSettingsPortableEnvelope,
  decryptBackupSettingsRuntime,
  encryptBackupSettingsEnvelope,
  parseBackupSettingsEnvelope,
} from './backup-settings-crypto';
import {
  BACKUP_DEFAULT_S3_REGION,
  BACKUP_DEFAULT_TIMEZONE,
  type BackupDestinationRecord,
  type BackupRuntimeState,
  type BackupSettings,
  type S3BackupAddressingStyle,
  type S3BackupDestination,
  type WebDavBackupDestination,
  createBackupRandomId,
  createDefaultBackupDestinationName,
  createDefaultBackupRuntimeState,
  createDefaultBackupScheduleConfig,
  createDefaultBackupSettings as createSharedDefaultBackupSettings,
} from '../../shared/backup-schema';
import * as configRepo from './storage-config-repo';
import * as userRepo from './storage-user-repo';

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

export interface BackupSettingsRepairState {
  needsRepair: boolean;
  portable: BackupSettingsPortableEnvelope | null;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asTrimmedString(value: unknown): string {
  return String(value ?? '').trim();
}

function normalizeHostnameForPolicy(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
}

// Backup destinations must not reach private, loopback, link-local, carrier-grade NAT, benchmarking,
// documentation, multicast or reserved space (SSRF). An IPv4-mapped IPv6 address is judged by its IPv4.
const BLOCKED_IPV4 = ([['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.0.0.0', 16], ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 3]] as const)
  .map(([network, prefix]) => [convertIPv4ToBinary(network), prefix] as const);
const BLOCKED_IPV6 = ([['::', 16], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32]] as const)
  .map(([network, prefix]) => [convertIPv6ToBinary(network), prefix] as const);
// URL parsing canonicalises IPv4 hosts to dotted quads; anything else with dots is a DNS name.
const IPV4_LITERAL = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const inBlockedRange = (address: bigint, width: number, ranges: ReadonlyArray<readonly [bigint, number]>) =>
  ranges.some(([network, prefix]) => address >> BigInt(width - prefix) === network >> BigInt(width - prefix));

function isBlockedIpAddress(hostname: string): boolean {
  if (IPV4_LITERAL.test(hostname)) return inBlockedRange(convertIPv4ToBinary(hostname), 32, BLOCKED_IPV4);
  if (!hostname.includes(':')) return false;
  try {
    const address = convertIPv6ToBinary(hostname);
    return isIPv4MappedIPv6(address)
      ? inBlockedRange(convertIPv4MappedIPv6ToIPv4(address), 32, BLOCKED_IPV4)
      : inBlockedRange(address, 128, BLOCKED_IPV6);
  } catch {
    return true;
  }
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
  if (isBlockedIpAddress(normalized)) {
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

function isValidTimeZone(timezone: string): boolean {
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(new Date());
    return true;
  } catch {
    return false;
  }
}

// Settings fields read leniently, as stored rows and older clients expect: absent, null and
// non-string values become their trimmed string form instead of failing the save.
const text = z.preprocess(asTrimmedString, z.string());
const remotePath = text.transform((path) => path.replace(/\\/g, '/').replace(/^\/+|\/+$/g, ''));
const nullableText = text.transform((value) => value || null);
const isoTimestamp = text.transform((value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
});

function integerBetween(min: number, max: number, error: string) {
  return z.preprocess(Number, z.int({ error }).min(min, { error }).max(max, { error }));
}

// The SSRF policy stays in normalizeBackupEndpointUrl, which backup-uploader re-applies before every
// transfer; here its message becomes the field's issue.
function endpointUrl(label: string) {
  return text.transform((url, context) => {
    try {
      return url && normalizeBackupEndpointUrl(url, label);
    } catch (error) {
      context.issues.push({ code: 'custom', message: (error as Error).message, input: url });
      return z.NEVER;
    }
  });
}

// A scheduled destination needs every credential; an unscheduled one may be saved half-filled.
function requireWhenScheduled(enabled: boolean, context: z.RefinementCtx, fields: Array<[field: string, value: string, message: string]>): void {
  if (!enabled) return;
  fields
    .filter(([, value]) => !value)
    .forEach(([field, , message]) => context.addIssue({ code: 'custom', message, path: ['destination', field] }));
}

const BackupRuntimeSchema = z.preprocess((runtime) => (isPlainObject(runtime) ? runtime : {}), z.object({
  lastAttemptAt: isoTimestamp,
  lastAttemptLocalDate: nullableText,
  lastSuccessAt: isoTimestamp,
  lastErrorAt: isoTimestamp,
  lastErrorMessage: nullableText,
  lastUploadedFileName: nullableText,
  lastUploadedSizeBytes: z.preprocess((size) => {
    const bytes = size === null || size === '' ? Number.NaN : Number(size);
    return Number.isFinite(bytes) && bytes >= 0 ? Math.floor(bytes) : null;
  }, z.number().nullable()),
  lastUploadedDestination: nullableText,
}));

const destinationRecordFields = {
  id: z.string(),
  name: z.string(),
  includeAttachments: z.boolean(),
  schedule: z.object({
    enabled: z.preprocess(Boolean, z.boolean()),
    intervalHours: integerBetween(1, 99, 'Backup interval hours must be between 1 and 99'),
    startTime: z.string()
      .regex(/^([01]?\d|2[0-3])(?::[0-5]?\d)?$/, { error: 'Backup start time must be in HH:mm format' })
      .transform((time) => {
        const [hour, minute = '0'] = time.split(':');
        return `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`;
      }),
    timezone: z.string().refine(isValidTimeZone, { error: 'Invalid backup timezone' }),
    retentionCount: z.preprocess(
      (count) => (count === null || String(count).trim() === '' ? null : count),
      integerBetween(1, 1000, 'Backup retention count must be between 1 and 1000').nullable()
    ),
  }),
  runtime: BackupRuntimeSchema,
};

const BackupDestinationRecordSchema = z.discriminatedUnion('type', [
  z.object({
    ...destinationRecordFields,
    type: z.literal('s3'),
    destination: z.object({
      endpoint: endpointUrl('S3 endpoint'),
      bucket: text,
      addressingStyle: text.transform((style): S3BackupAddressingStyle => (style === 'virtual-hosted-style' ? style : 'path-style')),
      region: text.transform((region) => region || BACKUP_DEFAULT_S3_REGION),
      accessKeyId: text,
      secretAccessKey: text,
      rootPath: remotePath,
    }),
  }).superRefine(({ schedule, destination }, context) => requireWhenScheduled(schedule.enabled, context, [
    ['endpoint', destination.endpoint, 'S3 endpoint is required'],
    ['bucket', destination.bucket, 'S3 bucket is required'],
    ['accessKeyId', destination.accessKeyId, 'S3 access key is required'],
    ['secretAccessKey', destination.secretAccessKey, 'S3 secret key is required'],
  ])),
  z.object({
    ...destinationRecordFields,
    type: z.literal('webdav'),
    destination: z.object({
      baseUrl: endpointUrl('WebDAV server URL'),
      username: text,
      password: z.preprocess((password) => String(password ?? ''), z.string()),
      remotePath,
    }),
  }).superRefine(({ schedule, destination }, context) => requireWhenScheduled(schedule.enabled, context, [
    ['baseUrl', destination.baseUrl, 'WebDAV server URL is required'],
    ['username', destination.username, 'WebDAV username is required'],
    ['password', destination.password, 'WebDAV password is required'],
  ])),
], { error: (issue) => (issue.code === 'invalid_union' ? 'Backup destination type is invalid' : 'Backup destination is invalid') });

// A save may omit fields: they keep the values of the stored destination with the same id (or the
// defaults), and a blank or redacted secret keeps the stored secret. The schema then validates the
// merged record. Entries that are not objects or name an unknown type pass through for the schema
// to reject.
function withStoredDestination(
  input: unknown,
  index: number,
  previousById: ReadonlyMap<string, BackupDestinationRecord>,
  fallbackTimezone: string
): unknown {
  if (!isPlainObject(input)) return input;
  const requestedType = asTrimmedString(input.type);
  const type = requestedType === 'e3' ? 's3' : requestedType;
  if (type !== 's3' && type !== 'webdav') return input;

  const id = asTrimmedString(input.id) || createBackupRandomId();
  const previous = previousById.get(id);
  const previousSchedule = previous?.schedule ?? createDefaultBackupScheduleConfig(fallbackTimezone);
  const schedule = isPlainObject(input.schedule) ? input.schedule : {};
  const destination = isPlainObject(input.destination) ? input.destination : {};
  const secretField = type === 's3' ? 'secretAccessKey' : 'password';
  const previousDestination: Record<string, unknown> = previous?.type === type ? { ...previous.destination } : {};
  const keepSecret = ['', REDACTED_BACKUP_SECRET].includes(String(destination[secretField] ?? ''));
  return {
    id,
    name: asTrimmedString(input.name) || previous?.name || createDefaultBackupDestinationName(type, index + 1),
    type,
    includeAttachments: typeof input.includeAttachments === 'boolean' ? input.includeAttachments : previous?.includeAttachments ?? false,
    destination: keepSecret ? { ...destination, [secretField]: previousDestination[secretField] || '' } : destination,
    schedule: {
      enabled: schedule.enabled ?? previousSchedule.enabled,
      intervalHours: schedule.intervalHours == null || schedule.intervalHours === '' ? previousSchedule.intervalHours : schedule.intervalHours,
      startTime: asTrimmedString(schedule.startTime) || previousSchedule.startTime,
      timezone: asTrimmedString(schedule.timezone ?? previousSchedule.timezone) || fallbackTimezone,
      retentionCount: Object.hasOwn(schedule, 'retentionCount') ? schedule.retentionCount : previousSchedule.retentionCount,
    },
    runtime: previous?.runtime ?? input.runtime,
  };
}

function backupSettingsSchema(previousById: ReadonlyMap<string, BackupDestinationRecord>, fallbackTimezone: string) {
  return z.object({
    destinations: z.array(z.unknown(), { error: 'Backup destinations are invalid' })
      .max(MAX_BACKUP_DESTINATIONS, { error: `You can save up to ${MAX_BACKUP_DESTINATIONS} backup destinations` })
      .transform((entries) => entries.map((entry, index) => withStoredDestination(entry, index, previousById, fallbackTimezone)))
      .pipe(z.array(BackupDestinationRecordSchema))
      .refine((destinations) => new Set(destinations.map(({ id }) => id)).size === destinations.length, {
        error: 'Backup destination ids must be unique',
      }),
  });
}

// Rows written before per-destination schedules are not migrated: the defaults come back and the
// administrator re-saves the schedule once.
const ScheduledSettingsRowSchema = z.object({ destinations: z.array(z.looseObject({ schedule: z.looseObject({}) })) });

const BackupRuntimeRowSchema = z.object({ destinations: z.record(z.string(), BackupRuntimeSchema) });

function stripRuntimeFromSettings(settings: BackupSettings): BackupSettings {
  return {
    destinations: settings.destinations.map((destination) => ({
      ...destination,
      runtime: createDefaultBackupRuntimeState(),
    })),
  };
}

function serializeRuntimeState(settings: BackupSettings): string {
  return JSON.stringify({
    version: 1,
    destinations: Object.fromEntries(
      settings.destinations.map((destination) => [destination.id, BackupRuntimeSchema.parse(destination.runtime)])
    ),
  });
}

async function loadBackupRuntimeStates(db: D1Database): Promise<Map<string, BackupRuntimeState>> {
  const raw = await configRepo.getConfigValue(db, BACKUP_RUNTIME_CONFIG_KEY);
  if (!raw) return new Map();
  try {
    const { destinations } = BackupRuntimeRowSchema.catch({ destinations: {} }).parse(JSON.parse(raw));
    return new Map(Object.entries(destinations).filter(([id]) => id.trim()));
  } catch {
    return new Map();
  }
}

function mergeRuntimeStates(settings: BackupSettings, runtimes: Map<string, BackupRuntimeState>): BackupSettings {
  return {
    destinations: settings.destinations.map((destination) => ({
      ...destination,
      runtime: runtimes.get(destination.id) || BackupRuntimeSchema.parse(destination.runtime),
    })),
  };
}

export function getDefaultBackupSettings(timezone: string = 'UTC'): BackupSettings {
  if (!isValidTimeZone(timezone)) throw new Error('Invalid backup timezone');
  return createSharedDefaultBackupSettings(timezone);
}

export function parseBackupSettings(raw: string | null, fallbackTimezone: string = 'UTC'): BackupSettings {
  const defaults = () => getDefaultBackupSettings(fallbackTimezone);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw ?? '');
  } catch {
    return defaults();
  }
  if (!ScheduledSettingsRowSchema.safeParse(parsed).success) return defaults();
  const settings = backupSettingsSchema(new Map(), fallbackTimezone).safeParse(parsed);
  return settings.success ? settings.data : defaults();
}

export function normalizeBackupSettingsInput(destinations: unknown, previous: BackupSettings) {
  const previousById = new Map(previous.destinations.map((destination) => [destination.id, destination]));
  return backupSettingsSchema(previousById, BACKUP_DEFAULT_TIMEZONE).safeParse({ destinations: destinations ?? previous.destinations });
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

export async function loadBackupSettings(db: D1Database, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettings> {
  const raw = await configRepo.getConfigValue(db, BACKUP_SETTINGS_CONFIG_KEY);
  const mergeRuntime = async (settings: BackupSettings): Promise<BackupSettings> => (
    mergeRuntimeStates(settings, await loadBackupRuntimeStates(db))
  );
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(db, env, settings);
    return mergeRuntime(settings);
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(db, env, settings);
    return mergeRuntime(settings);
  }

  try {
    const decrypted = await decryptBackupSettingsRuntime(raw, env);
    return mergeRuntime(parseBackupSettings(decrypted, fallbackTimezone));
  } catch {
    throw new Error('Backup settings need administrator reactivation after restore');
  }
}

export async function saveBackupSettings(db: D1Database, env: Env, settings: BackupSettings): Promise<void> {
  const users = await userRepo.getAllUsers(db);
  const encrypted = await encryptBackupSettingsEnvelope(serializeBackupSettings(settings), env, users);
  await configRepo.setConfigValue(db, BACKUP_SETTINGS_CONFIG_KEY, encrypted);
  await saveBackupRuntimeStates(db, settings);
}

export async function saveBackupRuntimeStates(db: D1Database, settings: BackupSettings): Promise<void> {
  await configRepo.setConfigValue(db, BACKUP_RUNTIME_CONFIG_KEY, serializeRuntimeState(settings));
}

export async function updateBackupDestinationRuntime(
  db: D1Database,
  destinationId: string,
  mutator: (runtime: BackupRuntimeState) => BackupRuntimeState
): Promise<BackupRuntimeState> {
  const runtimes = await loadBackupRuntimeStates(db);
  const current = runtimes.get(destinationId) || createDefaultBackupRuntimeState();
  const next = BackupRuntimeSchema.parse(mutator(current));
  runtimes.set(destinationId, next);
  await configRepo.setConfigValue(db, BACKUP_RUNTIME_CONFIG_KEY, JSON.stringify({
    version: 1,
    destinations: Object.fromEntries(runtimes.entries()),
  }));
  return next;
}

export async function normalizeImportedBackupSettings(db: D1Database, env: Env, fallbackTimezone: string = 'UTC'): Promise<void> {
  const raw = await configRepo.getConfigValue(db, BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) return;
  const users = await userRepo.getAllUsers(db);
  const normalized = await normalizeImportedBackupSettingsValue(raw, env, users, fallbackTimezone);
  if (normalized !== null) {
    await configRepo.setConfigValue(db, BACKUP_SETTINGS_CONFIG_KEY, normalized);
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

export async function getBackupSettingsRepairState(db: D1Database, env: Env, fallbackTimezone: string = 'UTC'): Promise<BackupSettingsRepairState> {
  const raw = await configRepo.getConfigValue(db, BACKUP_SETTINGS_CONFIG_KEY);
  if (!raw) {
    const settings = getDefaultBackupSettings(fallbackTimezone);
    await saveBackupSettings(db, env, settings);
    return { needsRepair: false, portable: null };
  }

  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    const settings = parseBackupSettings(raw, fallbackTimezone);
    await saveBackupSettings(db, env, settings);
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

export async function repairBackupSettings(db: D1Database, env: Env, settings: BackupSettings): Promise<void> {
  await saveBackupSettings(db, env, settings);
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
  const parsedTime = startTime.split(':').map((value) => Number(value));
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
