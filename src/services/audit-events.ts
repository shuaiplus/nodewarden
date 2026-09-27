import type { SQL } from 'drizzle-orm';
import { getOrm, withoutQueryParams } from '../db/client';
import { auditLogs } from '../db/schema';
import { SINGLE_ROW, bound } from '../db/sql';
import type { Env } from '../types';
import { generateUUID } from '../utils/uuid';
import * as adminRepo from './storage-admin-repo';
import * as configRepo from './storage-config-repo';

export type AuditLogCategory = 'auth' | 'security' | 'device' | 'data' | 'system';
export type AuditLogLevel = 'info' | 'warn' | 'error' | 'security';

export interface AuditEventInput {
  actorUserId?: string | null;
  action: string;
  category: AuditLogCategory;
  level?: AuditLogLevel;
  targetType?: string | null;
  targetId?: string | null;
  metadata?: Record<string, unknown> | null;
}

const SENSITIVE_KEY_RE = /(token|secret|password|key|hash|code|private)/i;
const MAX_METADATA_BYTES = 2048;
const AUDIT_CLEANUP_INTERVAL_MS = 6 * 60 * 60 * 1000;
const AUDIT_CLEANUP_PROBABILITY = 0.02;
const AUDIT_LOG_SETTINGS_KEY = 'audit.logs.settings.v1';
export const DEFAULT_AUDIT_LOG_SETTINGS: AuditLogSettings = {
  retentionDays: 90,
  maxEntries: null,
};
let lastAuditCleanupAt = 0;

export interface AuditLogSettings {
  retentionDays: number | null;
  maxEntries: number | null;
}

const ALLOWED_METADATA_KEYS = new Set([
  'method',
  'path',
  'ip',
  'userAgent',
  'email',
  'adminEmail',
  'targetEmail',
  'grantType',
  'webSession',
  'deviceIdentifier',
  'deviceType',
  'reason',
  'status',
  'role',
  'verifyDevices',
  'changed',
  'removed',
  'updated',
  'deleted',
  'removedTrusted',
  'removedSessions',
  'removedDevices',
  'requested',
  'count',
  'requestedCount',
  'type',
  'folderId',
  'cipherId',
  'size',
  'users',
  'ciphers',
  'attachments',
  'skippedAttachments',
  'skippedReason',
  'replaceExisting',
  'provider',
  'prfStatus',
  'fileName',
  'fileBytes',
  'bytes',
  'compressedBytes',
  'includesAttachments',
  'destinationName',
  'destinationId',
  'destinationType',
  'destinationCount',
  'scheduledDestinationCount',
  'retentionDays',
  'maxEntries',
  'remotePath',
  'trigger',
  'prunedFileCount',
  'pruneError',
  'uploadVerificationAttempts',
  'error',
  'expiresInHours',
  'checksumMismatchAccepted',
]);

function normalizePositiveInteger(value: unknown, allowed: readonly number[]): number | null {
  if (value === null || value === 0 || value === '0' || value === 'forever' || value === 'unlimited') return null;
  const parsed = Math.floor(Number(value));
  return allowed.includes(parsed) ? parsed : null;
}

export function normalizeAuditLogSettings(value: unknown): AuditLogSettings {
  const input = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  const retentionDays = normalizePositiveInteger(input.retentionDays, [7, 30, 90, 180, 365]);
  const maxEntries = normalizePositiveInteger(input.maxEntries, [1_000, 5_000, 10_000, 50_000]);

  if (retentionDays) return { retentionDays, maxEntries: null };
  if (maxEntries) return { retentionDays: null, maxEntries };
  if (input.retentionDays === null || input.retentionDays === 0 || input.retentionDays === '0') {
    return { retentionDays: null, maxEntries: null };
  }
  if (input.maxEntries === null || input.maxEntries === 0 || input.maxEntries === '0') {
    return { retentionDays: null, maxEntries: null };
  }

  return {
    ...DEFAULT_AUDIT_LOG_SETTINGS,
  };
}

export function auditRequestMetadata(request: Request): Record<string, unknown> {
  const url = new URL(request.url);
  return {
    method: request.method,
    path: url.pathname,
    ip: request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || null,
    userAgent: request.headers.get('User-Agent') || null,
  };
}

export async function getAuditLogSettings(db: D1Database): Promise<AuditLogSettings> {
  const raw = await configRepo.getConfigValue(db, AUDIT_LOG_SETTINGS_KEY);
  if (!raw) return { ...DEFAULT_AUDIT_LOG_SETTINGS };
  try {
    return normalizeAuditLogSettings(JSON.parse(raw));
  } catch {
    return { ...DEFAULT_AUDIT_LOG_SETTINGS };
  }
}

export async function saveAuditLogSettings(db: D1Database, settings: AuditLogSettings): Promise<AuditLogSettings> {
  const normalized = normalizeAuditLogSettings(settings);
  await configRepo.setConfigValue(db, AUDIT_LOG_SETTINGS_KEY, JSON.stringify(normalized));
  await applyAuditLogRetention(db, normalized);
  return normalized;
}

export async function applyAuditLogRetention(db: D1Database, settings?: AuditLogSettings): Promise<void> {
  const current = settings || await getAuditLogSettings(db);
  if (current.retentionDays) {
    const before = new Date(Date.now() - current.retentionDays * 24 * 60 * 60 * 1000).toISOString();
    await adminRepo.pruneAuditLogs(db, before);
  }
  if (current.maxEntries) {
    await adminRepo.pruneAuditLogsToMax(db, current.maxEntries);
  }
}

export function auditEventStatement(db: D1Database, event: AuditEventInput, guard?: SQL) {
  // Only allow-listed, non-sensitive scalar metadata is stored; an array keeps just its length.
  const metadata: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(event.metadata || {})) {
    if (!ALLOWED_METADATA_KEYS.has(key)) continue;
    if (value === undefined || value === null || value === '') continue;
    if (SENSITIVE_KEY_RE.test(key)) continue;
    if (Array.isArray(value)) {
      metadata[key] = value.length;
      continue;
    }
    if (typeof value === 'object') continue;
    metadata[key] = value;
  }
  let metadataJson = JSON.stringify(metadata);
  if (new TextEncoder().encode(metadataJson).byteLength > MAX_METADATA_BYTES) {
    metadataJson = JSON.stringify({ truncated: true });
  }

  const orm = getOrm(db);
  return orm.insert(auditLogs).select(orm.select({
    id: bound(generateUUID()).as('id'),
    actorUserId: bound(event.actorUserId ?? null).as('actor_user_id'),
    action: bound(event.action).as('action'),
    category: bound(event.category).as('category'),
    level: bound(event.level || 'info').as('level'),
    targetType: bound(event.targetType ?? null).as('target_type'),
    targetId: bound(event.targetId ?? null).as('target_id'),
    metadata: bound(metadataJson).as('metadata'),
    createdAt: bound(new Date().toISOString()).as('created_at'),
  }).from(SINGLE_ROW).where(guard));
}

export async function writeAuditEvent(db: D1Database, event: AuditEventInput): Promise<void> {
  try {
    await auditEventStatement(db, event);
    // Opportunistic retention: at most once per interval per isolate, and only on a small share of writes.
    const now = Date.now();
    if (now - lastAuditCleanupAt < AUDIT_CLEANUP_INTERVAL_MS) return;
    if (Math.random() > AUDIT_CLEANUP_PROBABILITY) return;
    lastAuditCleanupAt = now;
    await applyAuditLogRetention(db);
  } catch (error) {
    console.error('audit log write failed', withoutQueryParams(error));
  }
}

export async function safeWriteAuditEvent(env: Env, event: AuditEventInput): Promise<void> {
  await writeAuditEvent(env.DB, event);
}

// Folder, cipher, attachment and Send mutations leave the same row apart from the target type;
// deletions are security-level so they stand out in the admin log.
export async function writeDataAudit(
  db: D1Database,
  request: Request,
  userId: string,
  targetType: 'folder' | 'cipher' | 'attachment' | 'send',
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(db, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType,
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: { ...metadata, ...auditRequestMetadata(request) },
  });
}
