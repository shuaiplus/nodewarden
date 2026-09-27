import { and, desc, eq, gte, isNull, lt, lte, or } from 'drizzle-orm';
import { chunkRows, columnCount, getOrm } from '../db/client';
import { events, organizationMemberships } from '../db/schema';
import type { Env } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { getAuditLogSettings } from './audit-events';
import { StorageService } from './storage';

export const EventType = {
  UserLoggedIn: 1000, UserChangedPassword: 1001, UserUpdated2fa: 1002, UserDisabled2fa: 1003,
  UserRecovered2fa: 1004, UserFailedLogIn: 1005, UserFailedLogIn2fa: 1006, UserClientExportedVault: 1007,
  CipherCreated: 1100, CipherUpdated: 1101, CipherDeleted: 1102, CipherAttachmentCreated: 1103,
  CipherAttachmentDeleted: 1104, CipherShared: 1105, CipherUpdatedCollections: 1106,
  CipherClientViewed: 1107, CipherSoftDeleted: 1115, CipherRestored: 1116,
  CollectionCreated: 1300, CollectionUpdated: 1301, CollectionDeleted: 1302,
  GroupCreated: 1400, GroupUpdated: 1401, GroupDeleted: 1402,
  OrganizationUserInvited: 1500, OrganizationUserConfirmed: 1501, OrganizationUserUpdated: 1502,
  OrganizationUserRemoved: 1503, OrganizationUserUpdatedGroups: 1504, OrganizationUserRevoked: 1511,
  OrganizationUserRestored: 1512, OrganizationUserLeft: 1516,
  OrganizationUpdated: 1600, OrganizationPurgedVault: 1601, OrganizationClientExportedVault: 1602,
  PolicyUpdated: 1700,
  SecretRetrieved: 2100, SecretCreated: 2101, SecretEdited: 2102, SecretDeleted: 2103,
  SecretPermanentlyDeleted: 2104, SecretRestored: 2105,
  ProjectRetrieved: 2200, ProjectCreated: 2201, ProjectEdited: 2202, ProjectDeleted: 2203,
  ServiceAccountUserAdded: 2300, ServiceAccountUserRemoved: 2301, ServiceAccountGroupAdded: 2302,
  ServiceAccountGroupRemoved: 2303, ServiceAccountCreated: 2304, ServiceAccountDeleted: 2305,
} as const;

export type EventResourceType = 'cipher' | 'collection' | 'group' | 'policy' | 'organizationUser' | 'secret' | 'project';
export interface EventActor { userId?: string | null; serviceAccountId?: string | null; systemUser?: number | null }
export interface EventInput {
  type: number;
  organizationId: string | null;
  resourceType?: EventResourceType;
  resourceId?: string;
  userId?: string | null;
  grantedServiceAccountId?: string | null;
  date?: string;
}

export async function storeEvents(env: Env, request: Request | null, actor: EventActor, input: EventInput[]): Promise<void> {
  if (!input.length) return;
  const deviceHeader = request?.headers.get('Device-Type');
  const deviceType = deviceHeader && /^\d+$/.test(deviceHeader) ? Number(deviceHeader) : null;
  const rawIp = request?.headers.get('CF-Connecting-IP')?.trim();
  const ipAddress = rawIp && rawIp.length <= 45 && /^[0-9a-f:.]+$/i.test(rawIp) ? rawIp : null;
  const now = new Date().toISOString();
  const rows: Array<typeof events.$inferInsert> = input.map(event => ({
    id: crypto.randomUUID(), organizationId: event.organizationId, type: event.type, date: event.date ?? now, recordedAt: now,
    actingUserId: actor.userId ?? null, userId: event.userId ?? null,
    resourceType: event.resourceType ?? null, resourceId: event.resourceId ?? null,
    serviceAccountId: actor.serviceAccountId ?? null, grantedServiceAccountId: event.grantedServiceAccountId ?? null,
    deviceType: deviceType !== null && Number.isSafeInteger(deviceType) ? deviceType : null,
    ipAddress, systemUser: actor.systemUser ?? null,
  }));
  const orm = getOrm(env.DB);
  const statements = chunkRows(rows, columnCount(events)).map(chunk => orm.insert(events).values(chunk));
  await orm.batch(statements as [typeof statements[number], ...typeof statements]);
}

// A committed account/vault mutation must not become a misleading failure if its event cannot be saved.
export async function recordEvents(...args: Parameters<typeof storeEvents>): Promise<void> {
  try { await storeEvents(...args); } catch { console.error('Event recording failed'); }
}

export async function recordUserEvent(env: Env, request: Request | null, userId: string, type: number, date?: string): Promise<void> {
  try {
    const memberships = await getOrm(env.DB).select({ orgId: organizationMemberships.orgId, status: organizationMemberships.status })
    .from(organizationMemberships).where(eq(organizationMemberships.userId, userId));
  await recordEvents(env, request, { userId }, [
    { organizationId: null, userId, type, date },
    ...memberships.filter(member => member.status === 2).map(member => ({ organizationId: member.orgId, userId, type, date })),
    ]);
  } catch { console.error('User event recording failed'); }
}

export interface EventFilter {
  organizationId?: string;
  resourceType?: EventResourceType;
  resourceId?: string;
  serviceAccountId?: string;
  actingUserId?: string;
  personalUserId?: string;
}

const RESOURCE_FIELDS = {
  cipher: 'cipherId', collection: 'collectionId', group: 'groupId', policy: 'policyId',
  organizationUser: 'organizationUserId', secret: 'secretId', project: 'projectId',
} as const;

function eventResponse(row: typeof events.$inferSelect) {
  const references: Record<string, string | null> = {
    cipherId: null, collectionId: null, groupId: null, policyId: null, organizationUserId: null,
    secretId: null, projectId: null, sendId: null,
  };
  if (row.resourceType && row.resourceType in RESOURCE_FIELDS) references[RESOURCE_FIELDS[row.resourceType as EventResourceType]] = row.resourceId;
  return {
    object: 'event', type: row.type, date: row.date, organizationId: row.organizationId,
    actingUserId: row.actingUserId, userId: row.userId, serviceAccountId: row.serviceAccountId,
    grantedServiceAccountId: row.grantedServiceAccountId, deviceType: row.deviceType,
    ipAddress: row.ipAddress, systemUser: row.systemUser,
    providerId: null, providerUserId: null, providerOrganizationId: null, installationId: null, domainName: null,
    ...references,
  };
}

// The official client concatenates continuationToken without URL encoding; use base64url.
function cursor(date: string, id: string): string {
  return btoa(JSON.stringify([date, id])).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function listEventsResponse(request: Request, env: Env, filter: EventFilter): Promise<Response> {
  const params = new URL(request.url).searchParams;
  for (const name of ['start', 'end']) {
    if (params.has(name) && !Number.isFinite(Date.parse(params.get(name)!))) return errorResponse('Invalid date range.', 400);
  }
  let start: number;
  let end: number;
  if (!params.has('start') || !params.has('end')) {
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    start = today.getTime() - 30 * 86_400_000;
    end = today.getTime() + 86_400_000 - 1;
  } else {
    start = Date.parse(params.get('start')!);
    end = Date.parse(params.get('end')!);
    if (!Number.isFinite(start) || !Number.isFinite(end)) return errorResponse('Invalid date range.', 400);
    if (start > end) [start, end] = [end, start];
  }
  if (end - start > 367 * 86_400_000) return errorResponse('Range too large.', 400);
  const conditions = [gte(events.date, new Date(start).toISOString()), lte(events.date, new Date(end).toISOString())];
  if (filter.personalUserId) conditions.push(isNull(events.organizationId), eq(events.actingUserId, filter.personalUserId));
  else if (filter.organizationId) conditions.push(eq(events.organizationId, filter.organizationId));
  else throw new Error('Event query requires an authorized scope');
  if (filter.resourceType) conditions.push(eq(events.resourceType, filter.resourceType));
  if (filter.resourceId) conditions.push(eq(events.resourceId, filter.resourceId));
  if (filter.actingUserId) conditions.push(eq(events.actingUserId, filter.actingUserId));
  if (filter.serviceAccountId) conditions.push(or(eq(events.serviceAccountId, filter.serviceAccountId), eq(events.grantedServiceAccountId, filter.serviceAccountId))!);
  const token = params.get('continuationToken');
  if (token) {
    try {
      if (token.length > 256 || !/^[A-Za-z0-9_-]+$/.test(token)) throw new Error();
      const value: unknown = JSON.parse(atob(token.replace(/-/g, '+').replace(/_/g, '/')));
      if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string' || typeof value[1] !== 'string'
        || !Number.isFinite(Date.parse(value[0])) || new Date(value[0]).toISOString() !== value[0] || !/^[a-f0-9-]{36}$/i.test(value[1])) throw new Error();
      conditions.push(or(lt(events.date, value[0]), and(eq(events.date, value[0]), lt(events.id, value[1])))!);
    } catch { return errorResponse('Invalid continuation token.', 400); }
  }
  const rows = await getOrm(env.DB).select().from(events).where(and(...conditions)).orderBy(desc(events.date), desc(events.id)).limit(51);
  const data = rows.slice(0, 50);
  const last = data.at(-1);
  return jsonResponse({ object: 'list', data: data.map(eventResponse), continuationToken: rows.length > 50 && last ? cursor(last.date, last.id) : null });
}

// Reuse instance audit retention, pruning bounded batches by server receipt time, not client clocks.
export async function pruneEvents(env: Env): Promise<void> {
  const settings = await getAuditLogSettings(new StorageService(env.DB));
  if (settings.retentionDays) {
    await env.DB.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events WHERE recorded_at < ? ORDER BY recorded_at,id LIMIT 1000)')
      .bind(new Date(Date.now() - settings.retentionDays * 86_400_000).toISOString()).run();
  } else if (settings.maxEntries) {
    await env.DB.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY recorded_at DESC,id DESC LIMIT 1000 OFFSET ?)')
      .bind(settings.maxEntries).run();
  }
}
