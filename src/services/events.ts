import { and, desc, eq, gte, isNull, lt, lte, or } from 'drizzle-orm';
import { chunkRows, columnCount, getOrm } from '../db/client';
import { events, organizationMemberships } from '../db/schema';
import { SendAuthType, SendType, type Env, type Send } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { DEFAULT_AUDIT_LOG_SETTINGS, getAuditLogSettings } from './audit-events';
import { MembershipStatus } from './org-types';
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
  SendCreatedText: 2500, SendCreatedTextWithEmailVerification: 2501, SendCreatedTextWithPasswordProtection: 2502,
  SendCreatedFile: 2503, SendCreatedFileWithEmailVerification: 2504, SendCreatedFileWithPasswordProtection: 2505,
  SendEditedText: 2506, SendEditedFile: 2507, SendDeletedText: 2508, SendDeletedFile: 2509,
  SendAccessedText: 2510, SendAccessedFile: 2511,
} as const;

export type EventResourceType = 'cipher' | 'collection' | 'group' | 'policy' | 'organizationUser' | 'secret' | 'project' | 'send';
export interface EventActor { userId?: string | null; serviceAccountId?: string | null; systemUser?: number | null }
export interface EventInput {
  type: number;
  organizationId: string | null;
  resourceType?: EventResourceType;
  resourceId?: string;
  userId?: string | null;
  // Overrides the actor for this row only; null records no acting user (an external Send accessor).
  actingUserId?: string | null;
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
    actingUserId: event.actingUserId !== undefined ? event.actingUserId : actor.userId ?? null, userId: event.userId ?? null,
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

type AccountEvent = Pick<EventInput, 'type' | 'resourceType' | 'resourceId'>;

// Upstream LogUserEventAsync / LogSendEventAsync: one personal row acted by the account, plus a copy for
// every organization where it is a confirmed member. Access events pass organizationActingUserId null,
// because the account owns the Send but did not open it. Memberships are read once for every event.
async function recordAccountEvents(env: Env, request: Request | null, userId: string, accountEvents: AccountEvent[], organizationActingUserId?: null): Promise<void> {
  if (!accountEvents.length) return;
  try {
    const organizationIds = (await getOrm(env.DB).select({ orgId: organizationMemberships.orgId, status: organizationMemberships.status })
      .from(organizationMemberships).where(eq(organizationMemberships.userId, userId)))
      .filter(member => member.status === MembershipStatus.Confirmed).map(member => member.orgId);
    await recordEvents(env, request, { userId }, accountEvents.flatMap(event => [
      { ...event, organizationId: null, userId },
      ...organizationIds.map(organizationId => ({ ...event, organizationId, userId, actingUserId: organizationActingUserId })),
    ]));
  } catch { console.error('User event recording failed'); }
}

export async function recordUserEvent(env: Env, request: Request | null, userId: string, type: number): Promise<void> {
  await recordAccountEvents(env, request, userId, [{ type }]);
}

export type SendEventAction = 'created' | 'edited' | 'deleted' | 'accessed';

function sendEventType(send: Pick<Send, 'type' | 'authType' | 'passwordHash'>, action: SendEventAction): number {
  const text = send.type === SendType.Text;
  if (action === 'edited') return text ? EventType.SendEditedText : EventType.SendEditedFile;
  if (action === 'deleted') return text ? EventType.SendDeletedText : EventType.SendDeletedFile;
  if (action === 'accessed') return text ? EventType.SendAccessedText : EventType.SendAccessedFile;
  // A legacy password body sets a hash without authType, so the hash decides password protection.
  if (send.passwordHash) return text ? EventType.SendCreatedTextWithPasswordProtection : EventType.SendCreatedFileWithPasswordProtection;
  if (send.authType === SendAuthType.Email) return text ? EventType.SendCreatedTextWithEmailVerification : EventType.SendCreatedFileWithEmailVerification;
  return text ? EventType.SendCreatedText : EventType.SendCreatedFile;
}

// ponytail: every accessor is recorded as External; attribute confirmed members once Send email
// verification identifies who opened the Send.
type SendEventSubject = Pick<Send, 'id' | 'userId' | 'type' | 'authType' | 'passwordHash'>;

export async function recordSendEvents(env: Env, request: Request | null, ownerId: string, sends: SendEventSubject[], action: SendEventAction): Promise<void> {
  await recordAccountEvents(env, request, ownerId, sends.map(send => ({ type: sendEventType(send, action), resourceType: 'send', resourceId: send.id })),
    action === 'accessed' ? null : undefined);
}

export async function recordSendEvent(env: Env, request: Request | null, send: SendEventSubject, action: SendEventAction): Promise<void> {
  await recordSendEvents(env, request, send.userId, [send], action);
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
  organizationUser: 'organizationUserId', secret: 'secretId', project: 'projectId', send: 'sendId',
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

// Prune bounded batches by server receipt age only, as upstream does. A shared row cap would let any
// account's self-reported /events/collect volume evict other organizations' history, so the audit
// row-cap mode bounds only audit_logs and events then keep the default retention age. Retention
// switched off keeps events too.
export async function pruneEvents(env: Env): Promise<void> {
  const { retentionDays, maxEntries } = await getAuditLogSettings(new StorageService(env.DB));
  const days = retentionDays ?? (maxEntries ? DEFAULT_AUDIT_LOG_SETTINGS.retentionDays : null);
  if (!days) return;
  await env.DB.prepare('DELETE FROM events WHERE id IN (SELECT id FROM events WHERE recorded_at < ? ORDER BY recorded_at,id LIMIT 1000)')
    .bind(new Date(Date.now() - days * 86_400_000).toISOString()).run();
}
