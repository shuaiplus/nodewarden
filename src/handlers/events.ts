import { inArray } from 'drizzle-orm';
import { z } from 'zod';
import { chunkRows, getOrm } from '../db/client';
import { ciphers } from '../db/schema';
import type { Env, User } from '../types';
import { errorResponse, parseBody } from '../utils/response';
import { canAccessEventLogs, canViewCipher, hasFullCollectionAccess, isActiveMember } from '../services/org-authz';
import * as orgRepo from '../services/storage-org-repo';
import { EventType, listEventsResponse, storeEvents, type EventInput } from '../services/events';
import { LIMITS } from '../config/limits';
import { RateLimitService } from '../services/ratelimit';
import * as cipherRepo from '../services/storage-cipher-repo';

const CLIENT_CIPHER_TYPES = new Set([
  ...Array.from({ length: 8 }, (_, i) => 1107 + i),
  ...Array.from({ length: 16 }, (_, i) => 1117 + i),
]);
const CLIENT_ORGANIZATION_TYPES = new Set([1602, 1522, 1618, 1619]);
// Official TypeScript clients post their queue in batches of 100 (ApiService.EventUploadBatchSize), but
// native mobile clients post it whole and retry forever on 400, so an offline backlog must still fit.
// Each upload is charged one unit per 100 stored rows in its own per-minute budget: an account can store
// no more than those batched clients could, and a backlog never competes with vault API calls. A body
// larger than one minute's budget could never be admitted, so it is rejected outright.
const CLIENT_EVENT_UPLOAD_BATCH = 100;
const EVENT_BATCHES_PER_MINUTE = LIMITS.rateLimit.apiRequestsPerMinute;
const MAX_COLLECTED_EVENTS = CLIENT_EVENT_UPLOAD_BATCH * EVENT_BATCHES_PER_MINUTE;
const INVALID_EVENTS = { error: 'Invalid events.' };
const optionalGuid = z.guid(INVALID_EVENTS).nullish().transform(id => id ?? null);
const ClientEvents = z.array(z.object({
  type: z.int(INVALID_EVENTS),
  date: z.string(INVALID_EVENTS).refine(date => Number.isFinite(Date.parse(date)), INVALID_EVENTS).transform(date => new Date(date).toISOString()),
  cipherId: optionalGuid,
  organizationId: optionalGuid,
}, INVALID_EVENTS), INVALID_EVENTS).min(1, INVALID_EVENTS).max(MAX_COLLECTED_EVENTS, INVALID_EVENTS);

export async function handleEventRoute(request: Request, env: Env, user: User, path: string, method: string): Promise<Response | null> {
  if (path === '/events/collect') {
    if (method !== 'POST') return errorResponse('Method not allowed', 405);
    const input = await parseBody(request, ClientEvents, INVALID_EVENTS.error);
    if (input instanceof Response) return input;
    const memberships = (await orgRepo.listMembershipsByUser(env.DB, user.id)).filter(isActiveMember);
    // Charge before any lookup, counting the organization copies an export fans out to.
    const exportCopies = input.filter(event => event.type === EventType.UserClientExportedVault).length * memberships.length;
    const batches = Math.ceil((input.length + exportCopies) / CLIENT_EVENT_UPLOAD_BATCH);
    if (batches > EVENT_BATCHES_PER_MINUTE) return errorResponse('Invalid events.', 400);
    const budget = await new RateLimitService(env).consumeBudget(`${user.id}:events`, EVENT_BATCHES_PER_MINUTE, batches);
    if (!budget.allowed) return errorResponse('Too many requests', 429, { 'Retry-After': String(budget.retryAfterSeconds || 60) });
    const memberByOrg = new Map(memberships.map(member => [member.orgId, member]));
    const ids = [...new Set(input.filter(event => CLIENT_CIPHER_TYPES.has(event.type) && event.cipherId).map(event => event.cipherId!))];
    const cipherRows = (await Promise.all(chunkRows(ids, 1).map(chunk => getOrm(env.DB).select({ id: ciphers.id, organizationId: ciphers.organizationId })
      .from(ciphers).where(inArray(ciphers.id, chunk))))).flat();
    const collections = await orgRepo.listCipherCollectionIdsByCipherIds(env.DB, cipherRows.map(cipher => cipher.id));
    const accessByOrg = new Map(await Promise.all([...new Set(cipherRows.map(cipher => cipher.organizationId))].filter((orgId): orgId is string => {
      const member = orgId ? memberByOrg.get(orgId) : undefined;
      return !!member && !hasFullCollectionAccess(member);
    }).map(async orgId => [orgId, new Map((await orgRepo.listUserCollectionAccess(env.DB, user.id, orgId)).map(access => [access.collectionId, access]))] as const)));
    const accessible = new Map(cipherRows.filter(cipher => {
      const member = cipher.organizationId ? memberByOrg.get(cipher.organizationId) : undefined;
      return member && canViewCipher(member, collections.get(cipher.id) ?? [], accessByOrg.get(member.orgId) ?? new Map());
    }).map(cipher => [cipher.id, cipher.organizationId!]));

    const records: EventInput[] = [];
    for (const event of input) {
      if (event.type === EventType.UserClientExportedVault) {
        // Upstream LogUserEventAsync keeps the client date only on the personal row; organization copies
        // get receipt time, so a member cannot backdate an export out of the range their admins review.
        records.push({ type: event.type, organizationId: null, userId: user.id, date: event.date },
          ...memberships.map(member => ({ type: event.type, organizationId: member.orgId, userId: user.id })));
      } else if (CLIENT_CIPHER_TYPES.has(event.type) && event.cipherId) {
        const orgId = accessible.get(event.cipherId);
        if (!orgId || (event.organizationId !== null && event.organizationId !== orgId)) continue;
        records.push({ type: event.type, organizationId: orgId, resourceType: 'cipher', resourceId: event.cipherId, date: event.date });
      } else if (CLIENT_ORGANIZATION_TYPES.has(event.type) && event.organizationId) {
        const member = memberByOrg.get(event.organizationId);
        if (!member) continue;
        records.push({ type: event.type, organizationId: member.orgId, date: event.date,
          ...(event.type === EventType.OrganizationClientExportedVault ? {} : { resourceType: 'organizationUser' as const, resourceId: member.id, userId: user.id }),
        });
      }
    }
    // Unrecognized actions and inaccessible resources have the same acknowledged outcome.
    await storeEvents(env, request, { userId: user.id }, records);
    return new Response(null, { status: 200 });
  }
  if (path === '/api/events') return method === 'GET' ? listEventsResponse(request, env, { personalUserId: user.id }) : errorResponse('Method not allowed', 405);
  const cipherPath = path.match(/^\/api\/ciphers\/([a-f0-9-]+)\/events$/i);
  if (cipherPath) {
    if (method !== 'GET') return errorResponse('Method not allowed', 405);
    const cipher = await cipherRepo.getCipher(env.DB, cipherPath[1]);
    if (!cipher) return errorResponse('Not found', 404);
    if (cipher.organizationId) {
      if (!canAccessEventLogs(await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, cipher.organizationId))) return errorResponse('Not found', 404);
      return listEventsResponse(request, env, { organizationId: cipher.organizationId, resourceType: 'cipher', resourceId: cipher.id });
    }
    return cipher.userId === user.id ? listEventsResponse(request, env, { personalUserId: user.id, resourceType: 'cipher', resourceId: cipher.id }) : errorResponse('Not found', 404);
  }
  const orgPath = path.match(/^\/api\/organizations\/([a-f0-9-]+)(?:\/(users|sends)\/([a-f0-9-]+))?\/events$/i);
  if (!orgPath) return null;
  if (method !== 'GET') return errorResponse('Method not allowed', 405);
  const orgId = orgPath[1];
  if (!canAccessEventLogs(await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId))) return errorResponse('Not found', 404);
  if (orgPath[2] === 'users') {
    const member = await orgRepo.getMembership(env.DB, orgPath[3]);
    if (!member?.userId || member.orgId !== orgId) return errorResponse('Not found', 404);
    return listEventsResponse(request, env, { organizationId: orgId, actingUserId: member.userId });
  }
  // As upstream GetSend: the rows are already scoped to this organization, so a deleted Send keeps its history.
  if (orgPath[2] === 'sends') return listEventsResponse(request, env, { organizationId: orgId, resourceType: 'send', resourceId: orgPath[3] });
  return listEventsResponse(request, env, { organizationId: orgId });
}
