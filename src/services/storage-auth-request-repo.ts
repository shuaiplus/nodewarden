import { and, desc, eq, inArray, isNull, lt, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { authRequests } from '../db/schema';
import type { AuthRequestRecord, AuthRequestType } from '../types';

const AUTH_REQUEST_EXPIRATION_MS = 15 * 60 * 1000;

function mapAuthRequestRow(row: typeof authRequests.$inferSelect): AuthRequestRecord {
  return {
    id: row.id,
    userId: row.userId,
    organizationId: row.organizationId ?? null,
    type: Number(row.type) as AuthRequestType,
    requestDeviceIdentifier: row.requestDeviceIdentifier,
    requestDeviceType: Number(row.requestDeviceType ?? 14),
    requestIpAddress: row.requestIpAddress ?? null,
    requestCountryName: row.requestCountryName ?? null,
    responseDeviceIdentifier: row.responseDeviceIdentifier ?? null,
    accessCode: row.accessCode,
    publicKey: row.publicKey,
    key: row.key ?? null,
    masterPasswordHash: row.masterPasswordHash ?? null,
    approved: row.approved == null ? null : Number(row.approved) === 1,
    creationDate: row.creationDate,
    responseDate: row.responseDate ?? null,
    authenticationDate: row.authenticationDate ?? null,
  };
}

function authRequestValues(request: AuthRequestRecord) {
  return {
    id: request.id,
    userId: request.userId,
    organizationId: request.organizationId,
    type: request.type,
    requestDeviceIdentifier: request.requestDeviceIdentifier,
    requestDeviceType: request.requestDeviceType,
    requestIpAddress: request.requestIpAddress,
    requestCountryName: request.requestCountryName,
    responseDeviceIdentifier: request.responseDeviceIdentifier,
    accessCode: request.accessCode,
    publicKey: request.publicKey,
    key: request.key,
    masterPasswordHash: request.masterPasswordHash,
    approved: request.approved == null ? null : (request.approved ? 1 : 0),
    creationDate: request.creationDate,
    responseDate: request.responseDate,
    authenticationDate: request.authenticationDate,
  };
}

export function isAuthRequestExpired(request: AuthRequestRecord, nowMs: number = Date.now()): boolean {
  return new Date(request.creationDate).getTime() + AUTH_REQUEST_EXPIRATION_MS <= nowMs;
}

export async function createAuthRequest(db: D1Database, request: AuthRequestRecord): Promise<void> {
  await getOrm(db).insert(authRequests).values(authRequestValues(request));
}

export async function getAuthRequestById(db: D1Database, id: string): Promise<AuthRequestRecord | null> {
  const [row] = await getOrm(db).select().from(authRequests).where(eq(authRequests.id, id)).limit(1);
  return row ? mapAuthRequestRow(row) : null;
}

export async function getAuthRequestByIdForUser(db: D1Database, id: string, userId: string): Promise<AuthRequestRecord | null> {
  const [row] = await getOrm(db)
    .select()
    .from(authRequests)
    .where(and(eq(authRequests.id, id), eq(authRequests.userId, userId)))
    .limit(1);
  return row ? mapAuthRequestRow(row) : null;
}

export async function listAuthRequestsByUserId(db: D1Database, userId: string): Promise<AuthRequestRecord[]> {
  const rows = await getOrm(db)
    .select()
    .from(authRequests)
    .where(eq(authRequests.userId, userId))
    .orderBy(desc(authRequests.creationDate));
  return rows.map(mapAuthRequestRow);
}

export async function listPendingAuthRequestsByUserId(db: D1Database, userId: string, nowMs: number = Date.now()): Promise<AuthRequestRecord[]> {
  const cutoff = new Date(nowMs - AUTH_REQUEST_EXPIRATION_MS).toISOString();
  const orm = getOrm(db);
  const ar = authRequests;
  const latest = orm
    .select({
      requestDeviceIdentifier: ar.requestDeviceIdentifier,
      latestCreationDate: sql<string>`max(${ar.creationDate})`.as('latest_creation_date'),
    })
    .from(ar)
    .where(and(
      eq(ar.userId, userId),
      inArray(ar.type, [0, 1]),
      isNull(ar.approved),
      isNull(ar.responseDate),
      isNull(ar.authenticationDate),
      gteCreation(ar.creationDate, cutoff),
    ))
    .groupBy(ar.requestDeviceIdentifier)
    .as('latest');

  const rows = await orm
    .select()
    .from(ar)
    .innerJoin(
      latest,
      and(
        eq(latest.requestDeviceIdentifier, ar.requestDeviceIdentifier),
        eq(latest.latestCreationDate, ar.creationDate),
      ),
    )
    .where(and(
      eq(ar.userId, userId),
      inArray(ar.type, [0, 1]),
      isNull(ar.approved),
      isNull(ar.responseDate),
      isNull(ar.authenticationDate),
    ))
    .orderBy(desc(ar.creationDate));

  return rows.map((row) => mapAuthRequestRow(row.auth_requests)).filter((request) => !isAuthRequestExpired(request, nowMs));
}

function gteCreation(column: typeof authRequests.creationDate, cutoff: string) {
  return sql`${column} >= ${cutoff}`;
}

export async function updateAuthRequestResponse(
  db: D1Database,
  id: string,
  userId: string,
  update: {
    approved: boolean;
    responseDeviceIdentifier: string;
    key?: string | null;
    masterPasswordHash?: string | null;
    responseDate?: string;
  }
): Promise<boolean> {
  const result = await getOrm(db)
    .update(authRequests)
    .set({
      approved: update.approved ? 1 : 0,
      responseDeviceIdentifier: update.responseDeviceIdentifier,
      key: update.approved ? (update.key ?? null) : null,
      masterPasswordHash: update.approved ? (update.masterPasswordHash ?? null) : null,
      responseDate: update.responseDate || new Date().toISOString(),
    })
    .where(and(
      eq(authRequests.id, id),
      eq(authRequests.userId, userId),
      isNull(authRequests.approved),
      isNull(authRequests.responseDate),
      isNull(authRequests.authenticationDate),
    ))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function markAuthRequestAuthenticated(db: D1Database, id: string, authenticationDate: string = new Date().toISOString()): Promise<boolean> {
  const result = await getOrm(db)
    .update(authRequests)
    .set({ authenticationDate })
    .where(and(eq(authRequests.id, id), isNull(authRequests.authenticationDate)))
    .run();
  return Number(result.meta.changes ?? 0) > 0;
}

export async function pruneExpiredAuthRequests(db: D1Database, nowMs: number = Date.now()): Promise<number> {
  const cutoff = new Date(nowMs - AUTH_REQUEST_EXPIRATION_MS).toISOString();
  const result = await getOrm(db)
    .delete(authRequests)
    .where(lt(authRequests.creationDate, cutoff))
    .run();
  return Number(result.meta.changes ?? 0);
}
