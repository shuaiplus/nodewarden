import { and, desc, eq, gt, isNull, like, lt, lte, ne, or, sql } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import { auditLogs, invites, users } from '../db/schema';
import type { AuditLog, Invite } from '../types';

export interface AuditLogListOptions {
  limit: number;
  offset: number;
  category?: string | null;
  level?: string | null;
  q?: string | null;
  from?: string | null;
  to?: string | null;
}

export interface AuditLogListResult {
  logs: AuditLog[];
  total: number;
  hasMore: boolean;
}

function inviteStatus(value: string): Invite['status'] {
  if (value === 'used' || value === 'revoked' || value === 'expired') return value;
  return 'active';
}

function mapInvite(row: typeof invites.$inferSelect): Invite {
  return {
    code: row.code,
    createdBy: row.createdBy,
    usedBy: row.usedBy ?? null,
    expiresAt: row.expiresAt,
    status: inviteStatus(row.status),
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export async function createInvite(db: D1Database, invite: Invite): Promise<void> {
  await getOrm(db).insert(invites).values({
    code: invite.code,
    createdBy: invite.createdBy,
    usedBy: invite.usedBy,
    expiresAt: invite.expiresAt,
    status: invite.status,
    createdAt: invite.createdAt,
    updatedAt: invite.updatedAt,
  });
}

export async function getInvite(db: D1Database, code: string): Promise<Invite | null> {
  const [row] = await getOrm(db).select().from(invites).where(eq(invites.code, code)).limit(1);
  return row ? mapInvite(row) : null;
}

export async function listInvites(db: D1Database, includeInactive: boolean = false): Promise<Invite[]> {
  const now = new Date().toISOString();
  const rows = includeInactive
    ? await getOrm(db).select().from(invites).orderBy(desc(invites.createdAt))
    : await getOrm(db)
      .select()
      .from(invites)
      .where(and(eq(invites.status, 'active'), gt(invites.expiresAt, now)))
      .orderBy(desc(invites.createdAt));
  return rows.map(mapInvite);
}

export async function markInviteUsed(db: D1Database, code: string, userId: string): Promise<boolean> {
  void userId;
  const now = new Date().toISOString();
  const result = await getOrm(db)
    .update(invites)
    .set({ status: 'used', usedBy: null, updatedAt: now })
    .where(and(eq(invites.code, code), eq(invites.status, 'active'), gt(invites.expiresAt, now)))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function assignInviteUsedBy(db: D1Database, code: string, userId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await getOrm(db)
    .update(invites)
    .set({ usedBy: userId, updatedAt: now })
    .where(and(eq(invites.code, code), eq(invites.status, 'used'), isNull(invites.usedBy)))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function revertInviteUsed(db: D1Database, code: string, userId: string): Promise<boolean> {
  void userId;
  const now = new Date().toISOString();
  const result = await getOrm(db)
    .update(invites)
    .set({ status: 'active', usedBy: null, updatedAt: now })
    .where(and(eq(invites.code, code), eq(invites.status, 'used'), isNull(invites.usedBy)))
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteInvite(db: D1Database, code: string): Promise<boolean> {
  const result = await getOrm(db).delete(invites).where(eq(invites.code, code)).run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteInvalidInvites(db: D1Database): Promise<number> {
  const now = new Date().toISOString();
  const result = await getOrm(db)
    .delete(invites)
    .where(or(ne(invites.status, 'active'), lte(invites.expiresAt, now)))
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteAllInvites(db: D1Database): Promise<number> {
  const result = await getOrm(db).delete(invites).run();
  return Number(result.meta.changes ?? 0);
}

export async function createAuditLog(db: D1Database, log: AuditLog): Promise<void> {
  await getOrm(db).insert(auditLogs).values({
    id: log.id,
    actorUserId: log.actorUserId,
    action: log.action,
    category: log.category,
    level: log.level,
    targetType: log.targetType,
    targetId: log.targetId,
    metadata: log.metadata,
    createdAt: log.createdAt,
  });
}

export async function pruneAuditLogs(db: D1Database, beforeIso: string): Promise<number> {
  const result = await getOrm(db).delete(auditLogs).where(lt(auditLogs.createdAt, beforeIso)).run();
  return Number(result.meta.changes ?? 0);
}

export async function pruneAuditLogsToMax(db: D1Database, maxEntries: number): Promise<number> {
  const limit = Math.max(1, Math.floor(maxEntries));
  const result = await getOrm(db).run(sql`
    DELETE FROM audit_logs WHERE id IN (
      SELECT id FROM audit_logs ORDER BY created_at DESC LIMIT -1 OFFSET ${limit}
    )
  `);
  return Number(result.meta.changes ?? 0);
}

export async function clearAuditLogs(db: D1Database): Promise<number> {
  const result = await getOrm(db).delete(auditLogs).run();
  return Number(result.meta.changes ?? 0);
}

export async function listAuditLogs(db: D1Database, options: AuditLogListOptions): Promise<AuditLogListResult> {
  const limit = Math.max(1, Math.min(200, Math.floor(options.limit || 50)));
  const offset = Math.max(0, Math.floor(options.offset || 0));
  const actor = alias(users, 'actor');
  const target = alias(users, 'target');
  const filters = [];
  if (options.from) filters.push(gteCreated(options.from));
  if (options.to) filters.push(lteCreated(options.to));
  if (options.category) filters.push(eq(auditLogs.category, options.category));
  if (options.level) filters.push(eq(auditLogs.level, options.level));
  if (options.q) {
    const likePattern = `%${options.q.toLowerCase().slice(0, 48)}%`;
    filters.push(or(
      like(sql`lower(${auditLogs.action})`, likePattern),
      like(sql`lower(coalesce(${auditLogs.actorUserId}, ''))`, likePattern),
      like(sql`lower(coalesce(${auditLogs.targetType}, ''))`, likePattern),
      like(sql`lower(coalesce(${auditLogs.targetId}, ''))`, likePattern),
      like(sql`lower(coalesce(${actor.email}, ''))`, likePattern),
      like(sql`lower(coalesce(${target.email}, ''))`, likePattern),
    ));
  }

  const rows = await getOrm(db)
    .select({
      id: auditLogs.id,
      actorUserId: auditLogs.actorUserId,
      actorEmail: actor.email,
      action: auditLogs.action,
      category: auditLogs.category,
      level: auditLogs.level,
      targetType: auditLogs.targetType,
      targetId: auditLogs.targetId,
      targetUserEmail: target.email,
      metadata: auditLogs.metadata,
      createdAt: auditLogs.createdAt,
    })
    .from(auditLogs)
    .leftJoin(actor, eq(actor.id, auditLogs.actorUserId))
    .leftJoin(target, and(eq(auditLogs.targetType, 'user'), eq(target.id, auditLogs.targetId)))
    .where(filters.length ? and(...filters) : undefined)
    .orderBy(desc(auditLogs.createdAt))
    .limit(limit + 1)
    .offset(offset);

  const logs = rows.slice(0, limit).map((row) => ({
    id: row.id,
    actorUserId: row.actorUserId ?? null,
    actorEmail: row.actorEmail ?? null,
    action: row.action,
    category: auditCategory(row.category),
    level: auditLevel(row.level),
    targetType: row.targetType ?? null,
    targetId: row.targetId ?? null,
    targetUserEmail: row.targetUserEmail ?? null,
    metadata: row.metadata ?? null,
    createdAt: row.createdAt,
  }));

  return {
    logs,
    total: offset + logs.length + (rows.length > limit ? 1 : 0),
    hasMore: rows.length > limit,
  };
}

function auditCategory(value: string): AuditLog['category'] {
  if (value === 'auth' || value === 'security' || value === 'device' || value === 'data') return value;
  return 'system';
}

function auditLevel(value: string): AuditLog['level'] {
  if (value === 'warn' || value === 'error' || value === 'security') return value;
  return 'info';
}

function gteCreated(from: string) {
  return sql`${auditLogs.createdAt} >= ${from}`;
}

function lteCreated(to: string) {
  return sql`${auditLogs.createdAt} <= ${to}`;
}
