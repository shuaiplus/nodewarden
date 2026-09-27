import { and, desc, eq, gt, gte, inArray, isNull, like, lt, lte, ne, or, placeholder } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import { auditLogs, invites, users } from '../db/schema';
import { coalesce, likeEscaped, lower } from '../db/sql';
import type { AuditLog, Invite } from '../types';

export interface AuditLogListOptions {
  limit: number;
  offset: number;
  actionPrefix?: string;
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

function mapInvite(row: typeof invites.$inferSelect): Invite {
  return {
    code: row.code,
    createdBy: row.createdBy,
    usedBy: row.usedBy ?? null,
    expiresAt: row.expiresAt,
    status: row.status === 'used' || row.status === 'revoked' || row.status === 'expired' ? row.status : 'active',
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

// SQLite accepts OFFSET only after a LIMIT, where -1 means unbounded. Drizzle omits negative literal
// limits, so the -1 is bound through a placeholder.
export async function pruneAuditLogsToMax(db: D1Database, maxEntries: number): Promise<number> {
  const keep = Math.max(1, Math.floor(maxEntries));
  const orm = getOrm(db);
  const overflow = orm.select({ id: auditLogs.id }).from(auditLogs).orderBy(desc(auditLogs.createdAt))
    .limit(placeholder('unbounded')).offset(keep);
  const result = await orm.delete(auditLogs).where(inArray(auditLogs.id, overflow)).run({ unbounded: -1 });
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
  if (options.actionPrefix) filters.push(likeEscaped(auditLogs.action, options.actionPrefix.replace(/[\\%_]/g, (value) => `\\${value}`) + '%'));
  if (options.from) filters.push(gte(auditLogs.createdAt, options.from));
  if (options.to) filters.push(lte(auditLogs.createdAt, options.to));
  if (options.category) filters.push(eq(auditLogs.category, options.category));
  if (options.level) filters.push(eq(auditLogs.level, options.level));
  if (options.q) {
    const likePattern = `%${options.q.toLowerCase().slice(0, 48)}%`;
    filters.push(or(
      like(lower(auditLogs.action), likePattern),
      like(lower(coalesce(auditLogs.actorUserId, '')), likePattern),
      like(lower(coalesce(auditLogs.targetType, '')), likePattern),
      like(lower(coalesce(auditLogs.targetId, '')), likePattern),
      like(lower(coalesce(actor.email, '')), likePattern),
      like(lower(coalesce(target.email, '')), likePattern),
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

  const logs = rows.slice(0, limit).map((row): AuditLog => ({
    id: row.id,
    actorUserId: row.actorUserId ?? null,
    actorEmail: row.actorEmail ?? null,
    action: row.action,
    category: row.category === 'auth' || row.category === 'security' || row.category === 'device' || row.category === 'data'
      ? row.category
      : 'system',
    level: row.level === 'warn' || row.level === 'error' || row.level === 'security' ? row.level : 'info',
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
