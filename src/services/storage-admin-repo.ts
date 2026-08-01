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

function auditLogFromRow(row: any): AuditLog {
  return {
    id: row.id,
    actorUserId: row.actor_user_id ?? null,
    actorEmail: row.actor_email ?? null,
    action: row.action,
    category: row.category || 'system',
    level: row.level || 'info',
    targetType: row.target_type ?? null,
    targetId: row.target_id ?? null,
    targetUserEmail: row.target_user_email ?? null,
    metadata: row.metadata ?? null,
    createdAt: row.created_at,
  };
}

function buildAuditWhere(options: AuditLogListOptions): { where: string; params: unknown[] } {
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (options.from) {
    conditions.push('l.created_at >= ?');
    params.push(options.from);
  }
  if (options.to) {
    conditions.push('l.created_at <= ?');
    params.push(options.to);
  }
  if (options.category) {
    conditions.push('l.category = ?');
    params.push(options.category);
  }
  if (options.level) {
    conditions.push('l.level = ?');
    params.push(options.level);
  }
  if (options.q) {
    const q = options.q.toLowerCase().slice(0, 48);
    const like = `%${q}%`;
    conditions.push(
      '(LOWER(l.action) LIKE ? OR LOWER(COALESCE(l.actor_user_id, \'\')) LIKE ? OR LOWER(COALESCE(l.target_type, \'\')) LIKE ? OR LOWER(COALESCE(l.target_id, \'\')) LIKE ? OR LOWER(COALESCE(actor.email, \'\')) LIKE ? OR LOWER(COALESCE(target.email, \'\')) LIKE ?)'
    );
    params.push(like, like, like, like, like, like);
  }

  return {
    where: conditions.length ? `WHERE ${conditions.join(' AND ')}` : '',
    params,
  };
}

export async function createInvite(db: D1Database, invite: Invite): Promise<void> {
  await db
    .prepare(
      'INSERT INTO invites(code, created_by, used_by, expires_at, status, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(invite.code, invite.createdBy, invite.usedBy, invite.expiresAt, invite.status, invite.createdAt, invite.updatedAt)
    .run();
}

export async function getInvite(db: D1Database, code: string): Promise<Invite | null> {
  const row = await db
    .prepare('SELECT code, created_by, used_by, expires_at, status, created_at, updated_at FROM invites WHERE code = ?')
    .bind(code)
    .first<any>();
  if (!row) return null;
  return {
    code: row.code,
    createdBy: row.created_by,
    usedBy: row.used_by ?? null,
    expiresAt: row.expires_at,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function listInvites(db: D1Database, includeInactive: boolean = false): Promise<Invite[]> {
  const now = new Date().toISOString();
  const predicate = includeInactive
    ? '1 = 1'
    : "(status = 'active' AND expires_at > ?)";
  const query =
    'SELECT code, created_by, used_by, expires_at, status, created_at, updated_at FROM invites ' +
    `WHERE ${predicate} ORDER BY created_at DESC`;
  const res = includeInactive
    ? await db.prepare(query).all<any>()
    : await db.prepare(query).bind(now).all<any>();

  return (res.results || []).map((row) => ({
    code: row.code,
    createdBy: row.created_by,
    usedBy: row.used_by ?? null,
    expiresAt: row.expires_at,
    status: row.status,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export async function markInviteUsed(db: D1Database, code: string, userId: string): Promise<boolean> {
  void userId;
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      "UPDATE invites SET status = 'used', used_by = NULL, updated_at = ? WHERE code = ? AND status = 'active' AND expires_at > ?"
    )
    .bind(now, code, now)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function assignInviteUsedBy(db: D1Database, code: string, userId: string): Promise<boolean> {
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      "UPDATE invites SET used_by = ?, updated_at = ? WHERE code = ? AND status = 'used' AND used_by IS NULL"
    )
    .bind(userId, now, code)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function revertInviteUsed(db: D1Database, code: string, userId: string): Promise<boolean> {
  void userId;
  const now = new Date().toISOString();
  const result = await db
    .prepare(
      "UPDATE invites SET status = 'active', used_by = NULL, updated_at = ? WHERE code = ? AND status = 'used' AND used_by IS NULL"
    )
    .bind(now, code)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteInvite(db: D1Database, code: string): Promise<boolean> {
  const result = await db
    .prepare('DELETE FROM invites WHERE code = ?')
    .bind(code)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function deleteInvalidInvites(db: D1Database): Promise<number> {
  const now = new Date().toISOString();
  const result = await db
    .prepare("DELETE FROM invites WHERE status != 'active' OR expires_at <= ?")
    .bind(now)
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function deleteAllInvites(db: D1Database): Promise<number> {
  const result = await db.prepare('DELETE FROM invites').run();
  return Number(result.meta.changes ?? 0);
}

export async function createAuditLog(db: D1Database, log: AuditLog): Promise<void> {
  await db
    .prepare(
      'INSERT INTO audit_logs(id, actor_user_id, action, category, level, target_type, target_id, metadata, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
    .bind(log.id, log.actorUserId, log.action, log.category, log.level, log.targetType, log.targetId, log.metadata, log.createdAt)
    .run();
}

export async function pruneAuditLogs(db: D1Database, beforeIso: string): Promise<number> {
  const result = await db
    .prepare('DELETE FROM audit_logs WHERE created_at < ?')
    .bind(beforeIso)
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function pruneAuditLogsToMax(db: D1Database, maxEntries: number): Promise<number> {
  const limit = Math.max(1, Math.floor(maxEntries));
  const result = await db
    .prepare(
      'DELETE FROM audit_logs WHERE id IN (' +
        'SELECT id FROM audit_logs ORDER BY created_at DESC LIMIT -1 OFFSET ?' +
      ')'
    )
    .bind(limit)
    .run();
  return Number(result.meta.changes ?? 0);
}

export async function clearAuditLogs(db: D1Database): Promise<number> {
  const result = await db.prepare('DELETE FROM audit_logs').run();
  return Number(result.meta.changes ?? 0);
}

export async function listAuditLogs(db: D1Database, options: AuditLogListOptions): Promise<AuditLogListResult> {
  const limit = Math.max(1, Math.min(200, Math.floor(options.limit || 50)));
  const offset = Math.max(0, Math.floor(options.offset || 0));
  const { where, params } = buildAuditWhere(options);

  const rows = await db
    .prepare(
      'SELECT l.id, l.actor_user_id, actor.email AS actor_email, l.action, l.category, l.level, l.target_type, l.target_id, target.email AS target_user_email, l.metadata, l.created_at ' +
        'FROM audit_logs l ' +
        'LEFT JOIN users actor ON actor.id = l.actor_user_id ' +
        "LEFT JOIN users target ON l.target_type = 'user' AND target.id = l.target_id " +
        `${where} ORDER BY l.created_at DESC LIMIT ? OFFSET ?`
    )
    .bind(...params, limit + 1, offset)
    .all<any>();
  const results = rows.results || [];
  const logs = results.slice(0, limit).map(auditLogFromRow);
  const hasMore = results.length > limit;

  return {
    logs,
    total: offset + logs.length + (hasMore ? 1 : 0),
    hasMore,
  };
}
