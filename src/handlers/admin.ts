import { z } from 'zod';
import { Env, User, Invite } from '../types';
import { AuthService } from '../services/auth';
import { twoFactorProviders } from '../services/two-factor-providers';
import { getAllUsersWithTwoFactor } from '../services/storage-user-repo';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { deleteUserAccount, setUserStatus } from '../services/account-deletion';
import { auditRequestMetadata, getAuditLogSettings, normalizeAuditLogSettings, saveAuditLogSettings, writeAuditEvent } from '../services/audit-events';
import * as adminRepo from '../services/storage-admin-repo';
import * as userRepo from '../services/storage-user-repo';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

const PASSWORD_REQUIRED = 'masterPasswordHash is required';
const PasswordBody = z.object({ masterPasswordHash: z.string({ error: PASSWORD_REQUIRED }).trim().min(1, { error: PASSWORD_REQUIRED }) }, { error: PASSWORD_REQUIRED });
const DEFAULT_INVITE_HOURS = 24 * 7;
const MAX_INVITE_HOURS = 24 * 30;
const InviteBody = PasswordBody.extend({
  expiresInHours: z.coerce.number().catch(DEFAULT_INVITE_HOURS).transform(hours => Math.max(1, Math.min(MAX_INVITE_HOURS, Math.floor(hours)))),
});
const StatusBody = PasswordBody.extend({ status: z.enum(['active', 'banned'], { error: 'status must be active or banned' }) });

// Every destructive admin action re-proves the master password; unparseable JSON reads as a missing one.
async function readConfirmedBody<S extends typeof PasswordBody>(request: Request, env: Env, actorUser: User, schema: S): Promise<z.output<S> | Response> {
  const body = await parseBody(request, schema, PASSWORD_REQUIRED);
  if (body instanceof Response) return body;
  const valid = await new AuthService(env).verifyPassword(body.masterPasswordHash, actorUser.masterPasswordHash, actorUser.email);
  return valid ? body : errorResponse('Invalid password', 400);
}

async function writeAuditLog(
  db: D1Database,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null,
  request?: Request
): Promise<void> {
  await writeAuditEvent(db, {
    actorUserId,
    action,
    targetType,
    targetId,
    category: action.startsWith('admin.user.') ? 'security' : 'system',
    level: action.startsWith('admin.user.') ? 'security' : 'info',
    metadata: {
      ...(metadata || {}),
      ...(request ? auditRequestMetadata(request) : {}),
    },
  });
}

function toInviteResponse(request: Request, invite: Invite): Record<string, unknown> {
  return {
    code: invite.code,
    status: invite.status,
    createdBy: invite.createdBy,
    usedBy: invite.usedBy,
    createdAt: invite.createdAt,
    updatedAt: invite.updatedAt,
    expiresAt: invite.expiresAt,
    inviteLink: `${new URL(request.url).origin}/?invite=${encodeURIComponent(invite.code)}`,
    object: 'invite',
  };
}

// GET /api/admin/users
export async function handleAdminListUsers(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const users = await getAllUsersWithTwoFactor(env.DB);
  const data = users.map(user => {
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      twoFactorEnabled: twoFactorProviders(user, user.hasTwoFactorPasskey).length > 0,
      creationDate: user.createdAt,
      revisionDate: user.updatedAt,
      object: 'user',
    };
  });
  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/admin/logs
export async function handleAdminListAuditLogs(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const url = new URL(request.url);
  const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit') || 50) || 50));
  const offset = Math.max(0, Number(url.searchParams.get('offset') || 0) || 0);
  const category = String(url.searchParams.get('category') || '').trim() || null;
  const level = String(url.searchParams.get('level') || '').trim() || null;
  const q = String(url.searchParams.get('q') || '').trim().toLowerCase() || null;
  const from = String(url.searchParams.get('from') || '').trim() || null;
  const to = String(url.searchParams.get('to') || '').trim() || null;

  const result = await adminRepo.listAuditLogs(env.DB, { limit, offset, category, level, q, from, to });
  return jsonResponse({
    data: result.logs.map(log => ({
      id: log.id,
      actorUserId: log.actorUserId,
      actorEmail: log.actorEmail,
      action: log.action,
      category: log.category,
      level: log.level,
      targetType: log.targetType,
      targetId: log.targetId,
      targetUserEmail: log.targetUserEmail,
      metadata: log.metadata,
      createdAt: log.createdAt,
      object: 'auditLog',
    })),
    total: result.total,
    limit,
    offset,
    hasMore: result.hasMore,
    object: 'list',
    continuationToken: result.hasMore ? String(offset + result.logs.length) : null,
  });
}

// GET /api/admin/logs/settings
export async function handleAdminGetAuditLogSettings(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  void request;
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }
  return jsonResponse({
    object: 'auditLogSettings',
    ...await getAuditLogSettings(env.DB),
  });
}

// PUT /api/admin/logs/settings
export async function handleAdminUpdateAuditLogSettings(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }
  const body = await parseBody(request, z.unknown());
  if (body instanceof Response) return body;
  const settings = await saveAuditLogSettings(env.DB, normalizeAuditLogSettings(body));
  await writeAuditLog(env.DB, actorUser.id, 'admin.audit.settings.update', 'auditLog', null, { ...settings }, request);
  return jsonResponse({
    object: 'auditLogSettings',
    ...settings,
  });
}

// DELETE /api/admin/logs
export async function handleAdminClearAuditLogs(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }
  const deleted = await adminRepo.clearAuditLogs(env.DB);
  await writeAuditLog(env.DB, actorUser.id, 'admin.audit.clear', 'auditLog', null, {
    deleted,
  }, request);
  return jsonResponse({ object: 'auditLogClear', deleted });
}

// POST /api/admin/invites
export async function handleAdminCreateInvite(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const body = await readConfirmedBody(request, env, actorUser, InviteBody);
  if (body instanceof Response) return body;
  const { expiresInHours } = body;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInHours * 60 * 60 * 1000);
  const invite: Invite = {
    code: crypto.getRandomValues(new Uint8Array(20)).toHex(),
    createdBy: actorUser.id,
    usedBy: null,
    expiresAt: expiresAt.toISOString(),
    status: 'active',
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  await adminRepo.createInvite(env.DB, invite);
  await writeAuditLog(env.DB, actorUser.id, 'admin.invite.create', 'invite', null, {
    expiresInHours,
  }, request);

  return jsonResponse(toInviteResponse(request, invite), 201);
}

// GET /api/admin/invites
export async function handleAdminListInvites(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const url = new URL(request.url);
  const includeInactive = url.searchParams.get('includeInactive') === 'true';
  const invites = await adminRepo.listInvites(env.DB, includeInactive);
  return jsonResponse({
    data: invites.map(invite => toInviteResponse(request, invite)),
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/admin/invites/:code
export async function handleAdminDeleteInvite(
  request: Request,
  env: Env,
  actorUser: User,
  code: string
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const confirmed = await readConfirmedBody(request, env, actorUser, PasswordBody);
  if (confirmed instanceof Response) return confirmed;

  const deleted = await adminRepo.deleteInvite(env.DB, code);
  if (!deleted) {
    return errorResponse('Invite not found', 404);
  }

  await writeAuditLog(env.DB, actorUser.id, 'admin.invite.delete', 'invite', null, {
    code,
  }, request);
  return new Response(null, { status: 204 });
}

// DELETE /api/admin/invites
export async function handleAdminDeleteAllInvites(
  request: Request,
  env: Env,
  actorUser: User
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const confirmed = await readConfirmedBody(request, env, actorUser, PasswordBody);
  if (confirmed instanceof Response) return confirmed;

  const url = new URL(request.url);
  if (url.searchParams.get('scope') === 'invalid') {
    const deleted = await adminRepo.deleteInvalidInvites(env.DB);
    await writeAuditLog(env.DB, actorUser.id, 'admin.invite.delete_invalid', 'invite', null, {
      deleted,
    }, request);

    return jsonResponse({ deleted }, 200);
  }

  const deleted = await adminRepo.deleteAllInvites(env.DB);
  await writeAuditLog(env.DB, actorUser.id, 'admin.invite.delete_all', 'invite', null, {
    deleted,
  }, request);

  return jsonResponse({ deleted }, 200);
}

// PUT /api/admin/users/:id/status
export async function handleAdminSetUserStatus(
  request: Request,
  env: Env,
  actorUser: User,
  targetUserId: string
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  const body = await readConfirmedBody(request, env, actorUser, StatusBody);
  if (body instanceof Response) return body;
  const nextStatus = body.status;
  if (targetUserId === actorUser.id && nextStatus !== 'active') {
    return errorResponse('You cannot ban yourself', 400);
  }

  const target = await userRepo.getUserById(env.DB, targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  const outcome = await setUserStatus(env, target.id, nextStatus, {
    actorUserId: actorUser.id, action: 'admin.user.status', category: 'security', level: 'security',
    targetType: 'user', targetId: target.id,
    metadata: { status: nextStatus, ...auditRequestMetadata(request) },
  });
  if (outcome.kind === 'not-found') return errorResponse('User not found', 404);
  if (outcome.kind === 'last-vault-admin') return errorResponse('Cannot disable the last active instance administrator.', 400);

  return jsonResponse({
    id: target.id,
    email: target.email,
    role: target.role,
    status: nextStatus,
    object: 'user',
  });
}

// DELETE /api/admin/users/:id
export async function handleAdminDeleteUser(
  request: Request,
  env: Env,
  actorUser: User,
  targetUserId: string
): Promise<Response> {
  if (!isAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }
  if (targetUserId === actorUser.id) {
    return errorResponse('You cannot delete yourself', 400);
  }

  const confirmed = await readConfirmedBody(request, env, actorUser, PasswordBody);
  if (confirmed instanceof Response) return confirmed;

  const target = await userRepo.getUserById(env.DB, targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  const result = await deleteUserAccount(env, target.id, {
    actorUserId: actorUser.id,
    action: 'admin.user.delete',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: target.id,
    metadata: { targetEmail: target.email, ...auditRequestMetadata(request) },
  });
  if (result.kind === 'not-found') return errorResponse('User not found', 404);
  if (result.kind === 'blocked-by-orgs') return errorResponse('Transfer or delete these organizations first', 400);
  if (result.kind === 'last-vault-admin') return errorResponse('Cannot delete the last instance admin', 400);

  return new Response(null, { status: 204 });
}
