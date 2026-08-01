import { Env, User, Invite } from '../types';
import { AuthService } from '../services/auth';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from '../services/blob-store';
import { auditRequestMetadata, getAuditLogSettings, normalizeAuditLogSettings, saveAuditLogSettings, writeAuditEvent } from '../services/audit-events';

function isAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

async function requireMasterPasswordHash(
  env: Env,
  actorUser: User,
  masterPasswordHash: unknown
): Promise<Response | null> {
  const normalized = String(masterPasswordHash || '').trim();
  if (!normalized) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const auth = new AuthService(env);
  const valid = await auth.verifyPassword(normalized, actorUser.masterPasswordHash, actorUser.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }
  return null;
}

async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const body = await request.json();
    return body && typeof body === 'object' && !Array.isArray(body)
      ? body as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function randomHex(bytes: number): string {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(data).map(v => v.toString(16).padStart(2, '0')).join('');
}

function buildInviteLink(request: Request, code: string): string {
  const url = new URL(request.url);
  return `${url.origin}/?invite=${encodeURIComponent(code)}`;
}

async function writeAuditLog(
  storage: StorageService,
  actorUserId: string | null,
  action: string,
  targetType: string | null,
  targetId: string | null,
  metadata: Record<string, unknown> | null,
  request?: Request
): Promise<void> {
  await writeAuditEvent(storage, {
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
    inviteLink: buildInviteLink(request, invite.code),
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

  const storage = new StorageService(env.DB);
  const users = await storage.getAllUsers();
  const data = await Promise.all(users.map(async user => {
    const hasTwoFactorPasskey = await storage.countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor') > 0;
    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      twoFactorEnabled: !!user.totpSecret || Boolean(user.yubikeyKey1 || user.yubikeyKey2 || user.yubikeyKey3 || user.yubikeyKey4 || user.yubikeyKey5) || hasTwoFactorPasskey,
      creationDate: user.createdAt,
      revisionDate: user.updatedAt,
      object: 'user',
    };
  }));
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
  const limit = Math.max(1, Math.min(200, Number(url.searchParams.get('limit') || 50)));
  const offset = Math.max(0, Number(url.searchParams.get('offset') || 0));
  const category = String(url.searchParams.get('category') || '').trim() || null;
  const level = String(url.searchParams.get('level') || '').trim() || null;
  const q = String(url.searchParams.get('q') || '').trim().toLowerCase() || null;
  const from = String(url.searchParams.get('from') || '').trim() || null;
  const to = String(url.searchParams.get('to') || '').trim() || null;

  const storage = new StorageService(env.DB);
  const result = await storage.listAuditLogs({ limit, offset, category, level, q, from, to });
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
  const storage = new StorageService(env.DB);
  return jsonResponse({
    object: 'auditLogSettings',
    ...await getAuditLogSettings(storage),
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
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const storage = new StorageService(env.DB);
  const settings = await saveAuditLogSettings(storage, normalizeAuditLogSettings(body));
  await writeAuditLog(storage, actorUser.id, 'admin.audit.settings.update', 'auditLog', null, { ...settings }, request);
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
  const storage = new StorageService(env.DB);
  const deleted = await storage.clearAuditLogs();
  await writeAuditLog(storage, actorUser.id, 'admin.audit.clear', 'auditLog', null, {
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

  const storage = new StorageService(env.DB);
  const body = await readJsonBody(request);
  const passwordError = await requireMasterPasswordHash(env, actorUser, body.masterPasswordHash);
  if (passwordError) return passwordError;

  const expiresInHours = Number.isFinite(Number(body.expiresInHours))
    ? Math.max(1, Math.min(24 * 30, Math.floor(Number(body.expiresInHours))))
    : 24 * 7;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + expiresInHours * 60 * 60 * 1000);
  const invite: Invite = {
    code: randomHex(20),
    createdBy: actorUser.id,
    usedBy: null,
    expiresAt: expiresAt.toISOString(),
    status: 'active',
    createdAt: now.toISOString(),
    updatedAt: now.toISOString(),
  };

  await storage.createInvite(invite);
  await writeAuditLog(storage, actorUser.id, 'admin.invite.create', 'invite', null, {
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

  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeInactive = url.searchParams.get('includeInactive') === 'true';
  const invites = await storage.listInvites(includeInactive);
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

  const body = await readJsonBody(request);
  const passwordError = await requireMasterPasswordHash(env, actorUser, body.masterPasswordHash);
  if (passwordError) return passwordError;

  const storage = new StorageService(env.DB);
  const deleted = await storage.deleteInvite(code);
  if (!deleted) {
    return errorResponse('Invite not found', 404);
  }

  await writeAuditLog(storage, actorUser.id, 'admin.invite.delete', 'invite', null, {
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

  const body = await readJsonBody(request);
  const passwordError = await requireMasterPasswordHash(env, actorUser, body.masterPasswordHash);
  if (passwordError) return passwordError;

  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  if (url.searchParams.get('scope') === 'invalid') {
    const deleted = await storage.deleteInvalidInvites();
    await writeAuditLog(storage, actorUser.id, 'admin.invite.delete_invalid', 'invite', null, {
      deleted,
    }, request);

    return jsonResponse({ deleted }, 200);
  }

  const deleted = await storage.deleteAllInvites();
  await writeAuditLog(storage, actorUser.id, 'admin.invite.delete_all', 'invite', null, {
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

  const body = await readJsonBody(request);
  const passwordError = await requireMasterPasswordHash(env, actorUser, body.masterPasswordHash);
  if (passwordError) return passwordError;

  const nextStatus = body.status === 'banned' ? 'banned' : body.status === 'active' ? 'active' : null;
  if (!nextStatus) {
    return errorResponse('status must be active or banned', 400);
  }
  if (targetUserId === actorUser.id && nextStatus !== 'active') {
    return errorResponse('You cannot ban yourself', 400);
  }

  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  target.status = nextStatus;
  target.updatedAt = new Date().toISOString();
  await storage.saveUser(target);
  if (nextStatus === 'banned') {
    await storage.deleteRefreshTokensByUserId(target.id);
  }
  AuthService.invalidateUserCache(target.id);
  await writeAuditLog(storage, actorUser.id, 'admin.user.status', 'user', target.id, {
    status: nextStatus,
  }, request);

  return jsonResponse({
    id: target.id,
    email: target.email,
    role: target.role,
    status: target.status,
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

  const body = await readJsonBody(request);
  const passwordError = await requireMasterPasswordHash(env, actorUser, body.masterPasswordHash);
  if (passwordError) return passwordError;

  const storage = new StorageService(env.DB);
  const target = await storage.getUserById(targetUserId);
  if (!target) {
    return errorResponse('User not found', 404);
  }

  // Clean up R2 files before DB cascade deletes the metadata rows.
  // 1. Attachment files (keyed by cipherId/attachmentId)
  const attachmentMap = await storage.getAttachmentsByUserId(target.id);
  for (const [cipherId, attachments] of attachmentMap) {
    for (const att of attachments) {
      await deleteBlobObject(env, getAttachmentObjectKey(cipherId, att.id));
    }
  }
  // 2. Send files (keyed by sends/sendId/fileId)
  const sends = await storage.getAllSends(target.id);
  for (const send of sends) {
    if (send.type === 1) { // SendType.File
      try {
        const parsed = JSON.parse(send.data) as Record<string, unknown>;
        const fileId = typeof parsed.id === 'string' ? parsed.id : null;
        if (fileId) {
          await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));
        }
      } catch { /* non-file send or bad data, skip */ }
    }
  }

  await storage.deleteRefreshTokensByUserId(target.id);
  await storage.deleteUserById(target.id);
  AuthService.invalidateUserCache(target.id);
  await writeAuditLog(storage, actorUser.id, 'admin.user.delete', 'user', target.id, {
    targetEmail: target.email,
  }, request);

  return new Response(null, { status: 204 });
}
