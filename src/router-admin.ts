import type { Env, User } from './types';
import {
  handleAdminListUsers,
  handleAdminCreateInvite,
  handleAdminListInvites,
  handleAdminDeleteAllInvites,
  handleAdminDeleteInvite,
  handleAdminSetUserStatus,
  handleAdminDeleteUser,
  handleAdminListAuditLogs,
  handleAdminGetAuditLogSettings,
  handleAdminUpdateAuditLogSettings,
  handleAdminClearAuditLogs,
} from './handlers/admin';
import { handleAdminBackupRoute } from './router-admin-backup';
import { errorResponse } from './utils/response';

function isKnownAdminPath(path: string): boolean {
  return (
    path === '/api/admin/users' ||
    path === '/api/admin/logs' ||
    path === '/api/admin/logs/settings' ||
    path === '/api/admin/invites' ||
    path.startsWith('/api/admin/backup') ||
    /^\/api\/admin\/invites\/[^/]+$/i.test(path) ||
    /^\/api\/admin\/users\/[a-f0-9-]+(?:\/status)?$/i.test(path)
  );
}

function isActiveAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

export async function handleAdminRoute(
  request: Request,
  env: Env,
  actorUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if (!isKnownAdminPath(path)) {
    return null;
  }
  if (!isActiveAdmin(actorUser)) {
    return errorResponse('Forbidden', 403);
  }

  if (path === '/api/admin/users' && method === 'GET') {
    return handleAdminListUsers(request, env, actorUser);
  }

  if (path === '/api/admin/logs' && method === 'GET') {
    return handleAdminListAuditLogs(request, env, actorUser);
  }

  if (path === '/api/admin/logs' && method === 'DELETE') {
    return handleAdminClearAuditLogs(request, env, actorUser);
  }

  if (path === '/api/admin/logs/settings') {
    if (method === 'GET') return handleAdminGetAuditLogSettings(request, env, actorUser);
    if (method === 'PUT' || method === 'POST') return handleAdminUpdateAuditLogSettings(request, env, actorUser);
    return null;
  }

  const adminBackupResponse = await handleAdminBackupRoute(request, env, actorUser, path, method);
  if (adminBackupResponse) return adminBackupResponse;

  if (path === '/api/admin/invites') {
    if (method === 'GET') return handleAdminListInvites(request, env, actorUser);
    if (method === 'POST') return handleAdminCreateInvite(request, env, actorUser);
    if (method === 'DELETE') return handleAdminDeleteAllInvites(request, env, actorUser);
    return null;
  }

  const adminInviteMatch = path.match(/^\/api\/admin\/invites\/([^/]+)$/i);
  if (adminInviteMatch && method === 'DELETE') {
    const inviteCode = decodeURIComponent(adminInviteMatch[1]);
    return handleAdminDeleteInvite(request, env, actorUser, inviteCode);
  }

  const adminUserStatusMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]+)\/status$/i);
  if (adminUserStatusMatch && (method === 'PUT' || method === 'POST')) {
    return handleAdminSetUserStatus(request, env, actorUser, adminUserStatusMatch[1]);
  }

  const adminUserDeleteMatch = path.match(/^\/api\/admin\/users\/([a-f0-9-]+)$/i);
  if (adminUserDeleteMatch && method === 'DELETE') {
    return handleAdminDeleteUser(request, env, actorUser, adminUserDeleteMatch[1]);
  }

  return null;
}
