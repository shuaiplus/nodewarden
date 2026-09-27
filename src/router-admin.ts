import { Hono } from 'hono';
import type { User } from './types';
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
import type { AppEnv } from './router';

function isActiveAdmin(user: User): boolean {
  return user.role === 'admin' && user.status === 'active';
}

const adminUser = '/api/admin/users/:userId{[a-f0-9-]+}';

export const adminRoutes = new Hono<AppEnv>();

// Known admin paths answer 403 to non-admins whatever the method; unknown ones stay 404.
adminRoutes.on('ALL', [
  '/api/admin/users',
  '/api/admin/logs',
  '/api/admin/logs/settings',
  '/api/admin/invites',
  '/api/admin/backup',
  '/api/admin/backup/*',
  '/api/admin/invites/:inviteCode',
  adminUser,
  `${adminUser}/status`,
], async (c, next) => {
  if (!isActiveAdmin(c.get('currentUser'))) return errorResponse('Forbidden', 403);
  await next();
});

adminRoutes.get('/api/admin/users', (c) => handleAdminListUsers(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.get('/api/admin/logs', (c) => handleAdminListAuditLogs(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/logs', (c) => handleAdminClearAuditLogs(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.get('/api/admin/logs/settings', (c) => handleAdminGetAuditLogSettings(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.on(['PUT', 'POST'], '/api/admin/logs/settings', (c) => handleAdminUpdateAuditLogSettings(c.req.raw, c.env, c.get('currentUser')));

adminRoutes.use(async (c, next) => {
  const adminBackupResponse = await handleAdminBackupRoute(c.req.raw, c.env, c.get('currentUser'), c.req.path, c.req.method);
  if (adminBackupResponse) return adminBackupResponse;
  await next();
});

adminRoutes.get('/api/admin/invites', (c) => handleAdminListInvites(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.post('/api/admin/invites', (c) => handleAdminCreateInvite(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/invites', (c) => handleAdminDeleteAllInvites(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/invites/:inviteCode', (c) => handleAdminDeleteInvite(c.req.raw, c.env, c.get('currentUser'), c.req.param('inviteCode')));
adminRoutes.on(['PUT', 'POST'], `${adminUser}/status`, (c) => handleAdminSetUserStatus(c.req.raw, c.env, c.get('currentUser'), c.req.param('userId')));
adminRoutes.delete(adminUser, (c) => handleAdminDeleteUser(c.req.raw, c.env, c.get('currentUser'), c.req.param('userId')));
