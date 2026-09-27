import { Hono } from 'hono';
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
import { adminBackupRoutes } from './router-admin-backup';
import { errorResponse } from './utils/response';
import type { AppEnv } from './router';

const adminUser = '/api/admin/users/:userId{[a-f0-9-]+}';

export const adminRoutes = new Hono<AppEnv>();

// Known admin paths answer 403 to non-admins whatever the method; unknown ones stay 404.
adminRoutes.on(
  'ALL',
  [
    '/api/admin/users',
    '/api/admin/logs',
    '/api/admin/logs/settings',
    '/api/admin/invites',
    '/api/admin/backup',
    '/api/admin/backup/*',
    '/api/admin/invites/:inviteCode',
    adminUser,
    `${adminUser}/status`,
  ],
  async (c, next) => {
    const currentUser = c.get('currentUser');
    if (currentUser.role !== 'admin' || currentUser.status !== 'active') return errorResponse('Forbidden', 403);
    await next();
  },
);

adminRoutes.get('/api/admin/users', (c) => handleAdminListUsers(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.get('/api/admin/logs', (c) => handleAdminListAuditLogs(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/logs', (c) => handleAdminClearAuditLogs(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.get('/api/admin/logs/settings', (c) =>
  handleAdminGetAuditLogSettings(c.req.raw, c.env, c.get('currentUser')),
);
adminRoutes.on(['PUT', 'POST'], '/api/admin/logs/settings', (c) =>
  handleAdminUpdateAuditLogSettings(c.req.raw, c.env, c.get('currentUser')),
);

adminRoutes.route('/', adminBackupRoutes);

adminRoutes.get('/api/admin/invites', (c) => handleAdminListInvites(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.post('/api/admin/invites', (c) => handleAdminCreateInvite(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/invites', (c) => handleAdminDeleteAllInvites(c.req.raw, c.env, c.get('currentUser')));
adminRoutes.delete('/api/admin/invites/:inviteCode', (c) =>
  handleAdminDeleteInvite(c.req.raw, c.env, c.get('currentUser'), c.req.param('inviteCode')),
);
adminRoutes.on(['PUT', 'POST'], `${adminUser}/status`, (c) =>
  handleAdminSetUserStatus(c.req.raw, c.env, c.get('currentUser'), c.req.param('userId')),
);
adminRoutes.delete(adminUser, (c) =>
  handleAdminDeleteUser(c.req.raw, c.env, c.get('currentUser'), c.req.param('userId')),
);
