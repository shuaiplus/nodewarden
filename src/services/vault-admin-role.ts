import type { Env } from '../types';
import { parseAdminDirectory } from './admin-portal-auth';
import { AuthService } from './auth';
import { writeAuditEvent } from './audit-events';
import { normalizeImportedBackupSettings } from './backup-config';

export async function syncVaultAdminRoles(env: Env): Promise<void> {
  const directory = parseAdminDirectory(env);
  if (directory.kind !== 'enabled') return;
  const changed = await env.DB.prepare(`
    WITH directory(email) AS (SELECT value FROM json_each(?))
    UPDATE users SET role = CASE WHEN email IN (SELECT email FROM directory) AND email_verified = 1 THEN 'admin' ELSE 'user' END,
      updated_at = ?
    WHERE role <> CASE WHEN email IN (SELECT email FROM directory) AND email_verified = 1 THEN 'admin' ELSE 'user' END
      AND EXISTS (SELECT 1 FROM users u WHERE u.email IN (SELECT email FROM directory) AND u.email_verified = 1 AND u.status = 'active')
    RETURNING id, role
  `).bind(JSON.stringify([...directory.admins.keys()]), new Date().toISOString()).all<{ id: string; role: string }>();
  if (!changed.results.length) return;
  for (const user of changed.results) {
    AuthService.invalidateUserCache(user.id);
    await writeAuditEvent(env.DB, {
      action: 'admin.vault_role.sync', category: 'security', level: 'security', actorUserId: null,
      targetType: 'user', targetId: user.id, metadata: { role: user.role },
    });
  }
  await normalizeImportedBackupSettings(env.DB, env);
}

export async function markEmailVerified(env: Env, userId: string): Promise<void> {
  const changed = await env.DB.prepare('UPDATE users SET email_verified = 1 WHERE id = ? AND email_verified = 0 RETURNING id')
    .bind(userId).first();
  if (!changed) return;
  AuthService.invalidateUserCache(userId);
  await syncVaultAdminRoles(env);
}
