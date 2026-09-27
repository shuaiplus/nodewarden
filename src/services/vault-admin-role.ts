import { and, eq, exists, inArray, ne } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';
import { getOrm } from '../db/client';
import { users } from '../db/schema';
import { caseWhen, jsonValues } from '../db/sql';
import type { Env } from '../types';
import { parseAdminDirectory } from './admin-portal-auth';
import { AuthService } from './auth';
import { writeAuditEvent } from './audit-events';
import { normalizeImportedBackupSettings } from './backup-config';

export async function syncVaultAdminRoles(env: Env): Promise<void> {
  const directory = parseAdminDirectory(env);
  if (directory.kind !== 'enabled') return;
  const orm = getOrm(env.DB);
  const listed = jsonValues([...directory.admins.keys()]);
  const derivedRole = caseWhen<string>(and(inArray(users.email, listed), eq(users.emailVerified, 1)), 'admin', 'user');
  // No-lockout guard: roles move only while some listed address belongs to a verified, active account.
  const listedAdmin = alias(users, 'u');
  const changed = await orm.update(users)
    .set({ role: derivedRole, updatedAt: new Date().toISOString() })
    .where(and(ne(users.role, derivedRole), exists(orm.select({ id: listedAdmin.id }).from(listedAdmin)
      .where(and(inArray(listedAdmin.email, listed), eq(listedAdmin.emailVerified, 1), eq(listedAdmin.status, 'active'))))))
    .returning({ id: users.id, role: users.role });
  if (!changed.length) return;
  for (const user of changed) {
    AuthService.invalidateUserCache(user.id);
    await writeAuditEvent(env.DB, {
      action: 'admin.vault_role.sync', category: 'security', level: 'security', actorUserId: null,
      targetType: 'user', targetId: user.id, metadata: { role: user.role },
    });
  }
  await normalizeImportedBackupSettings(env.DB, env);
}

export async function markEmailVerified(env: Env, userId: string): Promise<void> {
  const [changed] = await getOrm(env.DB).update(users).set({ emailVerified: 1 })
    .where(and(eq(users.id, userId), eq(users.emailVerified, 0))).returning({ id: users.id });
  if (!changed) return;
  AuthService.invalidateUserCache(userId);
  await syncVaultAdminRoles(env);
}
