import { and, eq, isNull, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { attachments, ciphers, emergencyAccess, sends, session, users } from '../db/schema';
import type { Env } from '../types';
import { AuthService } from './auth';
import { StorageService } from './storage';
import { normalizeImportedBackupSettings } from './backup-config';
import { auditEventStatement, writeAuditEvent, type AuditEventInput } from './audit-events';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from './blob-store';
import { deleteCiphersByOrganization, reassignOrganizationCiphers } from './storage-cipher-repo';
import { bumpOrgMemberRevisions, deleteOrganization } from './storage-org-repo';

export type DeleteUserAccountResult =
  | { kind: 'deleted' }
  | { kind: 'not-found' }
  | { kind: 'blocked-by-orgs'; orgIds: string[] }
  | { kind: 'last-vault-admin' };

function blockedOrganizations(userId: string) {
  return sql`
    SELECT owner.org_id AS orgId FROM organization_memberships owner
    WHERE owner.user_id = ${userId} AND owner.status = 2 AND owner.type = 0
      AND NOT EXISTS (
        SELECT 1 FROM organization_memberships successor
        WHERE successor.org_id = owner.org_id AND successor.user_id <> ${userId}
          AND successor.status = 2 AND successor.type = 0
      )
    UNION
    SELECT owned.organization_id AS orgId FROM ciphers owned
    WHERE owned.user_id = ${userId} AND owned.organization_id IS NOT NULL
      AND NOT EXISTS (
        SELECT 1 FROM organization_memberships successor
        WHERE successor.org_id = owned.organization_id AND successor.user_id <> ${userId}
          AND successor.status = 2
      )
  `;
}

function lastActiveAdmin(userId: string) {
  return sql`EXISTS (SELECT 1 FROM users WHERE id = ${userId} AND role = 'admin' AND status = 'active')
    AND NOT EXISTS (SELECT 1 FROM users WHERE id <> ${userId} AND role = 'admin' AND status = 'active')`;
}

export type SetUserStatusResult = { kind: 'updated' | 'unchanged' | 'not-found' | 'last-vault-admin' };

export async function setUserStatus(env: Env, userId: string, next: 'active' | 'banned', audit: AuditEventInput): Promise<SetUserStatusResult> {
  const storage = new StorageService(env.DB);
  const orm = getOrm(env.DB);
  let changed: boolean;
  if (next === 'banned') {
    const securityStamp = crypto.randomUUID();
    const updated = sql`EXISTS (SELECT 1 FROM users WHERE id = ${userId} AND security_stamp = ${securityStamp})`;
    const [update] = await orm.batch([
      orm.update(users).set({ status: 'banned', securityStamp, updatedAt: new Date().toISOString() })
        .where(and(eq(users.id, userId), eq(users.status, 'active'), sql`NOT (${lastActiveAdmin(userId)})`)),
      orm.delete(session).where(and(eq(session.userId, userId), updated)),
      auditEventStatement(env.DB, audit, updated),
    ]);
    changed = (update.meta.changes ?? 0) > 0;
  } else {
    const updated = await orm.update(users).set({ status: 'active', updatedAt: new Date().toISOString() })
      .where(and(eq(users.id, userId), eq(users.status, 'banned'))).returning({ id: users.id });
    changed = updated.length > 0;
    if (changed) await writeAuditEvent(storage, audit);
  }
  const user = await storage.getUserById(userId);
  if (!user) return { kind: 'not-found' };
  if (!changed) return { kind: user.status === next ? 'unchanged' : 'last-vault-admin' };
  AuthService.invalidateUserCache(userId);
  if (next === 'banned') {
    const { notifyUserLogout } = await import('../durable/notifications-hub');
    notifyUserLogout(env, userId, null);
  }
  if (user.role === 'admin') await normalizeImportedBackupSettings(storage, env);
  return { kind: 'updated' };
}

async function userDeletionRefusal(db: D1Database, userId: string): Promise<Exclude<DeleteUserAccountResult, { kind: 'deleted' }> | null> {
  const orm = getOrm(db);
  const [user] = await orm.select({ lastAdmin: sql<number>`(${lastActiveAdmin(userId)})` })
    .from(users).where(eq(users.id, userId));
  if (!user) return { kind: 'not-found' };
  const orgs = await orm.all<{ orgId: string }>(blockedOrganizations(userId));
  if (orgs.length) return { kind: 'blocked-by-orgs', orgIds: orgs.map((org) => org.orgId) };
  return user.lastAdmin ? { kind: 'last-vault-admin' } : null;
}

async function deleteBlobs(env: Env, keys: string[]): Promise<void> {
  for (const key of keys) {
    try {
      await deleteBlobObject(env, key);
    } catch (error) {
      console.error('account deletion blob cleanup failed', { key, error });
    }
  }
}

export async function deleteUserAccount(env: Env, userId: string, audit: AuditEventInput): Promise<DeleteUserAccountResult> {
  const refusal = await userDeletionRefusal(env.DB, userId);
  if (refusal) return refusal;

  const orm = getOrm(env.DB);
  const guard = sql`EXISTS (SELECT 1 FROM users WHERE id = ${userId})
    AND NOT EXISTS (${blockedOrganizations(userId)}) AND NOT (${lastActiveAdmin(userId)})`;
  // Read keys in the same transaction: a personal cipher shared before this batch must keep its blob.
  const [personalAttachments, fileSends, , , , , deletion] = await orm.batch([
    orm.select({ cipherId: attachments.cipherId, id: attachments.id }).from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherId, ciphers.id))
      .where(and(eq(ciphers.userId, userId), isNull(ciphers.organizationId), guard)),
    orm.select({ id: sends.id, data: sends.data }).from(sends)
      .where(and(eq(sends.userId, userId), eq(sends.type, 1), guard)),
    reassignOrganizationCiphers(env.DB, userId, guard),
    orm.delete(emergencyAccess).where(and(eq(emergencyAccess.granteeId, userId), guard)),
    orm.delete(session).where(and(eq(session.userId, userId), guard)),
    auditEventStatement(env.DB, audit, guard),
    orm.delete(users).where(and(eq(users.id, userId), guard)),
  ]);
  if (!deletion.meta.changes) {
    const changedRefusal = await userDeletionRefusal(env.DB, userId);
    if (changedRefusal) return changedRefusal;
    throw new Error('User deletion preconditions changed; retry the request');
  }

  const keys = personalAttachments.map((attachment) => getAttachmentObjectKey(attachment.cipherId, attachment.id));
  for (const send of fileSends) {
    try {
      const fileId = JSON.parse(send.data)?.id;
      if (typeof fileId === 'string' && fileId) keys.push(getSendFileObjectKey(send.id, fileId));
    } catch {
      console.warn('account deletion skipped malformed Send data', { sendId: send.id });
    }
  }
  await deleteBlobs(env, keys);
  AuthService.invalidateUserCache(userId);
  return { kind: 'deleted' };
}

export async function deleteOrganizationAccount(env: Env, orgId: string, audit: AuditEventInput): Promise<void> {
  const orm = getOrm(env.DB);
  const [orgAttachments] = await orm.batch([
    orm.select({ cipherId: attachments.cipherId, id: attachments.id }).from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherId, ciphers.id)).where(eq(ciphers.organizationId, orgId)),
    bumpOrgMemberRevisions(env.DB, orgId),
    deleteCiphersByOrganization(env.DB, orgId),
    auditEventStatement(env.DB, audit, sql`EXISTS (SELECT 1 FROM organizations WHERE id = ${orgId})`),
    deleteOrganization(env.DB, orgId),
  ]);
  await deleteBlobs(env, orgAttachments.map((attachment) => getAttachmentObjectKey(attachment.cipherId, attachment.id)));
}
