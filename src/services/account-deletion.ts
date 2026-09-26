import { and, eq, isNull, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { attachments, ciphers, emergencyAccess, sends, session, users } from '../db/schema';
import type { Env } from '../types';
import { AuthService } from './auth';
import { auditEventStatement, type AuditEventInput } from './audit-events';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from './blob-store';
import { reassignOrganizationCiphers } from './storage-cipher-repo';

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
