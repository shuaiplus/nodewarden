import { and, eq, exists, isNotNull, isNull, ne, not, notExists } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { getOrm, userRowMatches, type Orm } from '../db/client';
import {
  attachments,
  ciphers,
  emergencyAccess,
  organizationMemberships,
  organizations,
  sends,
  session,
  users,
} from '../db/schema';
import { scalar, unmapped } from '../db/sql';
import type { Env } from '../types';
import { AuthService } from './auth';
import { normalizeImportedBackupSettings } from './backup-config';
import { syncVaultAdminRoles } from './vault-admin-role';
import { auditEventStatement, writeAuditEvent, type AuditEventInput } from './audit-events';
import { deleteBlobObject, getAttachmentObjectKey, getSendFileObjectKey } from './blob-store';
import { deleteCiphersByOrganization, reassignOrganizationCiphers } from './storage-cipher-repo';
import { MembershipStatus, MembershipType } from './org-types';
import { bumpOrgMemberRevisions, deleteOrganization } from './storage-org-repo';
import * as userRepo from './storage-user-repo';

export type DeleteUserAccountResult =
  | { kind: 'deleted' }
  | { kind: 'not-found' }
  | { kind: 'blocked-by-orgs'; orgIds: string[] }
  | { kind: 'last-vault-admin' };

// Organizations only this user keeps alive: they are the sole confirmed owner, or they own organization
// items and no other member is confirmed. Awaited it lists them; embedded it guards the deletion batch.
function blockedOrganizations(orm: Orm, userId: string) {
  const owner = alias(organizationMemberships, 'owner');
  const owned = alias(ciphers, 'owned');
  const successor = alias(organizationMemberships, 'successor');
  const confirmedSuccessor = eq(successor.status, MembershipStatus.Confirmed);
  return (
    orm
      .select({ orgId: owner.orgId })
      .from(owner)
      .where(
        and(
          eq(owner.userId, userId),
          eq(owner.status, MembershipStatus.Confirmed),
          eq(owner.type, MembershipType.Owner),
          notExists(
            orm
              .select({ id: successor.id })
              .from(successor)
              .where(
                and(
                  eq(successor.orgId, owner.orgId),
                  ne(successor.userId, userId),
                  confirmedSuccessor,
                  eq(successor.type, MembershipType.Owner),
                ),
              ),
          ),
        ),
      )
      // The IS NOT NULL filter makes this a string; the typed wrapper tells the union so.
      .union(
        orm
          .select({ orgId: unmapped<string>(owned.organizationId) })
          .from(owned)
          .where(
            and(
              eq(owned.userId, userId),
              isNotNull(owned.organizationId),
              notExists(
                orm
                  .select({ id: successor.id })
                  .from(successor)
                  .where(
                    and(eq(successor.orgId, owned.organizationId), ne(successor.userId, userId), confirmedSuccessor),
                  ),
              ),
            ),
          ),
      )
  );
}

// Inside a statement over users, each subquery's own FROM users shadows the outer row, so these
// conditions always read the subquery's rows.
function lastActiveAdmin(orm: Orm, userId: string) {
  const activeAdmin = [eq(users.role, 'admin'), eq(users.status, 'active')];
  return and(
    userRowMatches(orm, userId, ...activeAdmin),
    notExists(
      orm
        .select({ id: users.id })
        .from(users)
        .where(and(ne(users.id, userId), ...activeAdmin)),
    ),
  )!;
}

export type SetUserStatusResult = { kind: 'updated' | 'unchanged' | 'not-found' | 'last-vault-admin' };

export async function setUserStatus(
  env: Env,
  userId: string,
  next: 'active' | 'banned',
  audit: AuditEventInput,
): Promise<SetUserStatusResult> {
  const orm = getOrm(env.DB);
  let changed: boolean;
  if (next === 'banned') {
    const securityStamp = crypto.randomUUID();
    const updated = userRowMatches(orm, userId, eq(users.securityStamp, securityStamp));
    const [update] = await orm.batch([
      orm
        .update(users)
        .set({ status: 'banned', securityStamp, updatedAt: new Date().toISOString() })
        .where(and(eq(users.id, userId), eq(users.status, 'active'), not(lastActiveAdmin(orm, userId)))),
      orm.delete(session).where(and(eq(session.userId, userId), updated)),
      auditEventStatement(env.DB, audit, updated),
    ]);
    changed = (update.meta.changes ?? 0) > 0;
  } else {
    const updated = await orm
      .update(users)
      .set({ status: 'active', updatedAt: new Date().toISOString() })
      .where(and(eq(users.id, userId), eq(users.status, 'banned')))
      .returning({ id: users.id });
    changed = updated.length > 0;
    if (changed) await writeAuditEvent(env.DB, audit);
  }
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return { kind: 'not-found' };
  if (!changed) return { kind: user.status === next ? 'unchanged' : 'last-vault-admin' };
  AuthService.invalidateUserCache(userId);
  if (next === 'banned') {
    const { notifyUserLogout } = await import('../durable/notifications-hub');
    notifyUserLogout(env, userId, null);
  } else {
    await syncVaultAdminRoles(env);
  }
  if (user.role === 'admin') await normalizeImportedBackupSettings(env.DB, env);
  return { kind: 'updated' };
}

async function userDeletionRefusal(
  db: D1Database,
  userId: string,
  securityStamp?: string,
): Promise<Exclude<DeleteUserAccountResult, { kind: 'deleted' }> | null> {
  const orm = getOrm(db);
  const [user] = await orm
    .select({ lastAdmin: scalar<number>(lastActiveAdmin(orm, userId)) })
    .from(users)
    .where(and(eq(users.id, userId), securityStamp === undefined ? undefined : eq(users.securityStamp, securityStamp)));
  if (!user) return { kind: 'not-found' };
  const orgs = await blockedOrganizations(orm, userId);
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

export async function deleteUserAccount(
  env: Env,
  userId: string,
  audit: AuditEventInput,
  securityStamp?: string,
): Promise<DeleteUserAccountResult> {
  const refusal = await userDeletionRefusal(env.DB, userId, securityStamp);
  if (refusal) return refusal;

  const orm = getOrm(env.DB);
  const guard = and(
    userRowMatches(orm, userId, securityStamp === undefined ? undefined : eq(users.securityStamp, securityStamp)),
    notExists(blockedOrganizations(orm, userId)),
    not(lastActiveAdmin(orm, userId)),
  )!;
  // Read keys in the same transaction: a personal cipher shared before this batch must keep its blob.
  const [personalAttachments, fileSends, , , , , deletion] = await orm.batch([
    orm
      .select({ cipherId: attachments.cipherId, id: attachments.id })
      .from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherId, ciphers.id))
      .where(and(eq(ciphers.userId, userId), isNull(ciphers.organizationId), guard)),
    orm
      .select({ id: sends.id, data: sends.data })
      .from(sends)
      .where(and(eq(sends.userId, userId), eq(sends.type, 1), guard)),
    reassignOrganizationCiphers(env.DB, userId, guard),
    orm.delete(emergencyAccess).where(and(eq(emergencyAccess.granteeId, userId), guard)),
    orm.delete(session).where(and(eq(session.userId, userId), guard)),
    auditEventStatement(env.DB, audit, guard),
    orm.delete(users).where(and(eq(users.id, userId), guard)),
  ]);
  if (!deletion.meta.changes) {
    const changedRefusal = await userDeletionRefusal(env.DB, userId, securityStamp);
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
    orm
      .select({ cipherId: attachments.cipherId, id: attachments.id })
      .from(attachments)
      .innerJoin(ciphers, eq(attachments.cipherId, ciphers.id))
      .where(eq(ciphers.organizationId, orgId)),
    bumpOrgMemberRevisions(env.DB, orgId),
    deleteCiphersByOrganization(env.DB, orgId),
    auditEventStatement(
      env.DB,
      audit,
      exists(orm.select({ id: organizations.id }).from(organizations).where(eq(organizations.id, orgId))),
    ),
    deleteOrganization(env.DB, orgId),
  ]);
  await deleteBlobs(
    env,
    orgAttachments.map((attachment) => getAttachmentObjectKey(attachment.cipherId, attachment.id)),
  );
}
