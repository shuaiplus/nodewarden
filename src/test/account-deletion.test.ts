import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, getTableName } from 'drizzle-orm';

import { createAuth } from '../auth';
import { getOrm } from '../db/client';
import {
  auditLogs, ciphers, emergencyAccess, invites, organizationMemberships, sends, smAccessTokens, smProjects,
  smSecretProjects, smSecrets, smServiceAccountProjects, smServiceAccounts, userRevisions, users,
} from '../db/schema';
import { deleteOrganizationAccount, deleteUserAccount } from '../services/account-deletion';
import { AuthService } from '../services/auth';
import { type AuditEventInput } from '../services/audit-events';
import { getAttachmentObjectKey, getSendFileObjectKey } from '../services/blob-store';
import * as orgRepo from '../services/storage-org-repo';
import type { Env } from '../types';
import { abortWrites, authedFetch, createTestEnv, drainWaitUntil, memoryKv, seedUser } from './support/env';
import { seedMember } from './support/sm';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as cipherRepo from '../services/storage-cipher-repo';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

const { createOwnedOrganization } = await import('../handlers/organizations');

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const PAST = '2020-01-01T00:00:00.000Z';
const audit: AuditEventInput = { action: 'admin.user.delete', category: 'security', level: 'security' };

// Members join with full access at `createdAt`: the successor is the oldest other Owner, else the oldest member.
function addMember(env: Env, orgId: string, type = 0, createdAt = PAST) {
  return seedMember(env, orgId, { type, accessAll: true, createdAt, updatedAt: createdAt });
}

async function addCipher(env: Env, userId: string, organizationId: string | null) {
  const id = crypto.randomUUID();
  const attachmentId = crypto.randomUUID();
  await getOrm(env.DB).insert(ciphers).values({
    id, userId, organizationId, type: 1, name: ENCRYPTED, data: '{}', createdAt: PAST, updatedAt: PAST,
  });
  await attachmentRepo.saveAttachment(env.DB, {
    id: attachmentId, cipherId: id, fileName: ENCRYPTED, size: 10, sizeName: '10 Bytes', key: ENCRYPTED,
  });
  const key = getAttachmentObjectKey(id, attachmentId);
  await env.ATTACHMENTS_KV!.put(key, 'encrypted blob');
  return { id, key };
}

async function setup() {
  const blobs = memoryKv();
  const env = await createTestEnv({ ATTACHMENTS_KV: blobs.binding });
  const admin = await seedUser(env, { role: 'admin' });
  const target = await seedUser(env);
  const org = await createOwnedOrganization(env, target, { name: 'Co-owned', key: '4.dGVzdA==' });
  const { user: successor } = await addMember(env, org.id);
  const orgCipher = await addCipher(env, target.id, org.id);
  const personalCipher = await addCipher(env, target.id, null);
  const sendId = crypto.randomUUID();
  const fileId = crypto.randomUUID();
  const sendKey = getSendFileObjectKey(sendId, fileId);
  await getOrm(env.DB).insert(sends).values({
    id: sendId, userId: target.id, type: 1, name: ENCRYPTED, key: ENCRYPTED, data: JSON.stringify({ id: fileId }),
    createdAt: PAST, updatedAt: PAST, deletionDate: '2099-01-01T00:00:00.000Z',
  });
  await env.ATTACHMENTS_KV!.put(sendKey, 'encrypted Send');
  await sessionRepo.saveRefreshToken(env.DB, 'refresh-token', target.id);
  const eaId = crypto.randomUUID();
  await getOrm(env.DB).insert(emergencyAccess).values({
    id: eaId, grantorId: successor.id, granteeId: target.id, type: 0, status: 2,
    waitTimeDays: 7, createdAt: PAST, updatedAt: PAST,
  });
  await getOrm(env.DB).insert(invites).values({
    code: crypto.randomUUID(), createdBy: target.id, expiresAt: PAST, status: 'active', createdAt: PAST, updatedAt: PAST,
  });
  return { env, admin, target, successor, org, orgCipher, personalCipher, sendKey, eaId, blobs };
}

async function assertIntact(f: Awaited<ReturnType<typeof setup>>) {
  assert.ok(await userRepo.getUserById(f.env.DB, f.target.id));
  assert.equal((await cipherRepo.getCipher(f.env.DB, f.orgCipher.id))?.userId, f.target.id);
  assert.ok(await cipherRepo.getCipher(f.env.DB, f.personalCipher.id));
  assert.ok(await sessionRepo.getRefreshTokenRecord(f.env.DB, 'refresh-token'));
  assert.ok(await getOrm(f.env.DB).select({ id: emergencyAccess.id }).from(emergencyAccess).where(eq(emergencyAccess.id, f.eaId)).get());
  assert.equal(await getOrm(f.env.DB).$count(auditLogs), 0);
  assert.equal(f.blobs.values.size, 3);
}

test('admin user delete keeps org items with the oldest other Owner and cleans personal data, sessions, EA and invites', async () => {
  const f = await setup();
  await addMember(f.env, f.org.id, 1, '2010-01-01T00:00:00.000Z');
  await addMember(f.env, f.org.id, 0, '2021-01-01T00:00:00.000Z');

  const response = await authedFetch(f.env, {
    method: 'DELETE', path: `/api/admin/users/${f.target.id}`, userId: f.admin.id,
    body: { masterPasswordHash: f.admin.masterPasswordHash },
  });
  assert.equal(response.status, 204);
  assert.equal((await cipherRepo.getCipher(f.env.DB, f.orgCipher.id))?.userId, f.successor.id);
  assert.ok(f.blobs.values.has(f.orgCipher.key));
  assert.equal(f.blobs.values.has(f.personalCipher.key), false);
  assert.equal(f.blobs.values.has(f.sendKey), false);
  assert.equal(await userRepo.getUserById(f.env.DB, f.target.id), null);
  assert.equal(await cipherRepo.getCipher(f.env.DB, f.personalCipher.id), null);
  assert.equal(await sessionRepo.getRefreshTokenRecord(f.env.DB, 'refresh-token'), null);
  assert.equal(await getOrm(f.env.DB).$count(emergencyAccess), 0);
  assert.equal(await getOrm(f.env.DB).$count(invites), 0);
  const event = await getOrm(f.env.DB).select().from(auditLogs).get();
  assert.equal(event?.action, 'admin.user.delete');
  assert.equal(event?.actorUserId, f.admin.id);
  assert.equal(JSON.parse(event!.metadata!).targetEmail, f.target.email);
});

test('user delete falls back to the oldest confirmed member when no other Owner exists', async () => {
  const f = await setup();
  await getOrm(f.env.DB).update(organizationMemberships).set({ type: 1 });
  await addMember(f.env, f.org.id, 1, '2021-01-01T00:00:00.000Z');
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'deleted' });
  assert.equal((await cipherRepo.getCipher(f.env.DB, f.orgCipher.id))?.userId, f.successor.id);
  assert.ok(f.blobs.values.has(f.orgCipher.key));
});

test('sole Owners and item creators without a confirmed successor are refused without side effects', async () => {
  for (const soleOwner of [true, false]) {
    const f = await setup();
    await getOrm(f.env.DB).update(organizationMemberships).set({ status: 1 })
      .where(eq(organizationMemberships.userId, f.successor.id));
    if (!soleOwner) await getOrm(f.env.DB).update(organizationMemberships).set({ type: 1 });
    assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'blocked-by-orgs', orgIds: [f.org.id] });
    await assertIntact(f);
    const response = await authedFetch(f.env, {
      method: 'DELETE', path: `/api/admin/users/${f.target.id}`, userId: f.admin.id,
      body: { masterPasswordHash: f.admin.masterPasswordHash },
    });
    assert.equal(response.status, 400);
    assert.match(await response.text(), /Transfer or delete these organizations first/);
  }
});

test('deleting the last active vault admin is refused even if an inactive admin exists', async () => {
  const f = await setup();
  await getOrm(f.env.DB).update(users).set({ role: 'admin' }).where(eq(users.id, f.target.id));
  await getOrm(f.env.DB).update(users).set({ status: 'banned' }).where(eq(users.id, f.admin.id));
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'last-vault-admin' });
  await assertIntact(f);
  assert.deepEqual(await deleteUserAccount(f.env, 'missing', audit), { kind: 'not-found' });
});

test('a concurrent successor revocation or admin deactivation makes every batch write a no-op', async () => {
  for (const change of ['successor', 'admin']) {
    const f = await setup();
    if (change === 'admin') await getOrm(f.env.DB).update(users).set({ role: 'admin' }).where(eq(users.id, f.target.id));
    const batch = f.env.DB.batch.bind(f.env.DB);
    f.env.DB.batch = async (statements) => {
      if (change === 'successor') {
        await getOrm(f.env.DB).update(organizationMemberships).set({ status: 1 })
          .where(eq(organizationMemberships.userId, f.successor.id));
      } else {
        await getOrm(f.env.DB).update(users).set({ status: 'banned' }).where(eq(users.id, f.admin.id));
      }
      return batch(statements);
    };
    const expected = change === 'successor' ? { kind: 'blocked-by-orgs', orgIds: [f.org.id] } : { kind: 'last-vault-admin' };
    assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), expected);
    await assertIntact(f);
  }
});

test('a cipher shared after the refusal check keeps its attachment blob', async () => {
  const f = await setup();
  const batch = f.env.DB.batch.bind(f.env.DB);
  f.env.DB.batch = async (statements) => {
    await getOrm(f.env.DB).update(ciphers).set({ organizationId: f.org.id }).where(eq(ciphers.id, f.personalCipher.id));
    return batch(statements);
  };
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'deleted' });
  assert.equal((await cipherRepo.getCipher(f.env.DB, f.personalCipher.id))?.userId, f.successor.id);
  assert.ok(f.blobs.values.has(f.personalCipher.key));
});

test('an audit write failure rolls back user deletion and leaves every blob in place', async () => {
  const f = await setup();
  await abortWrites(f.env, { table: auditLogs, event: 'INSERT' }, 'audit failure');
  await assert.rejects(deleteUserAccount(f.env, f.target.id, audit), /audit failure/);
  await assertIntact(f);
});

test('blob cleanup is best effort after commit and continues after a deletion failure', async () => {
  const f = await setup();
  f.env.ATTACHMENTS_KV!.delete = async (key) => {
    assert.equal(await userRepo.getUserById(f.env.DB, f.target.id), null);
    if (key === f.personalCipher.key) throw new Error('blob unavailable');
    f.blobs.values.delete(key);
  };
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'deleted' });
  assert.ok(f.blobs.values.has(f.personalCipher.key));
  assert.equal(f.blobs.values.has(f.sendKey), false);
});

test('admin user deletion rejects non-admins, wrong passwords and self-deletion', async () => {
  const f = await setup();
  for (const [user, targetId, password, status] of [
    [f.successor, f.target.id, f.successor.masterPasswordHash, 403],
    [f.admin, f.target.id, 'wrong', 400],
    [f.admin, f.admin.id, f.admin.masterPasswordHash, 400],
  ] as const) {
    const response = await authedFetch(f.env, {
      method: 'DELETE', path: `/api/admin/users/${targetId}`, userId: user.id, body: { masterPasswordHash: password },
    });
    assert.equal(response.status, status);
    await assertIntact(f);
  }
});

test('self-deletion requires the master password and refuses sole Owners and the last active administrator', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  for (const body of [{}, { masterPasswordHash: 'wrong' }, { otp: user.masterPasswordHash }]) {
    const response = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body });
    assert.equal(response.status, 400);
    assert.equal((await response.json() as { error: string }).error, 'User verification failed.');
    assert.ok(await userRepo.getUserById(env.DB, user.id));
  }
  for (const body of [null, [], 'invalid', undefined]) {
    const response = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body });
    assert.equal(response.status, 400);
    assert.ok(await userRepo.getUserById(env.DB, user.id));
  }
  const org = await createOwnedOrganization(env, user, { name: 'Sole Owner', key: '4.dGVzdA==' });
  const owner = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body: { masterPasswordHash: user.masterPasswordHash } });
  assert.equal(owner.status, 400);
  assert.match(await owner.text(), /sole owner/);
  assert.ok(await orgRepo.getOrganization(env.DB, org.id));
  assert.ok(await userRepo.getUserById(env.DB, user.id));
  const admin = await seedUser(env, { role: 'admin' });
  const lastAdmin = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: admin.id, body: { masterPasswordHash: admin.masterPasswordHash } });
  assert.equal(lastAdmin.status, 400);
  assert.equal((await lastAdmin.json() as { error: string }).error, 'You cannot delete the last instance administrator.');
  assert.ok(await userRepo.getUserById(env.DB, admin.id));
  assert.equal(await getOrm(env.DB).$count(auditLogs), 0);
});

test('self-deletion transfers org items, cleans personal blobs and revokes access and refresh tokens', async () => {
  const f = await setup();
  const token = await new AuthService(f.env).generateAccessToken(f.target);
  const response = await authedFetch(f.env, { method: 'DELETE', path: '/api/accounts', userId: f.target.id, body: { masterPasswordHash: f.target.masterPasswordHash } });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
  assert.equal(await userRepo.getUserById(f.env.DB, f.target.id), null);
  assert.equal(await cipherRepo.getCipher(f.env.DB, f.personalCipher.id), null);
  assert.equal((await cipherRepo.getCipher(f.env.DB, f.orgCipher.id))?.userId, f.successor.id);
  assert.equal(f.blobs.values.has(f.personalCipher.key), false);
  assert.equal((await authedFetch(f.env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${token}` } })).status, 401);
  const refresh = await authedFetch(f.env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'refresh_token', refresh_token: 'refresh-token' } });
  assert.equal(refresh.status, 400);
  const logged = await getOrm(f.env.DB).select({ action: auditLogs.action, targetId: auditLogs.targetId }).from(auditLogs).get();
  assert.deepEqual(logged, { action: 'user.account.delete', targetId: f.target.id });
  await drainWaitUntil();
});

test('the accounts root and POST delete aliases use the same guarded deletion', async () => {
  for (const [method, path] of [['DELETE', '/accounts'], ['POST', '/api/accounts/delete']]) {
    const env = await createTestEnv();
    const user = await seedUser(env);
    const response = await authedFetch(env, { method, path, userId: user.id, body: { masterPasswordHash: user.masterPasswordHash } });
    assert.equal(response.status, 200);
    assert.equal(await userRepo.getUserById(env.DB, user.id), null);
    await drainWaitUntil();
  }
});

test('Better Auth cannot delete accounts or change email outside the vault adapter', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const options = createAuth(env).options;
  assert.equal(options.user?.deleteUser?.enabled, false);
  assert.equal(options.user?.changeEmail?.enabled, false);
  for (const path of ['/api/auth/delete-user', '/api/auth/change-email']) {
    const response = await authedFetch(env, { method: 'POST', path, userId: user.id, body: { password: user.masterPasswordHash, newEmail: 'replacement@example.test' } });
    assert.equal(response.ok, false);
    assert.equal((await userRepo.getUserById(env.DB, user.id))?.email, user.email);
  }
});

test('Owner org deletion cleans blobs and Secrets Manager data and bumps over 100 member revisions without touching another org', async () => {
  const f = await setup();
  const otherOwner = await seedUser(f.env);
  const otherOrg = await createOwnedOrganization(f.env, otherOwner, { name: 'Unchanged', key: '4.dGVzdA==' });
  const otherCipher = await addCipher(f.env, otherOwner.id, otherOrg.id);
  // One row in every Secrets Manager table per org: after the deletion only the other org's rows remain.
  for (const orgId of [f.org.id, otherOrg.id]) {
    const orm = getOrm(f.env.DB);
    const projectId = crypto.randomUUID();
    const secretId = crypto.randomUUID();
    const serviceAccountId = crypto.randomUUID();
    const tokenId = crypto.randomUUID();
    await orm.batch([
      orm.insert(smProjects).values({ id: projectId, orgId, name: ENCRYPTED, createdAt: PAST, updatedAt: PAST }),
      orm.insert(smSecrets).values({ id: secretId, orgId, key: ENCRYPTED, value: ENCRYPTED, createdAt: PAST, updatedAt: PAST }),
      orm.insert(smServiceAccounts).values({ id: serviceAccountId, orgId, name: ENCRYPTED, createdAt: PAST, updatedAt: PAST }),
      orm.insert(smAccessTokens).values({ id: tokenId, serviceAccountId, name: ENCRYPTED, clientSecretHash: 'hash', createdAt: PAST }),
      orm.insert(smSecretProjects).values({ secretId, projectId }),
      orm.insert(smServiceAccountProjects).values({ serviceAccountId, projectId }),
    ]);
  }
  for (let index = 0; index < 100; index++) await addMember(f.env, f.org.id, 2);
  await getOrm(f.env.DB).update(userRevisions).set({ revisionDate: PAST });
  // Leave one member with no revision row, which the batch must create.
  await getOrm(f.env.DB).delete(userRevisions).where(eq(userRevisions.userId, f.successor.id));
  const members = await orgRepo.listMembershipsByOrg(f.env.DB, f.org.id);
  assert.equal(members.length, 102);

  const response = await authedFetch(f.env, { method: 'DELETE', path: `/api/organizations/${f.org.id}`, userId: f.target.id });
  assert.equal(response.status, 200);
  assert.equal(await orgRepo.getOrganization(f.env.DB, f.org.id), null);
  assert.equal(await cipherRepo.getCipher(f.env.DB, f.orgCipher.id), null);
  assert.equal(f.blobs.values.has(f.orgCipher.key), false);
  assert.ok(f.blobs.values.has(f.personalCipher.key));
  assert.ok(f.blobs.values.has(f.sendKey));
  for (const member of members) assert.ok((await revisionRepo.getRevisionDate(f.env.DB, member.userId!)) > PAST);
  assert.equal(await revisionRepo.getRevisionDate(f.env.DB, otherOwner.id), PAST);
  assert.ok(await orgRepo.getOrganization(f.env.DB, otherOrg.id));
  assert.ok(await cipherRepo.getCipher(f.env.DB, otherCipher.id));
  assert.ok(f.blobs.values.has(otherCipher.key));
  for (const table of [smProjects, smSecrets, smServiceAccounts, smAccessTokens, smSecretProjects, smServiceAccountProjects]) {
    assert.equal(await getOrm(f.env.DB).$count(table), 1, getTableName(table));
  }
  assert.equal((await getOrm(f.env.DB).select({ action: auditLogs.action }).from(auditLogs).get())?.action, 'organization.delete');
});

test('a non-owner cannot delete an organization', async () => {
  const f = await setup();
  await getOrm(f.env.DB).update(organizationMemberships).set({ type: 1 })
    .where(eq(organizationMemberships.userId, f.successor.id));
  const response = await authedFetch(f.env, { method: 'DELETE', path: `/api/organizations/${f.org.id}`, userId: f.successor.id });
  assert.equal(response.status, 403);
  assert.ok(await orgRepo.getOrganization(f.env.DB, f.org.id));
  await assertIntact(f);
});

test('an org deletion audit failure rolls back revisions, ciphers and the org before touching blobs', async () => {
  const f = await setup();
  await getOrm(f.env.DB).update(userRevisions).set({ revisionDate: PAST });
  await abortWrites(f.env, { table: auditLogs, event: 'INSERT' }, 'audit failure');
  await assert.rejects(deleteOrganizationAccount(f.env, f.org.id, audit), /audit failure/);
  assert.ok(await orgRepo.getOrganization(f.env.DB, f.org.id));
  assert.equal(await revisionRepo.getRevisionDate(f.env.DB, f.target.id), PAST);
  await assertIntact(f);
});
