import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../src/db/client';
import {
  ciphers, emergencyAccess, invites, organizationMemberships, sends, smAccessTokens, smProjects,
  smSecretProjects, smSecrets, smServiceAccountProjects, smServiceAccounts, userRevisions,
} from '../src/db/schema';
import { deleteOrganizationAccount, deleteUserAccount } from '../src/services/account-deletion';
import { type AuditEventInput } from '../src/services/audit-events';
import { getAttachmentObjectKey, getSendFileObjectKey } from '../src/services/blob-store';
import { StorageService } from '../src/services/storage';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, memoryKv, seedUser } from './support/env';

const { createOwnedOrganization } = await import('../src/handlers/organizations');

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const PAST = '2020-01-01T00:00:00.000Z';
const audit: AuditEventInput = { action: 'admin.user.delete', category: 'security', level: 'security' };

async function addMember(env: Env, orgId: string, user: User, type = 0, createdAt = PAST) {
  await orgRepo.saveMembership(env.DB, {
    id: crypto.randomUUID(), userId: user.id, orgId, email: user.email, invitedByEmail: null,
    accessAll: true, key: '4.dGVzdA==', status: 2, type, permissions: null, resetPasswordKey: null,
    externalId: null, createdAt, updatedAt: createdAt,
  });
}

async function addCipher(env: Env, userId: string, organizationId: string | null) {
  const id = crypto.randomUUID();
  const attachmentId = crypto.randomUUID();
  await getOrm(env.DB).insert(ciphers).values({
    id, userId, organizationId, type: 1, name: ENCRYPTED, data: '{}', createdAt: PAST, updatedAt: PAST,
  });
  await new StorageService(env.DB).saveAttachment({
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
  const storage = new StorageService(env.DB);
  const org = await createOwnedOrganization(env, target, { name: 'Co-owned', key: '4.dGVzdA==' });
  const successor = await seedUser(env);
  await addMember(env, org.id, successor);
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
  await storage.saveRefreshToken('refresh-token', target.id);
  const eaId = crypto.randomUUID();
  await getOrm(env.DB).insert(emergencyAccess).values({
    id: eaId, grantorId: successor.id, granteeId: target.id, type: 0, status: 2,
    waitTimeDays: 7, createdAt: PAST, updatedAt: PAST,
  });
  await getOrm(env.DB).insert(invites).values({
    code: crypto.randomUUID(), createdBy: target.id, expiresAt: PAST, status: 'active', createdAt: PAST, updatedAt: PAST,
  });
  return { env, admin, target, successor, storage, org, orgCipher, personalCipher, sendKey, eaId, blobs };
}

async function assertIntact(f: Awaited<ReturnType<typeof setup>>) {
  assert.ok(await f.storage.getUserById(f.target.id));
  assert.equal((await f.storage.getCipher(f.orgCipher.id))?.userId, f.target.id);
  assert.ok(await f.storage.getCipher(f.personalCipher.id));
  assert.ok(await f.storage.getRefreshTokenRecord('refresh-token'));
  assert.ok(await f.env.DB.prepare('SELECT id FROM emergency_access WHERE id = ?').bind(f.eaId).first());
  assert.equal(await f.env.DB.prepare('SELECT COUNT(*) AS count FROM audit_logs').first('count'), 0);
  assert.equal(f.blobs.values.size, 3);
}

test('admin user delete keeps org items with the oldest other Owner and cleans personal data, sessions, EA and invites', async () => {
  const f = await setup();
  const olderAdmin = await seedUser(f.env);
  const newerOwner = await seedUser(f.env);
  await addMember(f.env, f.org.id, olderAdmin, 1, '2010-01-01T00:00:00.000Z');
  await addMember(f.env, f.org.id, newerOwner, 0, '2021-01-01T00:00:00.000Z');

  const response = await authedFetch(f.env, {
    method: 'DELETE', path: `/api/admin/users/${f.target.id}`, userId: f.admin.id,
    body: { masterPasswordHash: f.admin.masterPasswordHash },
  });
  assert.equal(response.status, 204);
  assert.equal((await f.storage.getCipher(f.orgCipher.id))?.userId, f.successor.id);
  assert.ok(f.blobs.values.has(f.orgCipher.key));
  assert.equal(f.blobs.values.has(f.personalCipher.key), false);
  assert.equal(f.blobs.values.has(f.sendKey), false);
  assert.equal(await f.storage.getUserById(f.target.id), null);
  assert.equal(await f.storage.getCipher(f.personalCipher.id), null);
  assert.equal(await f.storage.getRefreshTokenRecord('refresh-token'), null);
  assert.equal(await f.env.DB.prepare('SELECT COUNT(*) AS count FROM emergency_access').first('count'), 0);
  assert.equal(await f.env.DB.prepare('SELECT COUNT(*) AS count FROM invites').first('count'), 0);
  const event = await f.env.DB.prepare('SELECT * FROM audit_logs').first<{ action: string; metadata: string; actor_user_id: string }>();
  assert.equal(event?.action, 'admin.user.delete');
  assert.equal(event?.actor_user_id, f.admin.id);
  assert.equal(JSON.parse(event!.metadata).targetEmail, f.target.email);
});

test('user delete falls back to the oldest confirmed member when no other Owner exists', async () => {
  const f = await setup();
  await getOrm(f.env.DB).update(organizationMemberships).set({ type: 1 });
  const newer = await seedUser(f.env);
  await addMember(f.env, f.org.id, newer, 1, '2021-01-01T00:00:00.000Z');
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'deleted' });
  assert.equal((await f.storage.getCipher(f.orgCipher.id))?.userId, f.successor.id);
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
  await f.storage.saveUser({ ...f.target, role: 'admin' });
  await f.storage.saveUser({ ...f.admin, status: 'disabled' });
  assert.deepEqual(await deleteUserAccount(f.env, f.target.id, audit), { kind: 'last-vault-admin' });
  await assertIntact(f);
  assert.deepEqual(await deleteUserAccount(f.env, 'missing', audit), { kind: 'not-found' });
});

test('a concurrent successor revocation or admin deactivation makes every batch write a no-op', async () => {
  for (const change of ['successor', 'admin']) {
    const f = await setup();
    if (change === 'admin') await f.storage.saveUser({ ...f.target, role: 'admin' });
    const batch = f.env.DB.batch.bind(f.env.DB);
    f.env.DB.batch = async (statements) => {
      if (change === 'successor') {
        await getOrm(f.env.DB).update(organizationMemberships).set({ status: 1 })
          .where(eq(organizationMemberships.userId, f.successor.id));
      } else {
        await f.env.DB.prepare("UPDATE users SET status = 'disabled' WHERE id = ?").bind(f.admin.id).run();
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
  assert.equal((await f.storage.getCipher(f.personalCipher.id))?.userId, f.successor.id);
  assert.ok(f.blobs.values.has(f.personalCipher.key));
});

test('an audit write failure rolls back user deletion and leaves every blob in place', async () => {
  const f = await setup();
  await f.env.DB.prepare("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit failure'); END").run();
  await assert.rejects(deleteUserAccount(f.env, f.target.id, audit), /audit failure/);
  await assertIntact(f);
});

test('blob cleanup is best effort after commit and continues after a deletion failure', async () => {
  const f = await setup();
  f.env.ATTACHMENTS_KV!.delete = async (key) => {
    assert.equal(await f.storage.getUserById(f.target.id), null);
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

async function addSecretsManagerData(env: Env, orgId: string) {
  const orm = getOrm(env.DB);
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

test('Owner org deletion cleans blobs and Secrets Manager data and bumps over 100 member revisions without touching another org', async () => {
  const f = await setup();
  const otherOwner = await seedUser(f.env);
  const otherOrg = await createOwnedOrganization(f.env, otherOwner, { name: 'Unchanged', key: '4.dGVzdA==' });
  const otherCipher = await addCipher(f.env, otherOwner.id, otherOrg.id);
  for (const org of [f.org, otherOrg]) await addSecretsManagerData(f.env, org.id);
  for (let index = 0; index < 100; index++) await addMember(f.env, f.org.id, await seedUser(f.env), 2);
  await f.env.DB.prepare('UPDATE user_revisions SET revision_date = ?').bind(PAST).run();
  // Leave one member with no revision row, which the batch must create.
  await getOrm(f.env.DB).delete(userRevisions).where(eq(userRevisions.userId, f.successor.id));
  const members = await orgRepo.listMembershipsByOrg(f.env.DB, f.org.id);
  assert.equal(members.length, 102);

  const response = await authedFetch(f.env, { method: 'DELETE', path: `/api/organizations/${f.org.id}`, userId: f.target.id });
  assert.equal(response.status, 200);
  assert.equal(await orgRepo.getOrganization(f.env.DB, f.org.id), null);
  assert.equal(await f.storage.getCipher(f.orgCipher.id), null);
  assert.equal(f.blobs.values.has(f.orgCipher.key), false);
  assert.ok(f.blobs.values.has(f.personalCipher.key));
  assert.ok(f.blobs.values.has(f.sendKey));
  for (const member of members) assert.ok((await f.storage.getRevisionDate(member.userId!)) > PAST);
  assert.equal(await f.storage.getRevisionDate(otherOwner.id), PAST);
  assert.ok(await orgRepo.getOrganization(f.env.DB, otherOrg.id));
  assert.ok(await f.storage.getCipher(otherCipher.id));
  assert.ok(f.blobs.values.has(otherCipher.key));
  for (const table of ['sm_projects', 'sm_secrets', 'sm_service_accounts', 'sm_access_tokens', 'sm_secret_projects', 'sm_service_account_projects']) {
    assert.equal(await f.env.DB.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first('count'), 1, table);
  }
  assert.equal(await f.env.DB.prepare('SELECT action FROM audit_logs').first('action'), 'organization.delete');
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
  await f.env.DB.prepare('UPDATE user_revisions SET revision_date = ?').bind(PAST).run();
  await f.env.DB.prepare("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT, 'audit failure'); END").run();
  await assert.rejects(deleteOrganizationAccount(f.env, f.org.id, audit), /audit failure/);
  assert.ok(await orgRepo.getOrganization(f.env.DB, f.org.id));
  assert.equal(await f.storage.getRevisionDate(f.target.id), PAST);
  await assertIntact(f);
});
