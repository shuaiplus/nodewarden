import assert from 'node:assert/strict';
import test from 'node:test';

import { createAuth } from '../src/auth';
import { getOrm } from '../src/db/client';
import { ciphers } from '../src/db/schema';
import { AuthService } from '../src/services/auth';
import { getAttachmentObjectKey } from '../src/services/blob-store';
import * as orgRepo from '../src/services/storage-org-repo';
import { authedFetch, createTestEnv, drainWaitUntil, memoryKv, seedUser } from './support/env';
import * as sessionRepo from '../src/services/storage-session-repo';
import * as attachmentRepo from '../src/services/storage-attachment-repo';
import * as cipherRepo from '../src/services/storage-cipher-repo';
import * as userRepo from '../src/services/storage-user-repo';

const { createOwnedOrganization } = await import('../src/handlers/organizations');

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';

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
  assert.equal(await env.DB.prepare('SELECT COUNT(*) AS n FROM audit_logs').first('n'), 0);
});

test('self-deletion transfers org items, cleans personal blobs and revokes access and refresh tokens', async () => {
  const blobs = memoryKv();
  const env = await createTestEnv({ ATTACHMENTS_KV: blobs.binding });
  const user = await seedUser(env);
  const successor = await seedUser(env);
  const org = await createOwnedOrganization(env, user, { name: 'Shared org', key: '4.dGVzdA==' });
  await orgRepo.saveMembership(env.DB, {
    id: crypto.randomUUID(), userId: successor.id, orgId: org.id, email: successor.email, invitedByEmail: null,
    accessAll: true, key: '4.dGVzdA==', status: 2, type: 0, permissions: null, resetPasswordKey: null,
    externalId: null, createdAt: user.createdAt, updatedAt: user.updatedAt,
  });
  const orgCipher = crypto.randomUUID();
  const personalCipher = crypto.randomUUID();
  const personalBlob = getAttachmentObjectKey(personalCipher, 'attachment');
  for (const [id, organizationId] of [[orgCipher, org.id], [personalCipher, null]] as const) {
    await getOrm(env.DB).insert(ciphers).values({ id, userId: user.id, organizationId, type: 1, name: ENCRYPTED, data: '{}', createdAt: user.createdAt, updatedAt: user.updatedAt });
  }
  await attachmentRepo.saveAttachment(env.DB, { id: 'attachment', cipherId: personalCipher, fileName: ENCRYPTED, size: 1, sizeName: '1 Byte', key: ENCRYPTED });
  await env.ATTACHMENTS_KV!.put(personalBlob, 'encrypted');
  const token = await new AuthService(env).generateAccessToken(user);
  await sessionRepo.saveRefreshToken(env.DB, 'refresh-before-delete', user.id);
  const response = await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body: { masterPasswordHash: user.masterPasswordHash } });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
  assert.equal(await userRepo.getUserById(env.DB, user.id), null);
  assert.equal(await cipherRepo.getCipher(env.DB, personalCipher), null);
  assert.equal((await cipherRepo.getCipher(env.DB, orgCipher))?.userId, successor.id);
  assert.equal(blobs.values.has(personalBlob), false);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${token}` } })).status, 401);
  const refresh = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'refresh_token', refresh_token: 'refresh-before-delete' } });
  assert.equal(refresh.status, 400);
  const audit = await env.DB.prepare('SELECT action, target_id FROM audit_logs').first();
  assert.deepEqual(audit, { action: 'user.account.delete', target_id: user.id });
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
