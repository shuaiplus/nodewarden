import assert from 'node:assert/strict';
import { subtle } from 'node:crypto';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { unzipSync, zipSync } from 'fflate';

import { getOrm } from '../db/client';
import { auditLogs } from '../db/schema';
import { buildBackupArchive } from '../services/backup-archive';
import { importBackupArchiveBytes } from '../services/backup-import';
import { BACKUP_SETTINGS_CONFIG_KEY, getDefaultBackupSettings, saveBackupSettings } from '../services/backup-config';
import { parseBackupSettingsEnvelope } from '../services/backup-settings-crypto';
import { AuthService } from '../services/auth';
import { markEmailVerified, syncVaultAdminRoles } from '../services/vault-admin-role';
import { createRegisterVerifyToken } from '../utils/jwt';
import { authedFetch, createTestEnv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import * as configRepo from '../services/storage-config-repo';
import * as userRepo from '../services/storage-user-repo';

const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const roleSyncAudits = (db: D1Database) => getOrm(db).$count(auditLogs, eq(auditLogs.action, 'admin.vault_role.sync'));

test('enabling the first verified listed account synchronizes roles and revokes cached legacy admin access', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: 'listed@x.io' });
  const legacy = await seedUser(env, { role: 'admin' });
  const listed = await seedUser(env, { email: 'listed@x.io', emailVerified: true, status: 'banned' });
  await syncVaultAdminRoles(env);
  const token = await new AuthService(env).generateAccessToken(legacy);
  const headers = { Authorization: `Bearer ${token}` };
  assert.equal((await authedFetch(env, { path: '/api/admin/users', headers })).status, 200);

  const portal = await signInToAdminPortal(env, listed.email);
  const enabled = await portalFetch(env, {
    method: 'POST',
    path: `/admin/users/${listed.id}/enable`,
    cookie: portal.cookie,
    form: { csrf: portal.csrf },
  });
  assert.equal(enabled.status, 303);
  assert.equal((await userRepo.getUserById(env.DB, listed.id))?.role, 'admin');
  assert.equal((await userRepo.getUserById(env.DB, legacy.id))?.role, 'user');
  assert.equal((await authedFetch(env, { path: '/api/admin/users', headers })).status, 403);
});

for (const config of ['disabled', 'invalid', 'absent', 'unverified', 'banned', 'enabled']) {
  test(`directory ${config} obeys the verified active-account guard`, async () => {
    const env = await createTestEnv();
    const legacy = await seedUser(env, { role: 'admin' });
    const listed = await seedUser(env, {
      emailVerified: config !== 'unverified',
      status: config === 'banned' ? 'banned' : 'active',
    });
    env.ADMIN_EMAILS =
      config === 'disabled'
        ? undefined
        : config === 'invalid'
          ? 'invalid'
          : config === 'absent'
            ? 'missing@x.io'
            : listed.email;
    await syncVaultAdminRoles(env);
    assert.equal((await userRepo.getUserById(env.DB, legacy.id))?.role, config === 'enabled' ? 'user' : 'admin');
    assert.equal((await userRepo.getUserById(env.DB, listed.id))?.role, config === 'enabled' ? 'admin' : 'user');
    if (config === 'enabled') {
      await userRepo.saveUser(env.DB, { ...legacy, name: 'Stale role' });
      assert.equal((await userRepo.getUserById(env.DB, legacy.id))?.role, 'user');
      const auditCount = await roleSyncAudits(env.DB);
      await syncVaultAdminRoles(env);
      assert.equal(await roleSyncAudits(env.DB), auditCount);
    }
  });
}

test('only validated registration tokens verify an email; listing a claimed address later cannot promote it', async () => {
  const env = await createTestEnv({ ALLOW_OPEN_REGISTRATION: '1' });
  const firstEmail = 'first@x.io';
  const register = (email: string, token?: string) =>
    authedFetch(env, {
      method: 'POST',
      path: '/identity/accounts/register/finish',
      body: {
        email,
        masterPasswordHash: 'password-hash',
        key: ENCRYPTED,
        encryptedPrivateKey: ENCRYPTED,
        publicKey: 'public-key',
        emailVerificationToken: token,
      },
    });
  env.ADMIN_EMAILS = firstEmail;
  assert.equal((await register(firstEmail)).status, 200);
  const first = (await userRepo.getUser(env.DB, firstEmail))!;
  assert.equal(first.emailVerified, false);
  assert.equal(first.role, 'admin'); // First-account bootstrap remains the no-lockout fallback.
  const claimedEmail = 'claimed@x.io';
  assert.equal((await register(claimedEmail)).status, 200);
  const claimed = (await userRepo.getUser(env.DB, claimedEmail))!;
  assert.equal(claimed.emailVerified, false);
  env.ADMIN_EMAILS = claimedEmail;
  await syncVaultAdminRoles(env);
  assert.equal((await userRepo.getUserById(env.DB, claimed.id))?.role, 'user');
  const verifiedEmail = 'verified@x.io';
  env.ADMIN_EMAILS = `${claimedEmail},${verifiedEmail}`;
  const token = await createRegisterVerifyToken(env.JWT_SECRET, verifiedEmail, null);
  assert.equal((await register(verifiedEmail, token)).status, 200);
  assert.equal((await userRepo.getUser(env.DB, verifiedEmail))?.emailVerified, true);
  assert.equal((await userRepo.getUser(env.DB, verifiedEmail))?.role, 'admin');
  assert.equal((await userRepo.getUserById(env.DB, first.id))?.role, 'user');
  assert.equal((await userRepo.getUserById(env.DB, claimed.id))?.role, 'user');
  const invalid = await register('wrong@x.io', token);
  assert.equal(invalid.status, 400);
  assert.equal(await userRepo.getUser(env.DB, 'wrong@x.io'), null);
  const profile = await authedFetch(env, { path: '/api/accounts/profile', userId: claimed.id });
  assert.equal(((await profile.json()) as { emailVerified: boolean }).emailVerified, true);
});

test('markEmailVerified grants a listed account once and stale saves cannot clear verification', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { emailVerified: false });
  env.ADMIN_EMAILS = user.email;
  await markEmailVerified(env, user.id);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.emailVerified, true);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.role, 'admin');
  await userRepo.saveUser(env.DB, user);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.emailVerified, true);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.role, 'admin');
  await markEmailVerified(env, user.id);
  assert.equal(await roleSyncAudits(env.DB), 1);
});

test('role changes re-wrap live backup settings for the derived administrator', async () => {
  const env = await createTestEnv();
  const { publicKey } = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-1' },
    true,
    ['encrypt', 'decrypt'],
  );
  const spki = Buffer.from(await subtle.exportKey('spki', publicKey)).toString('base64');
  const old = await seedUser(env, { role: 'admin', publicKey: spki });
  const listed = await seedUser(env, { publicKey: spki });
  await saveBackupSettings(env.DB, env, getDefaultBackupSettings());
  assert.deepEqual(
    parseBackupSettingsEnvelope(
      await configRepo.getConfigValue(env.DB, BACKUP_SETTINGS_CONFIG_KEY),
    )!.portable.wraps.map((w) => w.userId),
    [old.id],
  );
  env.ADMIN_EMAILS = listed.email;
  await syncVaultAdminRoles(env);
  assert.deepEqual(
    parseBackupSettingsEnvelope(
      await configRepo.getConfigValue(env.DB, BACKUP_SETTINGS_CONFIG_KEY),
    )!.portable.wraps.map((w) => w.userId),
    [listed.id],
  );
});

test('local and remote backup restore preserve verified state, default legacy rows and correct imported roles', async () => {
  const source = await createTestEnv();
  const legacy = await seedUser(source, { role: 'admin' });
  const listed = await seedUser(source);
  const unverified = await seedUser(source, { emailVerified: false });
  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: false });
  const files = unzipSync(archive.bytes);
  const db = JSON.parse(new TextDecoder().decode(files['db.json']));
  assert.equal(db.users.find((row: { id: string }) => row.id === unverified.id).email_verified, 0);
  delete db.users.find((row: { id: string }) => row.id === listed.id).email_verified;
  files['db.json'] = Buffer.from(JSON.stringify(db));
  const bytes = zipSync(files);
  for (const remote of [false, true]) {
    const env = await createTestEnv({ ADMIN_EMAILS: listed.email });
    await importBackupArchiveBytes(bytes, env, legacy.id, false, remote ? { loadAttachment: async () => null } : null);
    assert.equal((await userRepo.getUserById(env.DB, listed.id))?.role, 'admin');
    assert.equal((await userRepo.getUserById(env.DB, listed.id))?.emailVerified, true);
    assert.equal((await userRepo.getUserById(env.DB, legacy.id))?.role, 'user');
    assert.equal((await userRepo.getUserById(env.DB, unverified.id))?.emailVerified, false);
  }
});
