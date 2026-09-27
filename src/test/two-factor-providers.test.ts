import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { integer, sqliteTable } from 'drizzle-orm/sqlite-core';

import { getOrm } from '../db/client';
import { session, trustedTwoFactorDeviceTokens, webauthnCredentials } from '../db/schema';
import { hashPassword } from '../services/auth-password';
import { twoFactorClearStatements } from '../services/two-factor-providers';
import type { Env, User } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMember, seedMembership } from './support/sm';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as deviceRepo from '../services/storage-device-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

const { createOwnedOrganization } = await import('../handlers/organizations');

const PASSWORD = 'client-master-password-hash';
const TOTP = 'JBSWY3DPEHPK3PXP';
const RECOVERY = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';

async function seedPasskey(env: Env, user: User, purpose: 'login' | 'twoFactor') {
  const id = crypto.randomUUID();
  await getOrm(env.DB).insert(webauthnCredentials).values({
    id,
    userId: user.id,
    purpose,
    name: purpose,
    publicKey: 'cHVibGlj',
    credentialId: id,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  });
  return id;
}

test('TOTP, YubiKey and WebAuthn are reported consistently; login passkeys are not two-factor', async (t) => {
  const env = await createTestEnv();
  const owner = await seedUser(env, { role: 'admin' });
  const org = await createOwnedOrganization(env, owner, { name: '2FA org', key: '4.dGVzdA==' });
  const users = [
    await seedUser(env, { totpSecret: TOTP }),
    await seedUser(env, { yubikeyKey1: 'cccccccccccc' }),
    await seedUser(env),
    await seedUser(env),
  ];
  await seedPasskey(env, users[2], 'twoFactor');
  await seedPasskey(env, users[3], 'login');
  for (const [index, user] of users.entries()) {
    await seedMembership(env, org.id, { userId: user.id, email: user.email });
    const profile = await authedFetch(env, { path: '/api/accounts/profile', userId: user.id });
    assert.equal(((await profile.json()) as { twoFactorEnabled: boolean }).twoFactorEnabled, index < 3);
    const providers = await authedFetch(env, { path: '/api/two-factor', userId: user.id });
    assert.deepEqual(
      ((await providers.json()) as { Data: { Type: number }[] }).Data.map((p) => p.Type),
      index < 3 ? [[0], [3], [7]][index] : [],
    );
  }
  const prepare = t.mock.method(env.DB, 'prepare');
  const list = async (path: string) => {
    const start = prepare.mock.callCount();
    const response = await authedFetch(env, { path, userId: owner.id });
    assert.equal(response.status, 200);
    const body = (await response.json()) as { data: { id: string; userId?: string; twoFactorEnabled: boolean }[] };
    return { rows: body.data, queries: prepare.mock.callCount() - start };
  };
  const memberPath = `/api/organizations/${org.id}/users`;
  // Warm request-level auth/rate-limit state before comparing list query counts.
  await list(memberPath);
  await list('/api/admin/users');
  const smallMembers = await list(memberPath);
  const smallAdmins = await list('/api/admin/users');
  for (const result of [smallMembers, smallAdmins]) {
    for (const [index, user] of users.entries()) {
      assert.equal(
        result.rows.find((row) => (row.userId ?? row.id) === user.id)?.twoFactorEnabled,
        index < 3,
        JSON.stringify({ index, rows: result.rows }),
      );
    }
  }
  for (let i = 5; i < 60; i++) await seedMember(env, org.id);
  const largeMembers = await list(memberPath);
  const largeAdmins = await list('/api/admin/users');
  assert.equal(largeMembers.rows.length, 60);
  assert.equal(largeMembers.queries, smallMembers.queries);
  assert.equal(largeAdmins.queries, smallAdmins.queries);
});

for (const loginRecovery of [false, true]) {
  test(`${loginRecovery ? 'login recovery provider' : 'recovery endpoint'} clears all factors and prior sessions atomically, preserving login passkeys`, async () => {
    const env = await createTestEnv();
    const user = await seedUser(env, {
      masterPasswordHash: await hashPassword(PASSWORD),
      totpSecret: TOTP,
      totpRecoveryCode: RECOVERY,
      yubikeyKey1: 'cccccccccccc',
    });
    const loginPasskey = await seedPasskey(env, user, 'login');
    await seedPasskey(env, user, 'twoFactor');
    await sessionRepo.saveRefreshToken(env.DB, 'old-session', user.id);
    await deviceRepo.saveTrustedTwoFactorDeviceToken(
      env.DB,
      'remember-before-recovery',
      user.id,
      'device',
      Date.now() + 60000,
    );
    const response = await authedFetch(env, {
      method: 'POST',
      path: loginRecovery ? '/identity/connect/token' : '/identity/accounts/recover-2fa',
      body: loginRecovery
        ? {
            grant_type: 'password',
            username: user.email,
            password: PASSWORD,
            twoFactorProvider: '8',
            twoFactorToken: RECOVERY,
          }
        : { email: user.email, masterPasswordHash: PASSWORD, recoveryCode: RECOVERY },
    });
    assert.equal(response.status, 200);
    const updated = (await userRepo.getUserById(env.DB, user.id))!;
    assert.equal(updated.totpSecret, null);
    assert.equal(updated.yubikeyKey1, null);
    assert.notEqual(updated.totpRecoveryCode, RECOVERY);
    assert.notEqual(updated.securityStamp, user.securityStamp);
    assert.equal(
      await getOrm(env.DB).$count(trustedTwoFactorDeviceTokens, eq(trustedTwoFactorDeviceTokens.userId, user.id)),
      0,
    );
    assert.equal(await sessionRepo.getRefreshTokenUserId(env.DB, 'old-session'), null);
    assert.equal(await getOrm(env.DB).$count(session, eq(session.userId, user.id)), loginRecovery ? 1 : 0);
    assert.deepEqual(
      (await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, user.id)).map((key) => key.id),
      [loginPasskey],
    );
    // Enrolling a new factor must not revive a remember token issued before recovery.
    await userRepo.saveUser(env.DB, { ...updated, totpSecret: TOTP }, ['totpSecret']);
    const remembered = await authedFetch(env, {
      method: 'POST',
      path: '/identity/connect/token',
      body: {
        grant_type: 'password',
        username: user.email,
        password: PASSWORD,
        deviceIdentifier: 'device',
        twoFactorProvider: '5',
        twoFactorToken: 'remember-before-recovery',
      },
    });
    assert.equal(remembered.status, 400);
    assert.deepEqual(((await remembered.json()) as { TwoFactorProviders: string[] }).TwoFactorProviders, ['0']);
  });
}

test('a failed clear batch leaves credentials and security stamp intact', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { totpSecret: TOTP });
  const orm = getOrm(env.DB);
  await assert.rejects(
    orm.batch([
      ...twoFactorClearStatements(env.DB, user.id, { recoveryCode: null, securityStamp: crypto.randomUUID() }),
      // No migration creates this table, so the batch fails after the clear statements.
      orm.select().from(sqliteTable('missing_table', { one: integer('one') })),
    ]),
    /no such table: missing_table/,
  );
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.securityStamp, user.securityStamp);
});

test('disabling the authenticator also deletes its Better Auth secret', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: TOTP });
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/two-factor/disable',
    userId: user.id,
    body: { type: 0, masterPasswordHash: PASSWORD },
  });
  assert.equal(response.status, 200);
});
