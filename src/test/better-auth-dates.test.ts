import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { createAuth } from '../auth';
import { getOrm } from '../db/client';
import {
  account as accountTable,
  session as sessionTable,
  users,
  verification as verificationTable,
} from '../db/schema';
import { unmapped } from '../db/sql';
import { upsertCredentialAccount } from '../services/auth-accounts';
import { hashPassword } from '../services/auth-password';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('Better Auth signs in, reads and renews its stored session, updates the user, and signs out', async () => {
  const env = await createTestEnv();
  const password = 'test-client-hash';
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(password) });
  await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash);
  const origin = 'https://vault.example.test';
  const signedIn = await authedFetch(env, {
    method: 'POST',
    path: '/api/auth/sign-in/email',
    body: { email: user.email, password },
    headers: { Origin: origin },
  });
  assert.equal(signedIn.status, 200);
  const login = (await signedIn.json()) as { token: string; user: { id: string } };
  assert.equal(login.user.id, user.id);
  const nativeBearer = { Authorization: `Bearer ${login.token}` };
  assert.equal((await authedFetch(env, { path: '/api/sync', headers: nativeBearer })).status, 401);
  const nativeRefresh = await authedFetch(env, {
    method: 'POST',
    path: '/identity/connect/token',
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: login.token, client_id: 'web' }),
  });
  assert.equal(nativeRefresh.status, 400);
  assert.equal(((await nativeRefresh.json()) as { access_token?: string }).access_token, undefined);
  const cookie = signedIn.headers
    .getSetCookie()
    .find((value) => value.includes('better-auth.session_token='))
    ?.split(';')[0];
  assert.ok(cookie);
  const headers = { Cookie: cookie, Origin: origin };
  const stored = await getOrm(env.DB)
    .select({
      expiresAt: unmapped<number>(sessionTable.expiresAt),
      createdAt: unmapped<number>(sessionTable.createdAt),
      updatedAt: unmapped<number>(sessionTable.updatedAt),
    })
    .from(sessionTable)
    .where(eq(sessionTable.token, login.token))
    .get();
  assert.ok(stored);
  assert.ok(Object.values(stored).every((value) => typeof value === 'number' && value > 0));
  const readSession = () => authedFetch(env, { path: '/api/auth/get-session', headers });
  const session = await readSession();
  assert.equal(session.status, 200);
  const body = (await session.json()) as { session: { expiresAt: string }; user: { createdAt: string } };
  assert.equal(body.session.expiresAt, new Date(stored.expiresAt).toISOString());
  assert.equal(body.user.createdAt, user.createdAt);

  const oldExpiry = Date.now() + 60_000;
  await getOrm(env.DB).update(sessionTable).set({ expiresAt: oldExpiry }).where(eq(sessionTable.token, login.token));
  const renewed = await readSession();
  assert.equal(renewed.status, 200);
  const renewedBody = (await renewed.json()) as { session: { expiresAt: string } };
  const refreshed = await getOrm(env.DB)
    .select({
      expiresAt: unmapped<number>(sessionTable.expiresAt),
      updatedAt: unmapped<number>(sessionTable.updatedAt),
    })
    .from(sessionTable)
    .where(eq(sessionTable.token, login.token))
    .get();
  assert.ok(refreshed && refreshed.expiresAt > oldExpiry);
  assert.equal(renewedBody.session.expiresAt, new Date(refreshed.expiresAt).toISOString());
  assert.equal(typeof refreshed.updatedAt, 'number');

  const updated = await authedFetch(env, {
    method: 'POST',
    path: '/api/auth/update-user',
    headers,
    body: { name: 'Updated user' },
  });
  assert.equal(updated.status, 200);
  const savedUser = await getOrm(env.DB)
    .select({ name: users.name, updatedAt: unmapped<string>(users.updatedAt) })
    .from(users)
    .where(eq(users.id, user.id))
    .get();
  assert.equal(savedUser?.name, 'Updated user');
  assert.equal(savedUser!.updatedAt, new Date(savedUser!.updatedAt).toISOString());

  assert.equal((await authedFetch(env, { method: 'POST', path: '/api/auth/sign-out', headers, body: {} })).status, 200);
  assert.equal(await getOrm(env.DB).$count(sessionTable, eq(sessionTable.token, login.token)), 0);
  assert.equal(await (await readSession()).json(), null);
});

test('Better Auth date writes and comparisons preserve numeric credential and verification timestamps', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const { adapter } = await createAuth(env, new Request('https://vault.example.test')).$context;
  const now = new Date();
  const expires = new Date(now.getTime() + 60_000);
  const credential = await adapter.create<
    Record<string, unknown>,
    { id: string; createdAt: Date; accessTokenExpiresAt: Date }
  >({
    model: 'account',
    data: {
      accountId: user.id,
      providerId: 'test-provider',
      userId: user.id,
      createdAt: now,
      updatedAt: now,
      accessTokenExpiresAt: expires,
      refreshTokenExpiresAt: expires,
    },
  });
  assert.equal(credential.createdAt.toISOString(), now.toISOString());
  assert.equal(credential.accessTokenExpiresAt.toISOString(), expires.toISOString());
  const account = await getOrm(env.DB)
    .select({
      createdAt: unmapped(accountTable.createdAt),
      updatedAt: unmapped(accountTable.updatedAt),
      accessTokenExpiresAt: unmapped(accountTable.accessTokenExpiresAt),
      refreshTokenExpiresAt: unmapped(accountTable.refreshTokenExpiresAt),
    })
    .from(accountTable)
    .where(eq(accountTable.id, credential.id))
    .get();
  assert.deepEqual(account, {
    createdAt: now.getTime(),
    updatedAt: now.getTime(),
    accessTokenExpiresAt: expires.getTime(),
    refreshTokenExpiresAt: expires.getTime(),
  });
  const verification = await adapter.create<Record<string, unknown>, { id: string; expiresAt: Date }>({
    model: 'verification',
    data: {
      identifier: 'test-date-conversion',
      value: 'test-value',
      expiresAt: expires,
      createdAt: now,
      updatedAt: now,
    },
  });
  assert.equal(verification.expiresAt.toISOString(), expires.toISOString());
  const stored = await getOrm(env.DB)
    .select({
      expiresAt: unmapped(verificationTable.expiresAt),
      createdAt: unmapped(verificationTable.createdAt),
      updatedAt: unmapped(verificationTable.updatedAt),
    })
    .from(verificationTable)
    .where(eq(verificationTable.id, verification.id))
    .get();
  assert.deepEqual(stored, { expiresAt: expires.getTime(), createdAt: now.getTime(), updatedAt: now.getTime() });
  assert.equal(
    await adapter.count({ model: 'verification', where: [{ field: 'expiresAt', operator: 'gt', value: now }] }),
    1,
  );
  assert.equal(
    await adapter.deleteMany({
      model: 'verification',
      where: [{ field: 'expiresAt', operator: 'lt', value: new Date(expires.getTime() + 1) }],
    }),
    1,
  );
});
