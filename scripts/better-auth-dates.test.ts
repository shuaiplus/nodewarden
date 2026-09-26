import assert from 'node:assert/strict';
import test from 'node:test';

import { createAuth } from '../src/auth';
import { upsertCredentialAccount } from '../src/services/auth-accounts';
import { hashPassword } from '../src/services/auth-password';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('Better Auth signs in, reads and renews its stored session, updates the user, and signs out', async () => {
  const env = await createTestEnv();
  const password = 'test-client-hash';
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(password) });
  await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash);
  const origin = 'https://vault.example.test';
  const signedIn = await authedFetch(env, {
    method: 'POST', path: '/api/auth/sign-in/email', body: { email: user.email, password }, headers: { Origin: origin },
  });
  assert.equal(signedIn.status, 200);
  const login = await signedIn.json() as { token: string; user: { id: string } };
  assert.equal(login.user.id, user.id);
  const cookie = signedIn.headers.getSetCookie().find(value => value.includes('better-auth.session_token='))?.split(';')[0];
  assert.ok(cookie);
  const headers = { Cookie: cookie, Origin: origin };
  const stored = await env.DB.prepare('SELECT expires_at, created_at, updated_at FROM session WHERE token=?').bind(login.token)
    .first<{ expires_at: number; created_at: number; updated_at: number }>();
  assert.ok(stored);
  assert.ok(Object.values(stored).every(value => typeof value === 'number' && value > 0));
  const readSession = () => authedFetch(env, { path: '/api/auth/get-session', headers });
  const session = await readSession();
  assert.equal(session.status, 200);
  const body = await session.json() as { session: { expiresAt: string }; user: { createdAt: string } };
  assert.equal(body.session.expiresAt, new Date(stored.expires_at).toISOString());
  assert.equal(body.user.createdAt, user.createdAt);

  const oldExpiry = Date.now() + 60_000;
  await env.DB.prepare('UPDATE session SET expires_at=? WHERE token=?').bind(oldExpiry, login.token).run();
  const renewed = await readSession();
  assert.equal(renewed.status, 200);
  const renewedBody = await renewed.json() as { session: { expiresAt: string } };
  const refreshed = await env.DB.prepare('SELECT expires_at, updated_at FROM session WHERE token=?').bind(login.token)
    .first<{ expires_at: number; updated_at: number }>();
  assert.ok(refreshed && refreshed.expires_at > oldExpiry);
  assert.equal(renewedBody.session.expiresAt, new Date(refreshed.expires_at).toISOString());
  assert.equal(typeof refreshed.updated_at, 'number');

  const updated = await authedFetch(env, { method: 'POST', path: '/api/auth/update-user', headers, body: { name: 'Updated user' } });
  assert.equal(updated.status, 200);
  const savedUser = await env.DB.prepare('SELECT name, updated_at FROM users WHERE id=?').bind(user.id).first<{ name: string; updated_at: string }>();
  assert.equal(savedUser?.name, 'Updated user');
  assert.equal(savedUser!.updated_at, new Date(savedUser!.updated_at).toISOString());

  assert.equal((await authedFetch(env, { method: 'POST', path: '/api/auth/sign-out', headers, body: {} })).status, 200);
  assert.equal(await env.DB.prepare('SELECT id FROM session WHERE token=?').bind(login.token).first(), null);
  assert.equal(await (await readSession()).json(), null);
});

test('Better Auth date writes and comparisons preserve numeric credential and verification timestamps', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const { adapter } = await createAuth(env, new Request('https://vault.example.test')).$context;
  const now = new Date();
  const expires = new Date(now.getTime() + 60_000);
  const credential = await adapter.create<{ id: string; createdAt: Date; accessTokenExpiresAt: Date }>({
    model: 'account',
    data: { accountId: user.id, providerId: 'test-provider', userId: user.id, createdAt: now, updatedAt: now, accessTokenExpiresAt: expires, refreshTokenExpiresAt: expires },
  });
  assert.equal(credential.createdAt.toISOString(), now.toISOString());
  assert.equal(credential.accessTokenExpiresAt.toISOString(), expires.toISOString());
  const account = await env.DB.prepare('SELECT created_at, updated_at, access_token_expires_at, refresh_token_expires_at FROM account WHERE id=?').bind(credential.id).first();
  assert.deepEqual(account, { created_at: now.getTime(), updated_at: now.getTime(), access_token_expires_at: expires.getTime(), refresh_token_expires_at: expires.getTime() });
  const verification = await adapter.create<{ id: string; expiresAt: Date }>({
    model: 'verification', data: { identifier: 'test-date-conversion', value: 'test-value', expiresAt: expires, createdAt: now, updatedAt: now },
  });
  assert.equal(verification.expiresAt.toISOString(), expires.toISOString());
  const stored = await env.DB.prepare('SELECT expires_at, created_at, updated_at FROM verification WHERE id=?').bind(verification.id).first();
  assert.deepEqual(stored, { expires_at: expires.getTime(), created_at: now.getTime(), updated_at: now.getTime() });
  assert.equal(await adapter.count({ model: 'verification', where: [{ field: 'expiresAt', operator: 'gt', value: now }] }), 1);
  assert.equal(await adapter.deleteMany({ model: 'verification', where: [{ field: 'expiresAt', operator: 'lt', value: new Date(expires.getTime() + 1) }] }), 1);
});
