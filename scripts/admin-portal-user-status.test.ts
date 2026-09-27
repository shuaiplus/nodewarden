import assert from 'node:assert/strict';
import test from 'node:test';

import { AuthService } from '../src/services/auth';
import { createAuth } from '../src/auth';
import { upsertCredentialAccount } from '../src/services/auth-accounts';
import { hashPassword } from '../src/services/auth-password';
import { setUserStatus } from '../src/services/account-deletion';
import { BACKUP_SETTINGS_CONFIG_KEY, getDefaultBackupSettings, saveBackupSettings } from '../src/services/backup-config';
import { parseBackupSettingsEnvelope } from '../src/services/backup-settings-crypto';
import { authedFetch, createTestEnv, drainWaitUntil, memoryKv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import * as sessionRepo from '../src/services/storage-session-repo';
import * as configRepo from '../src/services/storage-config-repo';
import * as deviceRepo from '../src/services/storage-device-repo';
import * as userRepo from '../src/services/storage-user-repo';

const ADMIN = 'portal@x.io';
const PASSWORD = 'test-client-hash';
const audit = { action: 'admin.user.status', category: 'security' as const, level: 'security' as const };

test('portal disable/enable rotates the stamp, invalidates existing tokens, and cannot revive them on enable', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  await sessionRepo.saveRefreshToken(env.DB, 'old-session', user.id);
  await deviceRepo.upsertDevice(env.DB, user.id, 'device', 'Existing device', 2);
  const token = await new AuthService(env).generateAccessToken(user);
  const path = `/admin/users/${user.id}/disable`;
  const view = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: auth.cookie });
  assert.match(await view.text(), /Disable user/);
  assert.equal((await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: {} })).status, 403);
  assert.equal((await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf }, headers: { Origin: 'https://foreign.test' } })).status, 403);
  // Reversible status changes need CSRF but no fresh step-up.
  await env.DB.prepare("UPDATE verification SET value=json_set(value,'$.authTime',0) WHERE id LIKE 'admin-session:%'").run();
  const disabled = await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf } });
  assert.equal(disabled.status, 303);
  assert.match(disabled.headers.get('Location')!, /m=disabled/);
  const updated = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(updated.status, 'banned');
  assert.notEqual(updated.securityStamp, user.securityStamp);
  assert.ok(await deviceRepo.getDevice(env.DB, user.id, 'device'));
  const login = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password: PASSWORD } });
  assert.equal(login.status, 400);
  assert.match(await login.text(), /Account is disabled/);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${token}` } })).status, 401);
  assert.equal((await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'refresh_token', refresh_token: 'old-session' } })).status, 400);
  const repeated = await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf } });
  assert.equal(repeated.status, 303);
  const events = await env.DB.prepare("SELECT actor_user_id,metadata FROM audit_logs WHERE action='admin.portal.user.disable'").all<{ actor_user_id: string | null; metadata: string }>();
  assert.equal(events.results.length, 1);
  assert.equal(events.results[0].actor_user_id, null);
  assert.equal(JSON.parse(events.results[0].metadata).adminEmail, ADMIN);
  const enabled = await portalFetch(env, { path: `/admin/users/${user.id}/enable`, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf } });
  assert.equal(enabled.status, 303);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.securityStamp, updated.securityStamp);
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${token}` } })).status, 401);
  assert.equal((await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'refresh_token', refresh_token: 'old-session' } })).status, 400);
  await drainWaitUntil();
});

test('both admin surfaces refuse the last active vault administrator; stale user saves cannot undo a ban', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: ADMIN });
  const auth = await signInToAdminPortal(env, ADMIN);
  const admin = await seedUser(env, { role: 'admin' });
  const portal = await portalFetch(env, { path: `/admin/users/${admin.id}/disable`, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf } });
  assert.equal(portal.status, 400);
  assert.match(await portal.text(), /last active instance administrator/);
  const legacy = await authedFetch(env, { method: 'PUT', path: `/api/admin/users/${admin.id}/status`, userId: admin.id, body: { status: 'banned', masterPasswordHash: admin.masterPasswordHash } });
  assert.equal(legacy.status, 400);
  const user = await seedUser(env);
  const oldToken = await new AuthService(env).generateAccessToken(user);
  assert.deepEqual(await setUserStatus(env, user.id, 'banned', audit), { kind: 'updated' });
  await userRepo.saveUser(env.DB, { ...user, name: 'Stale update' });
  const saved = (await userRepo.getUserById(env.DB, user.id))!;
  assert.equal(saved.status, 'banned');
  assert.notEqual(saved.securityStamp, user.securityStamp);
  assert.deepEqual(await setUserStatus(env, user.id, 'active', audit), { kind: 'updated' });
  assert.equal((await authedFetch(env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldToken}` } })).status, 401);
  assert.deepEqual(await setUserStatus(env, 'missing', 'active', audit), { kind: 'not-found' });
  await drainWaitUntil();
});

test('disabling an administrator re-wraps backup settings without their key, and enabling restores it', async () => {
  const env = await createTestEnv();
  const { publicKey } = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-1' }, true, ['encrypt', 'decrypt']);
  const spki = Buffer.from(await crypto.subtle.exportKey('spki', publicKey)).toString('base64');
  const admin = await seedUser(env, { role: 'admin', publicKey: spki });
  const target = await seedUser(env, { role: 'admin', publicKey: spki });
  await saveBackupSettings(env.DB, env, getDefaultBackupSettings());
  const wraps = async () => parseBackupSettingsEnvelope(await configRepo.getConfigValue(env.DB, BACKUP_SETTINGS_CONFIG_KEY))!.portable.wraps.map(wrap => wrap.userId).sort();
  assert.deepEqual(await wraps(), [admin.id, target.id].sort());
  assert.deepEqual(await setUserStatus(env, target.id, 'banned', audit), { kind: 'updated' });
  assert.deepEqual(await wraps(), [admin.id]);
  assert.deepEqual(await setUserStatus(env, target.id, 'active', audit), { kind: 'updated' });
  assert.deepEqual(await wraps(), [admin.id, target.id].sort());
  await drainWaitUntil();
});

test('Better Auth refuses new sessions while a user is disabled', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash);
  const signIn = () => authedFetch(env, { method: 'POST', path: '/api/auth/sign-in/email', body: { email: user.email, password: PASSWORD } });
  const beforeCreate = createAuth(env).options.databaseHooks!.session!.create!.before!;
  const candidate = { id: 'session', token: 'session-token', userId: user.id, expiresAt: new Date(Date.now() + 60000), createdAt: new Date(), updatedAt: new Date() };
  assert.deepEqual(await beforeCreate(candidate, null), { data: candidate });
  assert.equal((await signIn()).status, 200);
  assert.deepEqual(await setUserStatus(env, user.id, 'banned', audit), { kind: 'updated' });
  const rejected = await signIn();
  assert.equal(rejected.status, 401);
  assert.equal((await rejected.json() as { code: string }).code, 'FAILED_TO_CREATE_SESSION');
  assert.equal(await env.DB.prepare('SELECT COUNT(*) AS n FROM session WHERE user_id=?').bind(user.id).first('n'), 0);
  assert.deepEqual(await setUserStatus(env, user.id, 'active', audit), { kind: 'updated' });
  assert.deepEqual(await beforeCreate(candidate, null), { data: candidate });
  assert.equal((await signIn()).status, 200);
  await drainWaitUntil();
});

test('stale Better Auth KV sessions cannot survive disable and re-enable', async () => {
  const cache = memoryKv();
  const env = await createTestEnv({ CACHE_KV: cache.binding });
  const user = await seedUser(env);
  const token = 'cached-session-token';
  await env.DB.prepare('INSERT INTO session (id, token, user_id, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)')
    .bind('cached-session', token, user.id, Date.now() + 60000, Date.now(), Date.now()).run();
  await cache.binding.put(token, JSON.stringify({
    session: { id: 'cached-session', token, userId: user.id, expiresAt: new Date(Date.now() + 60000).toISOString(), createdAt: user.createdAt, updatedAt: user.updatedAt },
    user: { ...user, emailVerified: true },
  }));
  await cache.binding.put(`active-sessions-${user.id}`, JSON.stringify([{ token, expiresAt: Date.now() + 60000 }]));
  const activeSession = await authedFetch(env, { path: '/api/auth/get-session', headers: { Authorization: `Bearer ${token}` } });
  assert.equal(activeSession.status, 200);
  assert.equal((await activeSession.json() as { user: { id: string } }).user.id, user.id);
  const options = createAuth(env).options;
  assert.equal(options.secondaryStorage, undefined);
  const rateLimit = options.rateLimit!.customStorage!;
  const counter = { key: 'rate-limit-test', count: 2, lastRequest: Date.now() };
  await rateLimit.set(counter.key, counter);
  assert.deepEqual(await rateLimit.get(counter.key), counter);
  for (const next of ['banned', 'active'] as const) {
    assert.deepEqual(await setUserStatus(env, user.id, next, audit), { kind: 'updated' });
    assert.ok(await cache.binding.get(token));
    const session = await authedFetch(env, { path: '/api/auth/get-session', headers: { Authorization: `Bearer ${token}` } });
    assert.equal(session.status, 200);
    assert.equal(await session.json(), null);
  }
  await drainWaitUntil();
});
