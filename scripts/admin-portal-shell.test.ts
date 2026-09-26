import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { authedFetch, createTestEnv, portalFetch } from './support/env';
import { isAdminPortalPath } from '../src/web-vault-visibility';
import { PORTAL_HEADERS } from '../src/views/admin-portal';

test('portal remains on the Worker origin and independent of vault/JWT configuration', async (t) => {
  t.mock.method(console, 'error', () => {});
  const env = await createTestEnv();
  assert.equal((await portalFetch(env, { path: '/admin' })).status, 404);
  env.ADMIN_EMAILS = 'bad-secret-config';
  const invalid = await portalFetch(env, { path: '/admin' });
  assert.equal(invalid.status, 500);
  assert.doesNotMatch(await invalid.text(), /bad-secret-config/);
  assert.equal((await authedFetch(env, { path: '/api/config' })).status, 200);
  env.ADMIN_EMAILS = 'admin@x.io';
  env.JWT_SECRET = '';
  env.HIDE_WEB_VAULT = '1';
  const login = await portalFetch(env, { path: '/admin/login' });
  assert.equal(login.status, 200);
  for (const [key, value] of Object.entries(PORTAL_HEADERS)) assert.equal(login.headers.get(key), value);
  assert.equal(login.headers.get('X-Frame-Options'), 'DENY');
  assert.equal(login.headers.get('X-Content-Type-Options'), 'nosniff');
  const home = await portalFetch(env, { path: '/admin' });
  assert.equal(home.headers.get('Location'), '/admin/login?returnUrl=%2Fadmin');
  for (const method of ['GET', 'OPTIONS']) {
    const response = await portalFetch(env, { method, path: '/admin/login', headers: { Origin: 'https://web.example.test' } });
    assert.ok(![...response.headers.keys()].some((key) => key.startsWith('access-control-')));
  }
  for (const path of ['/admin-panel', '/administrator', '/ADMIN']) assert.equal(isAdminPortalPath(path), false);
  assert.doesNotMatch(readFileSync('official-web/functions/_middleware.js', 'utf8'), /['"]\/admin['"]/);
});

test('portal rejects fetch and cross-origin form requests', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: 'admin@x.io' });
  assert.equal((await portalFetch(env, { path: '/admin/login', headers: { 'Sec-Fetch-Mode': 'cors' } })).status, 403);
  for (const headers of [{ Origin: 'null' }, { Origin: 'https://evil.io' }, {}]) assert.equal((await authedFetch(env, { path: '/admin/login', method: 'POST', headers })).status, 403);
  assert.equal((await authedFetch(env, { path: '/admin/login', method: 'POST', headers: { 'Sec-Fetch-Site': 'same-origin' } })).status, 405);
});
