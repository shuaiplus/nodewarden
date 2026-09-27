import assert from 'node:assert/strict';
import test from 'node:test';
import { LIMITS } from '../config/limits';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const VAULT_ORIGIN = 'https://web.example.test';
const corsHeaders = (response: Response) =>
  Object.fromEntries([...response.headers].filter(([name]) => name.startsWith('access-control-') || name === 'vary'));

test('configured vault origins read every response, errors included, with credentials', async () => {
  const env = await createTestEnv({ WEB_VAULT_ORIGINS: VAULT_ORIGIN });
  const user = await seedUser(env);
  for (const response of [
    await authedFetch(env, { path: '/api/sync', userId: user.id, headers: { Origin: VAULT_ORIGIN } }),
    await authedFetch(env, { path: '/api/sync', headers: { Origin: VAULT_ORIGIN } }),
  ]) {
    assert.deepEqual(corsHeaders(response), {
      'access-control-allow-credentials': 'true',
      'access-control-allow-origin': VAULT_ORIGIN,
      'access-control-expose-headers': '*',
      vary: 'Origin',
    });
  }
  const preflight = await authedFetch(env, {
    method: 'OPTIONS',
    path: '/api/sync',
    headers: { Origin: VAULT_ORIGIN, 'Access-Control-Request-Headers': 'authorization, bitwarden-client-name' },
  });
  assert.equal(preflight.status, 204);
  assert.deepEqual(corsHeaders(preflight), {
    'access-control-allow-credentials': 'true',
    'access-control-allow-headers': 'authorization,bitwarden-client-name',
    'access-control-allow-methods': 'GET,POST,PUT,DELETE,PATCH,OPTIONS',
    'access-control-allow-origin': VAULT_ORIGIN,
    'access-control-expose-headers': '*',
    'access-control-max-age': String(LIMITS.cors.preflightMaxAgeSeconds),
    vary: 'Origin, Access-Control-Request-Headers',
  });
});

test('other origins get a wildcard only on public paths and never credentials', async () => {
  const env = await createTestEnv();
  const origin = { Origin: 'https://elsewhere.example' };
  for (const headers of [origin, {}]) {
    const config = await authedFetch(env, { path: '/api/config', headers });
    assert.equal(config.headers.get('Access-Control-Allow-Origin'), '*');
    assert.equal(config.headers.get('Access-Control-Allow-Credentials'), null);
    assert.equal(config.headers.get('Vary'), 'Origin');
  }
  const preflight = await authedFetch(env, { method: 'OPTIONS', path: '/api/sync', headers: origin });
  assert.equal(preflight.status, 204);
  assert.deepEqual(corsHeaders(preflight), {});
  assert.deepEqual(corsHeaders(await authedFetch(env, { path: '/api/sync', headers: origin })), {});
});
