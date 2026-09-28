import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import test from 'node:test';

import './support/env';
import { BACKEND_EXACT_PATHS, BACKEND_PATH_PREFIXES } from '../../shared/backend-paths';
import { isBackendRequestPath } from '../web-vault-visibility';

const { app } = await import('../router');
// Each route pattern as a concrete sample path: a parameter becomes one segment, a trailing wildcard another.
const routePaths = [...new Set(app.routes.map((route) => route.path))]
  .filter((path) => path !== '/*' && path !== '*')
  .map((path) => path.replace(/\/:[^/]+\{[^}]*\}|\/:[^/]+/g, '/x').replace(/\/\*$/, '/x'));

test('every Worker route is a backend path, so Cloudflare runs the Worker for it', () => {
  assert.deepEqual(
    routePaths.filter((path) => !isBackendRequestPath(path)),
    [],
  );
  assert.equal(isBackendRequestPath('/events/collect'), true);
  assert.equal(isBackendRequestPath('/events-preview'), false);
});

test('both wrangler configs run the Worker first for exactly the backend paths, the portal and our own pages', () => {
  // Our pages in public/ need the Worker's security headers; only the WebAuthn iframe connector may be framed.
  const ownPages = readdirSync('public')
    .filter((file) => file.endsWith('.html'))
    .map((file) => `/${file}`);
  const expected = [
    ...BACKEND_PATH_PREFIXES.flatMap((prefix) => [prefix, `${prefix}/*`]),
    ...BACKEND_EXACT_PATHS,
    '/admin',
    '/admin/*',
    ...ownPages,
  ].sort();
  for (const file of ['wrangler.toml', 'wrangler.kv.toml']) {
    const patterns = readFileSync(file, 'utf8').match(/^run_worker_first\s*=\s*\[([\s\S]*?)\]/m)?.[1] ?? '';
    assert.deepEqual([...patterns.matchAll(/"([^"]+)"/g)].map(([, pattern]) => pattern).sort(), expected, file);
  }
});
