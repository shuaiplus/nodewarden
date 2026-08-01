import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import type { Env } from '../src/types';
import { getConfiguredWebAuthnAllowedOrigins } from '../src/utils/origins';
import { applyCors, handleCors } from '../src/utils/response';

const env = {} as Env;

test('only the iframe connector drops anti-framing headers', () => {
  const connectorRequest = new Request('https://vault.example.test/webauthn-connector.html');
  const connector = applyCors(connectorRequest, new Response('<!doctype html>'), env);
  assert.equal(connector.headers.get('X-Frame-Options'), null);
  assert.doesNotMatch(connector.headers.get('Content-Security-Policy') || '', /frame-ancestors/);
  assert.match(connector.headers.get('Content-Security-Policy') || '', /script-src 'self'/);

  for (const path of ['/', '/webauthn-fallback-connector.html', '/webauthn-mobile-connector.html']) {
    const request = new Request(`https://vault.example.test${path}`);
    const response = applyCors(request, new Response('<!doctype html>'), env);
    assert.equal(response.headers.get('X-Frame-Options'), 'DENY');
    assert.match(response.headers.get('Content-Security-Policy') || '', /frame-ancestors 'none'/);
  }
});

test('official Bitwarden desktop origin receives credentialed CORS', () => {
  assert.ok(getConfiguredWebAuthnAllowedOrigins(env).includes('bw-desktop-file://bundle'));
  const preflight = handleCors(new Request('https://vault.example.test/api/sync', {
    method: 'OPTIONS',
    headers: {
      Origin: 'bw-desktop-file://bundle',
      'Access-Control-Request-Headers': 'authorization, content-type',
    },
  }), env);
  assert.equal(preflight.headers.get('Access-Control-Allow-Origin'), 'bw-desktop-file://bundle');
  assert.equal(preflight.headers.get('Access-Control-Allow-Credentials'), 'true');
});

test('Worker assets preserve exact official connector .html paths', async () => {
  for (const configUrl of [
    new URL('../wrangler.toml', import.meta.url),
    new URL('../wrangler.kv.toml', import.meta.url),
  ]) {
    const config = await readFile(configUrl, 'utf8');
    const assetsSection = config.match(/\[assets\]([\s\S]*?)(?=\n\[|$)/)?.[1] || '';
    assert.match(assetsSection, /^\s*html_handling\s*=\s*"none"\s*$/m);
  }
});
