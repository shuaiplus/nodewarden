import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

test('generated service worker leaves administrator documents to the network', () => {
  const config = readFileSync(new URL('../webapp/vite.config.ts', import.meta.url), 'utf8');
  const template = config.match(/function buildServiceWorkerSource[\s\S]*?return (`[\s\S]*?`);\n}/)?.[1];
  assert.ok(template);
  const source = runInNewContext(template, { precacheUrls: [], version: 'test' });
  let onFetch;
  runInNewContext(source, {
    URL, Response, navigator: { onLine: false },
    self: { location: { origin: 'https://vault.io' }, addEventListener(name, callback) { if (name === 'fetch') onFetch = callback; } },
    caches: { async open() { return { async match() { return new Response('SPA'); } }; } },
  });
  for (const path of ['/admin', '/admin/login', '/admin/users/view/user']) {
    let intercepted = false;
    onFetch({ request: { method: 'GET', url: `https://vault.io${path}`, mode: 'navigate' }, respondWith() { intercepted = true; }, waitUntil() { intercepted = true; } });
    assert.equal(intercepted, false, path);
  }
  for (const path of ['/admin-panel', '/administrator']) {
    let intercepted = false;
    onFetch({ request: { method: 'GET', url: `https://vault.io${path}`, mode: 'navigate' }, respondWith() { intercepted = true; } });
    assert.equal(intercepted, true, path);
  }
});
