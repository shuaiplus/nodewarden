import assert from 'node:assert/strict';
import test from 'node:test';
import { onRequest } from '../../official-web/functions/_middleware.js';
import { isBackendRequestPath } from '../web-vault-visibility';

test('Pages forwards authenticated event collection to the Worker instead of SPA assets', async (t) => {
  const requests: Request[] = [];
  t.mock.method(globalThis, 'fetch', async (request: Request) => {
    requests.push(request);
    return new Response('collected');
  });
  let fallback = false;
  const response = await onRequest({
    request: new Request('https://vault.example.test/events/collect', {
      method: 'POST', headers: { Authorization: 'Bearer synthetic', 'Device-Type': '9' },
    }),
    env: { WORKER_ORIGIN: 'https://worker.example.test' },
    next: () => { fallback = true; return new Response('assets'); },
  });
  assert.equal(await response.text(), 'collected');
  assert.equal(fallback, false);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, 'https://worker.example.test/events/collect');
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].headers.get('Authorization'), 'Bearer synthetic');
  assert.equal(requests[0].headers.get('Device-Type'), '9');
  assert.equal(requests[0].headers.get('X-Forwarded-Host'), 'vault.example.test');
  assert.equal(isBackendRequestPath('/events/collect'), true);
  assert.equal(isBackendRequestPath('/events'), true);
  assert.equal(isBackendRequestPath('/events-preview'), false);
});
