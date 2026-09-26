import assert from 'node:assert/strict';
import test from 'node:test';
import { waitUntil, drainWaitUntil } from './support/cloudflare-workers';

test('drainWaitUntil includes nested work and handles rejected tasks', async (t) => {
  const error = t.mock.method(console, 'error', () => {});
  let done = false;
  waitUntil(Promise.resolve().then(() => {
    waitUntil(Promise.resolve().then(() => { done = true; }));
    throw new Error('expected');
  }));
  await drainWaitUntil();
  assert.equal(done, true);
  assert.equal(error.mock.callCount(), 1);
});
