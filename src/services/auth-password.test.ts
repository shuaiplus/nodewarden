import assert from 'node:assert/strict';
import { test } from 'node:test';

import { hashPassword, verifyBetterAuthPassword, verifyPassword } from './auth-password';

test('hashPassword produces a random-salt $s2$ digest that verifies', async () => {
  const hash = await hashPassword('client-hash');
  assert.match(hash, /^\$s2\$100000\$/);
  assert.equal(await verifyPassword('client-hash', hash), true);
  assert.equal(await verifyPassword('wrong', hash), false);
  assert.equal(await verifyBetterAuthPassword({ password: 'client-hash', hash }), true);
});

test('legacy $s$ email-salt hashes still verify when email is supplied', async () => {
  const email = 'user@example.com';
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode('client-hash'), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new TextEncoder().encode(email), iterations: 100_000 },
    keyMaterial,
    256
  );
  const bytes = new Uint8Array(bits);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  const legacy = `$s$${btoa(binary)}`;
  assert.equal(await verifyPassword('client-hash', legacy, email), true);
  assert.equal(await verifyPassword('client-hash', legacy), false);
});
