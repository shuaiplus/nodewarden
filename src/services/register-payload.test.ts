import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseRegisterPayload } from './register-payload';

test('parses the official web RegisterFinish payload', () => {
  const parsed = parseRegisterPayload({
    email: 'Owner@Example.com',
    name: 'Owner',
    masterPasswordHint: '  ',
    userAsymmetricKeys: {
      publicKey: 'pub',
      encryptedPrivateKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
    masterPasswordAuthentication: {
      salt: 'owner@example.com',
      kdf: { kdfType: 0, iterations: 600000 },
      masterPasswordAuthenticationHash: 'hash',
    },
    masterPasswordUnlock: {
      salt: 'owner@example.com',
      kdf: { kdfType: 0, iterations: 600000 },
      masterKeyWrappedUserKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
    emailVerificationToken: 'token',
  });

  assert.equal(typeof parsed, 'object');
  if (typeof parsed === 'string') throw new Error(parsed);
  assert.equal(parsed.email, 'owner@example.com');
  assert.equal(parsed.masterPasswordHash, 'hash');
  assert.equal(parsed.kdf, 0);
  assert.equal(parsed.kdfIterations, 600000);
  assert.equal(parsed.emailVerificationToken, 'token');
  assert.equal(parsed.publicKey, 'pub');
});

test('parses the NodeWarden local webapp register payload', () => {
  const parsed = parseRegisterPayload({
    email: 'local@example.com',
    masterPasswordHash: 'hash',
    key: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    keys: {
      publicKey: 'pub',
      encryptedPrivateKey: '2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
    },
    kdf: 0,
    kdfIterations: 600000,
  });
  assert.equal(typeof parsed, 'object');
  if (typeof parsed === 'string') throw new Error(parsed);
  assert.equal(parsed.email, 'local@example.com');
  assert.equal(parsed.inviteCode, '');
});
