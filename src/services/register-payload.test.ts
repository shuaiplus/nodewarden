import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RegisterSchema } from './register-payload';

test('parses the official web RegisterFinish payload', () => {
  const parsed = RegisterSchema.parse({
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
  assert.equal(parsed.email, 'owner@example.com');
  assert.equal(parsed.masterPasswordHash, 'hash');
  assert.equal(parsed.kdf, 0);
  assert.equal(parsed.kdfIterations, 600000);
  assert.equal(parsed.emailVerificationToken, 'token');
  assert.equal(parsed.publicKey, 'pub');
});

test('parses the NodeWarden local webapp register payload', () => {
  const parsed = RegisterSchema.parse({
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
  assert.equal(parsed.email, 'local@example.com');
  assert.equal(parsed.inviteCode, '');
});

test('reports the first failing registration check', () => {
  const valid = { email: 'a@example.com', masterPasswordHash: 'hash', key: 'key', publicKey: 'pub', encryptedPrivateKey: 'private' };
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ ...valid, email: 'abc', key: '' }, 'Email, masterPasswordHash, and key are required'],
    [{ ...valid, email: 'abc', publicKey: '' }, 'Invalid email address'],
    [{ ...valid, publicKey: 7, kdf: 2 }, 'Private key and public key are required'],
    [{ ...valid, kdf: 2 }, 'KDF type must be PBKDF2-SHA256 or Argon2id'],
    [{ ...valid, kdfIterations: 99_999 }, 'PBKDF2 iterations must be at least 100000'],
    [{ ...valid, masterPasswordUnlock: { kdf: { kdfType: 1, iterations: 3, memory: 15, parallelism: 4 } } }, 'Argon2id memory must be at least 16 MiB'],
    [{ ...valid, masterPasswordHint: 'x'.repeat(121) }, 'masterPasswordHint must be 120 characters or fewer'],
  ];
  for (const [body, message] of cases) assert.equal(RegisterSchema.safeParse(body).error?.issues[0].message, message);
  assert.equal(RegisterSchema.parse({ ...valid, kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4, masterPasswordHint: '  ' }).masterPasswordHint, null);
});
