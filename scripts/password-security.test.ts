import assert from 'node:assert/strict';
import test from 'node:test';

import { inspectVaultPasswordSecurity } from '../webapp/src/lib/password-security';
import type { Cipher } from '../webapp/src/lib/types';

const twoFactorDirectory = {
  'github.com': { methods: ['totp', 'u2f'], documentation: 'https://example.com/2fa-docs' },
  'plain.example': {},
  'empty.example': { methods: [] },
};

const passkeyDirectory = {
  'github.com': { passwordless: 'allowed', mfa: 'allowed', documentation: 'https://example.com/passkey-docs' },
};

function stubFetch(input: unknown): Promise<Response> {
  const url = String(input);
  if (url.startsWith('https://api.pwnedpasswords.com/range/')) return Promise.resolve(new Response('', { status: 200 }));
  if (url === 'https://api.2fa.directory/v4/all.json') return Response.json(twoFactorDirectory);
  if (url === 'https://passkeys-api.2fa.directory/v1/all.json') return Response.json(passkeyDirectory);
  return Promise.reject(new Error(`Unexpected fetch: ${url}`));
}

function loginCipher(id: string, uri: string | null, password: string): Cipher {
  return {
    id,
    type: 1,
    name: id,
    login: { decPassword: password, decUsername: 'ada@example.org', ...(uri ? { uri } : {}) },
  } as unknown as Cipher;
}

test('2FA/passkey directory matching distinguishes supported, confirmed-missing, and unlisted sites', async () => {
  const ciphers = [
    loginCipher('cipher-github', 'https://github.com/login', 'Zq!9vT#2mKp$LwXz'),
    loginCipher('cipher-plain', 'https://plain.example', 'Bn@7wR%4jMz&QxYp'),
    loginCipher('cipher-empty-methods', 'https://empty.example', 'Df$5xY!8hNq@UbMe'),
    loginCipher('cipher-unlisted', 'https://notlisted.example', '1234567890'),
    loginCipher('cipher-no-uri', null, 'abcdefghij'),
  ];

  const report = await inspectVaultPasswordSecurity(ciphers, undefined, stubFetch);

  const byId = new Map(report.items.map((item) => [item.cipherId, item]));

  // Catalogued with methods: supported.
  assert.equal(byId.get('cipher-github')?.twoFactorSupported, true);
  assert.equal(byId.get('cipher-github')?.twoFactorDocumentation, 'https://example.com/2fa-docs');
  assert.equal(byId.get('cipher-github')?.passkeySupported, true);

  // Catalogued without methods: confirmed "no 2FA" — counted and badged.
  assert.equal(byId.get('cipher-plain')?.twoFactorSupported, false);
  assert.equal(byId.get('cipher-empty-methods')?.twoFactorSupported, false);

  // Not in the catalog / no URI: unknown, must not be reported as missing 2FA.
  assert.equal(byId.get('cipher-unlisted')?.twoFactorSupported, null);
  assert.equal(byId.get('cipher-unlisted')?.passkeySupported, null);
  assert.equal(byId.get('cipher-no-uri')?.twoFactorSupported, null);

  assert.equal(report.twoFactorMissingCount, 2);
  assert.equal(report.passkeyAvailableCount, 1);
  assert.equal(report.twoFactorUnavailable, false);
  assert.equal(report.passkeyUnavailable, false);
  assert.equal(report.eligibleCount, 5);
  assert.equal(report.checkedCount, 5);
});
