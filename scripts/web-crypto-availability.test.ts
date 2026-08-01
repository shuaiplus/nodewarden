import assert from 'node:assert/strict';
import test from 'node:test';

import { registerAccount } from '../webapp/src/lib/api/auth';
import {
  requireWebCrypto,
  WebCryptoUnavailableError,
} from '../webapp/src/lib/crypto';

const supportedCrypto = {
  subtle: {
    importKey: () => Promise.reject(new Error('not used by capability checks')),
  },
  getRandomValues: <T>(array: T): T => array,
} as unknown as Crypto;

function restoreGlobalProperty(name: string, descriptor: PropertyDescriptor | undefined): void {
  if (descriptor) {
    Object.defineProperty(globalThis, name, descriptor);
    return;
  }
  delete (globalThis as unknown as Record<string, unknown>)[name];
}

test('Web Crypto guard rejects insecure browser contexts', () => {
  assert.throws(
    () => requireWebCrypto({ crypto: supportedCrypto, isSecureContext: false }),
    WebCryptoUnavailableError
  );
});

test('Web Crypto guard rejects secure contexts without SubtleCrypto', () => {
  const cryptoWithoutSubtle = {
    getRandomValues: <T>(array: T): T => array,
  } as unknown as Crypto;

  assert.throws(
    () => requireWebCrypto({ crypto: cryptoWithoutSubtle, isSecureContext: true }),
    WebCryptoUnavailableError
  );
});

test('Web Crypto guard accepts a secure supported browser', () => {
  assert.equal(
    requireWebCrypto({ crypto: supportedCrypto, isSecureContext: true }),
    supportedCrypto
  );
});

test('registration returns an actionable error without contacting the backend', async () => {
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const secureContextDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'isSecureContext');
  const fetchDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'fetch');
  let fetchCalled = false;

  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
  Object.defineProperty(globalThis, 'isSecureContext', { value: false, configurable: true });
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: async () => {
      fetchCalled = true;
      return new Response(null, { status: 500 });
    },
  });

  try {
    const result = await registerAccount({
      email: 'first@example.test',
      name: 'First Admin',
      password: 'correct horse battery staple',
      fallbackIterations: 600_000,
    });

    assert.deepEqual(result, {
      ok: false,
      message: 'Secure browser cryptography is unavailable. Open NodeWarden over HTTPS in a supported browser.',
    });
    assert.equal(fetchCalled, false);
  } finally {
    restoreGlobalProperty('crypto', cryptoDescriptor);
    restoreGlobalProperty('isSecureContext', secureContextDescriptor);
    restoreGlobalProperty('fetch', fetchDescriptor);
  }
});
