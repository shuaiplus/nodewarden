import assert from 'node:assert/strict';
import { mock, test } from 'node:test';

import type { Env } from '../types';
import { createR2PresignedPutUrl } from './r2-presign';

const env = {
  R2_ACCOUNT_ID: 'account123',
  R2_ACCESS_KEY_ID: 'AKIDEXAMPLE',
  R2_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
  R2_BUCKET: 'vault-files',
} as Env;

// The signature was produced by the previous hand-rolled SigV4 signer at the same instant, so it pins the canonical request.
test('presigned R2 PUT URLs keep the path-style key encoding and host-only query signature', async () => {
  mock.timers.enable({ apis: ['Date'], now: Date.UTC(2026, 8, 27, 12, 34, 56) });
  try {
    const signed = new URL(await createR2PresignedPutUrl(env, 'cipher-1/attachment 1.bin', 900));
    assert.equal(signed.origin + signed.pathname, 'https://account123.r2.cloudflarestorage.com/vault-files/cipher-1/attachment%201.bin');
    assert.deepEqual(Object.fromEntries(signed.searchParams), {
      'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
      'X-Amz-Credential': 'AKIDEXAMPLE/20260927/auto/s3/aws4_request',
      'X-Amz-Date': '20260927T123456Z',
      'X-Amz-Expires': '900',
      'X-Amz-SignedHeaders': 'host',
      'X-Amz-Signature': 'b9e8a2c6acce14897c041b4ca5c21e3f4604629587c8d5b7573f79f2de63db09',
    });
  } finally {
    mock.timers.reset();
  }
});
