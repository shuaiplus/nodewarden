import assert from 'node:assert/strict';
import { test } from 'node:test';

import { fromAccessId } from './sends-shared';

test('fromAccessId reads 16 base64url bytes as a GUID in byte order and rejects anything else', () => {
  const bytes = Uint8Array.fromHex('00112233445566778899aabbccddeeff');
  assert.equal(fromAccessId(bytes.toBase64({ alphabet: 'base64url', omitPadding: true })), '00112233-4455-6677-8899-aabbccddeeff');
  assert.equal(fromAccessId(bytes.subarray(0, 15).toBase64({ alphabet: 'base64url', omitPadding: true })), null);
  assert.equal(fromAccessId('not base64url!'), null);
});
