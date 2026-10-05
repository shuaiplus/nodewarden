import assert from 'node:assert/strict';
import test from 'node:test';

import { isTotpEnabled, isValidTotpSecret } from '../src/utils/totp';

// Fixtures are low-entropy Base32 alphabet runs on purpose: they decode like real keys, but secret
// scanners can tell them apart from leaked credentials.
const VALID_KEY = 'ABCDEFGHIJKLMNOP';
const LONGER_KEY = 'QRSTUVWXYZ234567QRSTUVWXYZ234567';

test('accepts a valid RFC 4648 Base32 secret', () => {
  assert.equal(isValidTotpSecret(VALID_KEY), true);
  assert.equal(isValidTotpSecret(LONGER_KEY), true);
});

test('rejects characters outside the Base32 alphabet', () => {
  assert.equal(isValidTotpSecret(`${VALID_KEY}0`), false);
  assert.equal(isValidTotpSecret(`${VALID_KEY}1`), false);
  assert.equal(isValidTotpSecret(`${VALID_KEY}8`), false);
  assert.equal(isValidTotpSecret(`${VALID_KEY}!`), false);
});

test('rejects empty and null-ish secrets', () => {
  assert.equal(isValidTotpSecret(''), false);
  assert.equal(isValidTotpSecret(null), false);
  assert.equal(isValidTotpSecret(undefined), false);
});

test('tolerates lowercase, whitespace, dashes and padding like the server normalizer', () => {
  assert.equal(isValidTotpSecret(VALID_KEY.toLowerCase()), true);
  assert.equal(isValidTotpSecret('ABCD EFGH IJKL MNOP'), true);
  assert.equal(isValidTotpSecret('ABCD-EFGH-IJKL-MNOP'), true);
  assert.equal(isValidTotpSecret(`${VALID_KEY}===`), true);
});

test('distinguishes a merely non-empty string from a decodable secret', () => {
  // isTotpEnabled only checks "non-empty after normalization"; a hand-edited key can be non-empty
  // yet undecodable, which isValidTotpSecret catches so the server rejects it before commit.
  assert.equal(isTotpEnabled('!!!!'), true);
  assert.equal(isValidTotpSecret('!!!!'), false);
});
