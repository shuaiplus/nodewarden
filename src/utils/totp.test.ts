import assert from 'node:assert/strict';
import test from 'node:test';
import { findMatchingTotpCounter, isTotpEnabled } from './totp';

// RFC 6238 appendix B SHA-1 vector: ASCII "12345678901234567890" at T=59s is step 1, code 287082.
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const RFC_TOKEN = '287082';

test('TOTP matches return the absolute step counter within one step of drift', async () => {
  assert.equal(await findMatchingTotpCounter(RFC_SECRET, RFC_TOKEN, 59_000), 1);
  assert.equal(await findMatchingTotpCounter(RFC_SECRET, ' 287 082 ', 89_000), 1);
  assert.equal(await findMatchingTotpCounter('gezd-gnbv gy3t qojq gezd gnbv gy3t qojq====', RFC_TOKEN, 30_000), 1);
  assert.equal(await findMatchingTotpCounter(RFC_SECRET, RFC_TOKEN, 119_000), null);
  assert.equal(await findMatchingTotpCounter(RFC_SECRET, '28708a', 59_000), null);
  assert.equal(await findMatchingTotpCounter('GEZD1', RFC_TOKEN, 59_000), null);
  assert.equal(await findMatchingTotpCounter('A', RFC_TOKEN, 59_000), null);
  assert.equal(isTotpEnabled(' = '), false);
});
