import assert from 'node:assert/strict';
import test from 'node:test';

import { calcTotpNow, normalizeTotpInput } from '../webapp/src/lib/totp';

// RFC 6238 appendix B: ASCII "12345678901234567890" (SHA-1) and "12345678901234567890123456789012" (SHA-256).
const RFC_SHA1_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const RFC_SHA256_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const RFC_TIME_MS = 59_000;

test('otpauth URIs honour algorithm, digits and period', async () => {
  const sha256 = await calcTotpNow(`otpauth://totp/x?secret=${RFC_SHA256_SECRET}&algorithm=SHA256&digits=8`, RFC_TIME_MS);
  assert.deepEqual(sha256, { code: '46119246', remain: 1, period: 30 });
  const slow = await calcTotpNow(`otpauth://totp/x?secret=${RFC_SHA1_SECRET}&digits=8&period=60`, RFC_TIME_MS);
  assert.equal(slow?.remain, 1);
});

test('lenient inputs otpauth URI.parse would reject still produce codes', async () => {
  const expected = { code: '94287082', remain: 1, period: 30 };
  const grouped = RFC_SHA1_SECRET.toLowerCase().replace(/(.{4})/g, '$1 ');
  assert.deepEqual(await calcTotpNow(`otpauth://hotp?SECRET=${encodeURIComponent(grouped)}&digits=8`, RFC_TIME_MS), expected);
  assert.equal((await calcTotpNow(`${grouped}-===`, RFC_TIME_MS))?.code, '287082');
  assert.equal(await calcTotpNow('https://example.com/?secret=GEZDGNBV', RFC_TIME_MS), null);
  assert.equal(await calcTotpNow('!!!', RFC_TIME_MS), null);
});

test('steam secrets render in the Steam Guard alphabet', async () => {
  assert.deepEqual(await calcTotpNow(`steam://${RFC_SHA1_SECRET}`, RFC_TIME_MS), { code: 'PV9M4', remain: 1, period: 30 });
});

test('a single-account Google Authenticator migration becomes an equivalent otpauth URI', async () => {
  // MigrationPayload { otp_parameters { secret, name "john", issuer "ACME", algorithm SHA1, digits EIGHT, type TOTP } }
  const migration = 'otpauth-migration://offline?data=CigKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgRqb2huGgRBQ01FIAEoAjAC';
  const uri = normalizeTotpInput(migration);
  assert.equal(uri, `otpauth://totp/ACME:john?issuer=ACME&secret=${RFC_SHA1_SECRET}&algorithm=SHA1&digits=8&period=30`);
  assert.equal((await calcTotpNow(migration, RFC_TIME_MS))?.code, '94287082');
});
