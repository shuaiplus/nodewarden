import assert from 'node:assert/strict';
import test from 'node:test';

import { createTestEnv } from '../test/support/env';
import { LIMITS } from '../config/limits';
import { hmacSha256Base64Url } from '../utils/jwt';
import { issueEmailOtp, purgeExpiredEmailOtps, redeemEmailOtp, spendEmailOtpIssueBudget, type EmailOtpTarget } from './email-otp';
import type { MailOutcome } from './mail';

const NOW = 1_800_000_000_000;
const target: EmailOtpTarget = { purpose: 'two-factor-setup', subject: 'user@example.test', binding: 'stamp:setup@example.test' };

test('OTP generation rejects biased draws, pads six digits and stores only HMAC-protected identifiers and values', async (t) => {
  const env = await createTestEnv();
  t.mock.method(Date, 'now', () => NOW);
  const draws = [0xffff_ffff, 4_294_000_000, 4_293_999_999, 0, 42];
  const random = t.mock.method(crypto, 'getRandomValues', (bytes: Uint32Array) => {
    assert.ok(draws.length, 'unexpected random draw');
    bytes[0] = draws.shift()!;
    return bytes;
  });
  for (const expected of ['999999', '000000', '000042']) {
    const current = { ...target, subject: `${target.subject}:${expected}` };
    assert.deepEqual(await issueEmailOtp(env, current, async code => {
      assert.equal(code, expected);
      return { kind: 'sent' };
    }), { kind: 'sent' });
    const id = `otp:${current.purpose}:${await hmacSha256Base64Url(env.JWT_SECRET, `${current.purpose}\n${current.subject}`)}`;
    const row = await env.DB.prepare('SELECT id, identifier, value, expires_at FROM verification WHERE id = ?').bind(id)
      .first<{ id: string; identifier: string; value: string; expires_at: number }>();
    assert.deepEqual(row, {
      id, identifier: id,
      value: await hmacSha256Base64Url(env.JWT_SECRET, `${id}\n${current.binding}\n${expected}`),
      expires_at: NOW + LIMITS.auth.emailOtpTtlSeconds * 1000,
    });
    assert.ok(!id.includes(current.subject));
    assert.notEqual(row!.value, expected);
  }
  assert.equal(random.mock.callCount(), 5);
});

test('redemption binds purpose, subject and stamp/email, preserves typos, and consumes a code only once', async (t) => {
  const env = await createTestEnv();
  t.mock.method(Date, 'now', () => NOW);
  let code = '';
  await issueEmailOtp(env, target, async value => { code = value; return { kind: 'sent' }; });
  const prepare = t.mock.method(env.DB, 'prepare');
  for (const invalid of ['', '12345', '1234567', '123 456', '１２３４５６']) {
    assert.equal(await redeemEmailOtp(env, target, invalid), false);
  }
  assert.equal(prepare.mock.callCount(), 0);
  assert.equal(await redeemEmailOtp(env, { ...target, purpose: 'two-factor-login' }, code), false);
  assert.equal(await redeemEmailOtp(env, { ...target, subject: 'another-user' }, code), false);
  assert.equal(await redeemEmailOtp(env, { ...target, binding: 'new-stamp:setup@example.test' }, code), false);
  assert.equal(await redeemEmailOtp(env, { ...target, binding: 'stamp:other@example.test' }, code), false);
  assert.equal(await redeemEmailOtp(env, target, code === '000000' ? '000001' : '000000'), false);
  const results = await Promise.all([redeemEmailOtp(env, target, ` ${code}\n`), redeemEmailOtp(env, target, code)]);
  assert.deepEqual(results.sort(), [false, true]);
  assert.equal(await env.DB.prepare('SELECT count(*) AS n FROM verification').first('n'), 0);
});

test('failed or throttled delivery preserves the previous code and successful resends replace one row', async (t) => {
  const env = await createTestEnv();
  t.mock.method(Date, 'now', () => NOW);
  let draw = 100;
  t.mock.method(crypto, 'getRandomValues', (bytes: Uint32Array) => { bytes[0] = draw++; return bytes; });
  let first = '';
  await issueEmailOtp(env, target, async code => { first = code; return { kind: 'sent' }; });
  const original = await env.DB.prepare('SELECT * FROM verification').first();
  for (const outcome of [{ kind: 'failed', code: 'E_TEST' }, { kind: 'throttled', retryAfterSeconds: 60 }] satisfies MailOutcome[]) {
    assert.deepEqual(await issueEmailOtp(env, target, async () => outcome), outcome);
    assert.deepEqual(await env.DB.prepare('SELECT * FROM verification').first(), original);
  }
  assert.equal(await redeemEmailOtp(env, target, first), true);
  let replacement = '';
  await issueEmailOtp(env, target, async code => { replacement = code; return { kind: 'sent' }; });
  let latest = '';
  await issueEmailOtp(env, target, async code => { latest = code; return { kind: 'sent' }; });
  assert.equal(await env.DB.prepare('SELECT count(*) AS n FROM verification').first('n'), 1);
  assert.equal(await redeemEmailOtp(env, target, replacement), false);
  let sentAfterLimit = false;
  assert.deepEqual(await issueEmailOtp(env, target, async () => { sentAfterLimit = true; return { kind: 'sent' }; }), { kind: 'throttled', retryAfterSeconds: 3600 });
  assert.equal(sentAfterLimit, false);
  assert.equal(await redeemEmailOtp(env, target, latest), true);
});

test('issue budgets separate purposes and subjects, with larger sign-in limits and stable binding-independent attempts', async (t) => {
  const env = await createTestEnv();
  t.mock.method(Date, 'now', () => NOW);
  for (const purpose of ['two-factor-setup', 'email-change', 'send-access', 'two-factor-login', 'new-device'] as const) {
    const current = { ...target, purpose };
    const limit = purpose === 'two-factor-login' || purpose === 'new-device'
      ? LIMITS.rateLimit.emailSignInCodeIssuesPerHour : LIMITS.rateLimit.emailOtpIssuesPerHour;
    for (let index = 0; index < limit; index++) assert.equal(await spendEmailOtpIssueBudget(env, current), true);
    assert.equal(await spendEmailOtpIssueBudget(env, { ...current, binding: 'changed' }), false);
    assert.equal(await spendEmailOtpIssueBudget(env, { ...current, subject: 'another-user' }), true);
  }
  const current = { ...target, subject: 'attempt-budget' };
  let code = '';
  await issueEmailOtp(env, current, async value => { code = value; return { kind: 'sent' }; });
  for (let index = 0; index < LIMITS.rateLimit.emailOtpAttemptsPerWindow; index++) {
    assert.equal(await redeemEmailOtp(env, { ...current, binding: `wrong-${index}` }, code), false);
  }
  assert.equal(await redeemEmailOtp(env, current, code), false);
  assert.equal(await env.DB.prepare('SELECT count(*) AS n FROM verification').first('n'), 1);
  const buckets = await env.DB.prepare('SELECT bucket_key FROM rate_limit_buckets').all<{ bucket_key: string }>();
  assert.ok(buckets.results.every(row => !row.bucket_key.includes(target.subject)));
});

test('codes expire at the TTL and purge removes only expired OTP identifiers', async (t) => {
  const env = await createTestEnv();
  let now = NOW;
  t.mock.method(Date, 'now', () => now);
  let code = '';
  await issueEmailOtp(env, target, async value => { code = value; return { kind: 'sent' }; });
  now += LIMITS.auth.emailOtpTtlSeconds * 1000;
  assert.equal(await redeemEmailOtp(env, target, code), false);
  now++;
  for (const [id, identifier, expires] of [
    ['expired-otp', 'otp:manual', now - 1],
    ['live-otp', 'otp:live', now + 1],
    ['boundary-otp', 'otp:boundary', now],
    ['prefix-neighbor', 'otp;neighbor', now - 1],
    ['plain-prefix', 'otp', now - 1],
    ['other-purpose', 'admin-session:test', now - 1],
  ] as const) {
    await env.DB.prepare('INSERT INTO verification (id, identifier, value, expires_at) VALUES (?, ?, ?, ?)')
      .bind(id, identifier, 'opaque', expires).run();
  }
  await purgeExpiredEmailOtps(env);
  const remaining = await env.DB.prepare('SELECT id FROM verification ORDER BY id').all<{ id: string }>();
  assert.deepEqual(remaining.results.map(row => row.id), ['boundary-otp', 'live-otp', 'other-purpose', 'plain-prefix', 'prefix-neighbor']);
});
