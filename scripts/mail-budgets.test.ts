import assert from 'node:assert/strict';
import test from 'node:test';
import { captureEmail, createTestEnv, MAILABLE_DOMAIN } from './support/env';
import { sendMail, readMailConfig, mailStatusCheck } from '../src/services/mail';
import { toSafeUrl } from '../src/utils/html';

test('mail budgets cap per-recipient and instance traffic while admin sign-in remains exempt', async (t) => {
  t.mock.method(console, 'warn', () => {});
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const email = `recipient@${MAILABLE_DOMAIN}`;
  const model = { vaultOrigin: 'https://vault.io', email, token: 'token' };
  for (let i = 0; i < 5; i++) assert.equal((await sendMail(env, email, 'registerVerification', model)).kind, 'sent');
  const capped = await sendMail(env, email.toUpperCase(), 'registerVerification', model);
  assert.equal(capped.kind, 'throttled');
  const status = mailStatusCheck(capped);
  assert.equal(status.ok, false);
  if (!status.ok) { assert.equal(status.status, 429); assert.ok(Number(status.headers['Retry-After']) > 0); }
  const small = await createTestEnv({ ...capture.overrides, EMAIL_SENDS_PER_HOUR: '2' });
  for (let i = 0; i < 2; i++) assert.equal((await sendMail(small, `r${i}@${MAILABLE_DOMAIN}`, 'registerVerification', model)).kind, 'sent');
  assert.equal((await sendMail(small, `third@${MAILABLE_DOMAIN}`, 'registerVerification', model)).kind, 'throttled');
  assert.equal((await sendMail(small, email, 'adminSignIn', { url: toSafeUrl(new URL('https://vault.io/admin')) })).kind, 'sent');
});

test('invalid mail budgets are configuration errors', (t) => {
  t.mock.method(console, 'error', () => {});
  for (const value of ['', '0', '-1', 'abc', '1.5', '1e3', '9007199254740992']) assert.equal(readMailConfig({ ...captureEmail().overrides, EMAIL_SENDS_PER_HOUR: value }).kind, 'misconfigured');
});
