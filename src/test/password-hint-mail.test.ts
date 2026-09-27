import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, seedUser } from './support/env';

test('password hints are mailed privately with uniform responses and background budgets', async (t) => {
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, WEB_VAULT_ORIGINS: '' });
  const user = await seedUser(env, {
    email: `hint@${MAILABLE_DOMAIN}`,
    masterPasswordHint: '<b>secret clue</b> https://x.y',
  });
  const noHint = await seedUser(env, { email: `nohint@${MAILABLE_DOMAIN}` });
  const banned = await seedUser(env, { email: `banned@${MAILABLE_DOMAIN}`, status: 'banned' });
  let ip = 10;
  const request = (email: string) =>
    authedFetch(env, {
      method: 'POST',
      path: '/api/accounts/password-hint',
      body: { email },
      headers: { 'CF-Connecting-IP': `203.0.113.${ip++}` },
    });
  const expected = { object: 'passwordHint', hasHint: false, masterPasswordHint: null, sentByEmail: true };
  for (const email of [user.email, noHint.email, banned.email, `unknown@${MAILABLE_DOMAIN}`])
    assert.deepEqual(await (await request(email)).json(), expected);
  await drainWaitUntil();
  assert.equal(capture.sent.length, 2);
  assert.match(capture.sent[0].html, /&lt;b&gt;secret clue&lt;\/b&gt;/);
  assert.match(capture.sent[0].text, /x\[dot\]y/);
  assert.match(capture.sent[1].text, /No master password hint/);
  for (let i = 0; i < 5; i++) {
    assert.deepEqual(await (await request(user.email)).json(), expected);
    await drainWaitUntil();
  }
  assert.equal(capture.sent.filter((message) => message.to === user.email).length, 5);
  env.EMAIL_FROM = 'bad';
  for (const email of [user.email, 'unknown@x.io']) assert.equal((await request(email)).status, 503);
  env.EMAIL = undefined;
  assert.deepEqual(await (await request(user.email)).json(), {
    object: 'passwordHint',
    hasHint: true,
    masterPasswordHint: user.masterPasswordHint,
  });
});
