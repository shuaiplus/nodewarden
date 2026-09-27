import assert from 'node:assert/strict';
import test from 'node:test';
import {
  authedFetch,
  captureEmail,
  createTestEnv,
  drainWaitUntil,
  failingEmail,
  MAILABLE_DOMAIN,
  seedUser,
} from './support/env';

test('registration verification responds uniformly before background delivery and never trusts forwarded hosts', async (t) => {
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, WEB_VAULT_ORIGINS: '', ALLOW_OPEN_REGISTRATION: '1' });
  const existing = await seedUser(env, { email: `known@${MAILABLE_DOMAIN}` });
  let address = 10;
  const request = (email: string) =>
    authedFetch(env, {
      method: 'POST',
      path: '/identity/accounts/register/send-verification-email',
      body: { email },
      headers: { 'X-Forwarded-Host': 'evil.test', 'CF-Connecting-IP': `203.0.113.${address++}` },
    });
  for (const email of [existing.email, `new@${MAILABLE_DOMAIN}`, 'reserved@example.test']) {
    const response = await request(email);
    assert.equal(response.status, 200);
    assert.equal(await response.json(), '');
  }
  await drainWaitUntil();
  assert.equal(capture.sent.length, 1);
  assert.match(capture.sent[0].text, /https:\/\/vault.example.test\/redirect-connector.html/);
  env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
  assert.equal(await (await request(`failed@${MAILABLE_DOMAIN}`)).json(), '');
  await drainWaitUntil();
  for (const email of [existing.email, `unknown@${MAILABLE_DOMAIN}`]) {
    env.EMAIL = undefined;
    assert.equal((await request(email)).status, 503);
    env.EMAIL = capture.overrides.EMAIL;
    env.EMAIL_FROM = 'invalid';
    assert.equal((await request(email)).status, 503);
  }
});
