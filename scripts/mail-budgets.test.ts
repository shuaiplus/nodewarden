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

test('the sixth organization invite to a recipient is refused before saving its membership', async (t) => {
  t.mock.method(console, 'warn', () => {});
  const { authedFetch, seedUser } = await import('./support/env');
  const { createOwnedOrganization } = await import('../src/handlers/organizations');
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const owner = await seedUser(env);
  const recipient = `invitee@${MAILABLE_DOMAIN}`;
  for (let i = 0; i < 6; i++) {
    const org = await createOwnedOrganization(env, owner, { name: `Organization ${i}`, key: '4.dGVzdA==' });
    const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${org.id}/users/invite`, userId: owner.id, body: { emails: [recipient], type: 2 } });
    assert.equal(response.status, i < 5 ? 200 : 429, await response.clone().text());
    if (i === 5) {
      assert.ok(Number(response.headers.get('Retry-After')) > 0);
      assert.equal(await env.DB.prepare('SELECT id FROM organization_memberships WHERE org_id=? AND email=?').bind(org.id, recipient).first(), null);
    }
  }
  assert.equal(capture.sent.length, 5);
});
