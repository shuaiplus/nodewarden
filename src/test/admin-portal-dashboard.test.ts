import assert from 'node:assert/strict';
import test from 'node:test';
import { captureEmail, createTestEnv, portalFetch, signInToAdminPortal, MAILABLE_DOMAIN } from './support/env';
import { safeWriteAuditEvent } from '../services/audit-events';

test('dashboard shows configuration facts and portal events without credentials or the directory', async (t) => {
  t.mock.method(console, 'error', () => {});
  const email = `admin@${MAILABLE_DOMAIN}`;
  const env = await createTestEnv({
    ...captureEmail().overrides,
    ADMIN_EMAILS: `${email},hidden@${MAILABLE_DOMAIN}`,
    SSO_CLIENT_SECRET: 'never-print-sso-secret',
    R2_SECRET_ACCESS_KEY: 'never-print-r2-secret',
  });
  const auth = await signInToAdminPortal(env, email);
  await safeWriteAuditEvent(env, {
    action: 'admin.portal.login',
    category: 'security',
    metadata: { adminEmail: email },
  });
  await safeWriteAuditEvent(env, { action: 'nonportal_event', category: 'security' });
  for (const state of ['enabled', 'misconfigured', 'disabled']) {
    if (state === 'misconfigured') env.EMAIL_FROM = 'bad';
    if (state === 'disabled') env.EMAIL = undefined;
    const response = await portalFetch(env, { path: '/admin', cookie: auth.cookie });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.match(body, new RegExp(`<dd>${state}</dd>`));
    assert.match(body, /admin.portal.login/);
    for (const forbidden of [
      env.JWT_SECRET,
      'never-print-sso-secret',
      'never-print-r2-secret',
      `hidden@${MAILABLE_DOMAIN}`,
      'nonportal_event',
    ])
      assert.ok(!body.includes(forbidden));
  }
  assert.equal((await portalFetch(env, { path: '/admin' })).status, 303);
});
