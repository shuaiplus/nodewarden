import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, like } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { auditLogs, verification } from '../db/schema';
import { jsonSet } from '../db/sql';
import { createTestEnv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import * as userRepo from '../services/storage-user-repo';

const ADMIN = 'portal@x.io';

test('portal verifies listed/unlisted accounts and names the vault-admin promotion before confirmation', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: ADMIN });
  const listed = await seedUser(env, { email: ADMIN, emailVerified: false });
  const unlisted = await seedUser(env, { emailVerified: false });
  const auth = await signInToAdminPortal(env, ADMIN);
  for (const [user, label, role] of [[listed, 'Verify email and grant vault admin', 'admin'], [unlisted, 'Verify email', 'user']] as const) {
    const view = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: auth.cookie });
    const html = await view.text();
    assert.ok(html.includes(label));
    assert.match(html, /registered without an emailed token/);
    const response = await portalFetch(env, {
      method: 'POST', path: `/admin/users/${user.id}/verify-email`, cookie: auth.cookie,
      form: { csrf: auth.csrf, confirmation: user.email.toUpperCase() },
    });
    assert.equal(response.status, 303);
    assert.match(response.headers.get('Location')!, /m=verified/);
    const verified = (await userRepo.getUserById(env.DB, user.id))!;
    assert.equal(verified.emailVerified, true);
    assert.equal(verified.role, role);
    const after = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: auth.cookie });
    assert.doesNotMatch(await after.text(), /\/verify-email/);
  }
  const events = await getOrm(env.DB).select({ actorUserId: auditLogs.actorUserId, metadata: auditLogs.metadata }).from(auditLogs)
    .where(eq(auditLogs.action, 'admin.portal.user.email_verified'));
  assert.equal(events.length, 2);
  assert.equal(events[0].actorUserId, null);
  assert.equal(JSON.parse(events[0].metadata!).adminEmail, ADMIN);
});

test('portal email verification enforces CSRF, typed email, recent sign-in and the shared sensitive-action budget', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: ADMIN });
  const user = await seedUser(env, { emailVerified: false });
  let auth = await signInToAdminPortal(env, ADMIN);
  const path = `/admin/users/${user.id}/verify-email`;
  const post = (form: Record<string, string>) => portalFetch(env, { method: 'POST', path, cookie: auth.cookie, form });
  assert.equal((await post({ confirmation: user.email })).status, 403);
  assert.equal((await post({ csrf: auth.csrf, confirmation: 'wrong@x.io' })).status, 400);
  await getOrm(env.DB).update(verification).set({ value: jsonSet(verification.value, '$.authTime', 0) }).where(like(verification.id, 'admin-session:%'));
  const stale = await post({ csrf: auth.csrf, confirmation: user.email });
  assert.equal(stale.status, 303);
  assert.match(stale.headers.get('Location')!, /m=reauth/);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.emailVerified, false);
  auth = await signInToAdminPortal(env, ADMIN);
  for (let index = 0; index < 20; index++) {
    const target = await seedUser(env, { emailVerified: false });
    const response = await portalFetch(env, { method: 'POST', path: `/admin/users/${target.id}/verify-email`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: target.email } });
    assert.equal(response.status, 303);
  }
  assert.equal((await post({ csrf: auth.csrf, confirmation: user.email })).status, 429);
  const deletion = await portalFetch(env, { method: 'POST', path: `/admin/users/delete/${user.id}`, cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(deletion.status, 429);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.emailVerified, false);
});
