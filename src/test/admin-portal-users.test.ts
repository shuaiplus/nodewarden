import assert from 'node:assert/strict';
import test from 'node:test';
import { createTestEnv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import { searchUsersByEmailPrefix } from '../services/storage-user-repo';

const adminEmail = 'portal@x.io';

test('portal user search escapes LIKE wildcards, bounds paging and safely renders 101 users', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: adminEmail });
  const auth = await signInToAdminPortal(env, adminEmail);
  for (let i = 0; i < 101; i++) await seedUser(env, { email: `u${String(i).padStart(3, '0')}@x.io`, name: '<script>bad()</script>', totpSecret: i === 0 ? 'SECRET' : null });
  await seedUser(env, { email: 'a_b@x.io' });
  await seedUser(env, { email: 'axb@x.io' });
  assert.equal((await searchUsersByEmailPrefix(env.DB, 'A_B@', 0, 10)).length, 1);
  assert.equal((await searchUsersByEmailPrefix(env.DB, '%', 0, 10)).length, 0);
  for (const page of ['0', '-1', 'abc', 'Infinity']) {
    const response = await portalFetch(env, { path: `/admin/users?email=u&count=1000&page=${page}`, cookie: auth.cookie });
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.equal((body.match(/\/admin\/users\/view\//g) ?? []).length, 100);
    assert.match(body, /Page 1/);
    assert.match(body, /Next/);
    assert.match(body, /&lt;script&gt;/);
    assert.doesNotMatch(body, /<script>/);
    assert.match(body, /<td>Yes<\/td>/);
  }
  assert.match(await (await portalFetch(env, { path: '/admin/users?email=u&count=100&page=2', cookie: auth.cookie })).text(), /Previous/);
});

test('portal delete requires CSRF, recent login and matching email; logs successful deletion', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: adminEmail });
  const auth = await signInToAdminPortal(env, adminEmail);
  const user = await seedUser(env, { name: '<script>bad()</script>' });
  const path = `/admin/users/delete/${user.id}`;
  assert.equal((await portalFetch(env, { path, cookie: auth.cookie })).status, 405);
  assert.equal((await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { confirmation: user.email } })).status, 403);
  assert.equal((await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: 'wrong' } })).status, 400);
  await env.DB.prepare("UPDATE verification SET value=json_set(value,'$.authTime',0) WHERE id LIKE 'admin-session:%'").run();
  const stale = await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { csrf: auth.csrf, confirmation: user.email } });
  assert.equal(stale.status, 303);
  assert.match(stale.headers.get('Location')!, /m=reauth/);
  const fresh = await signInToAdminPortal(env, adminEmail);
  const view = await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: fresh.cookie });
  assert.match(await view.text(), /&lt;script&gt;/);
  assert.equal((await portalFetch(env, { path, method: 'POST', cookie: fresh.cookie, form: { csrf: fresh.csrf, confirmation: user.email.toUpperCase() } })).status, 303);
  assert.equal(await env.DB.prepare('SELECT id FROM users WHERE id=?').bind(user.id).first(), null);
  const audit = await env.DB.prepare("SELECT metadata FROM audit_logs WHERE action='admin.portal.user.delete'").first<{ metadata: string }>();
  assert.equal(JSON.parse(audit!.metadata).adminEmail, adminEmail);
  assert.equal((await portalFetch(env, { path: `/admin/users/view/${user.id}`, cookie: fresh.cookie })).status, 404);
  const lastAdmin = await seedUser(env, { role: 'admin' });
  const refused = await portalFetch(env, { path: `/admin/users/delete/${lastAdmin.id}`, method: 'POST', cookie: fresh.cookie, form: { csrf: fresh.csrf, confirmation: lastAdmin.email } });
  assert.equal(refused.status, 400);
  assert.match(await refused.text(), /last active instance administrator/);
});
