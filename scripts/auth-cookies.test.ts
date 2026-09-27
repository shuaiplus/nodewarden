import assert from 'node:assert/strict';
import test from 'node:test';
import { ADMIN_COOKIE, readAdminCookie } from '../src/services/admin-portal-auth';
import { authedFetch, createTestEnv, seedUser, TEST_ORIGIN } from './support/env';

const WEB_SESSION = { 'X-NodeWarden-Web-Session': '1' };
const refreshCookie = (response: Response) => response.headers.getSetCookie().find((value) => value.startsWith('nodewarden_web_refresh='));

test('the web vault refresh token round-trips through a strict HttpOnly cookie and revocation clears it', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const login = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', headers: WEB_SESSION, body: new URLSearchParams({ grant_type: 'password', username: user.email, password: user.masterPasswordHash }) });
  assert.equal(login.status, 200);
  const issued = refreshCookie(login)!;
  assert.match(issued, /^nodewarden_web_refresh=[^;]+; Max-Age=2592000; Path=\/identity\/connect; HttpOnly; Secure; SameSite=Strict$/);
  const cookie = issued.split(';')[0];

  const refreshed = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', headers: { ...WEB_SESSION, Cookie: `other=1; ${cookie}` }, body: new URLSearchParams({ grant_type: 'refresh_token' }) });
  assert.equal(refreshed.status, 200);

  const revoked = await authedFetch(env, { method: 'POST', path: '/identity/connect/revocation', headers: { ...WEB_SESSION, Cookie: refreshCookie(refreshed)!.split(';')[0] }, body: new URLSearchParams({}) });
  assert.equal(refreshCookie(revoked), 'nodewarden_web_refresh=; Max-Age=0; Path=/identity/connect; HttpOnly; Secure; SameSite=Strict');
});

test('an administrator cookie sent twice is trusted in neither copy', () => {
  const read = (cookie: string) => readAdminCookie(new Request(TEST_ORIGIN, { headers: { Cookie: cookie } }), ADMIN_COOKIE);
  assert.equal(read(`a=1; ${ADMIN_COOKIE}=token`), 'token');
  assert.equal(read(`${ADMIN_COOKIE}=token; ${ADMIN_COOKIE}=other`), '');
  assert.equal(read('a=1'), '');
});
