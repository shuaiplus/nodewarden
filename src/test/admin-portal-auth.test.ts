import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, like } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { auditLogs, verification } from '../db/schema';
import {
  authedFetch,
  captureEmail,
  createTestEnv,
  drainWaitUntil,
  failingEmail,
  MAILABLE_DOMAIN,
  portalFetch,
  signInToAdminPortal,
  type SentEmail,
} from './support/env';
import { sha256Base64Url } from '../utils/account-passkeys';
const email = `admin@${MAILABLE_DOMAIN}`;
const cookie = (response: Response, name: string) =>
  response.headers
    .getSetCookie()
    .find((value) => value.startsWith(name + '='))
    ?.split(';')[0] ?? '';
const token = (sent: SentEmail[]) =>
  new URL(sent.at(-1)!.text.match(/https:\/\/\S+\/admin\/login\/confirm\?token=\S+/)![0]).searchParams.get('token')!;

test('admin links are same-browser POST-only and single-use; sessions use CSRF and revoke on logout', async () => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ADMIN_EMAILS: email });
  const requested = await portalFetch(env, {
    method: 'POST',
    path: '/admin/login',
    form: { email: email.toUpperCase(), returnUrl: '/admin/users?page=2' },
    headers: { 'X-Forwarded-Host': 'evil.test' },
  });
  assert.equal(requested.status, 303);
  const nonce = cookie(requested, '__Host-nw_admin_login');
  await drainWaitUntil();
  assert.equal(capture.sent.length, 1);
  assert.equal(capture.sent[0].to, email);
  assert.match(capture.sent[0].text, /https:\/\/vault.example.test\/admin\/login\/confirm/);
  const value = token(capture.sent);
  assert.ok(!capture.sent[0].subject.includes(value));
  for (let i = 0; i < 2; i++)
    assert.equal((await portalFetch(env, { path: `/admin/login/confirm?token=${value}` })).status, 200);
  for (const wrongCookie of ['', '__Host-nw_admin_login=' + 'A'.repeat(43)]) {
    assert.equal(
      (
        await portalFetch(env, {
          method: 'POST',
          path: '/admin/login/confirm',
          form: { token: value },
          cookie: wrongCookie,
        })
      ).status,
      400,
    );
  }
  const confirmed = await portalFetch(env, {
    method: 'POST',
    path: '/admin/login/confirm',
    form: { token: value },
    cookie: nonce,
  });
  assert.equal(confirmed.status, 303);
  assert.equal(confirmed.headers.get('Location'), '/admin/users?page=2');
  const session = cookie(confirmed, '__Host-nw_admin');
  assert.match(
    confirmed.headers.getSetCookie().find((c) => c.startsWith('__Host-nw_admin='))!,
    /Max-Age=172800; Path=\/; HttpOnly; Secure; SameSite=Strict/,
  );
  assert.equal(
    (await portalFetch(env, { method: 'POST', path: '/admin/login/confirm', form: { token: value }, cookie: nonce }))
      .status,
    400,
  );
  const dashboard = await portalFetch(env, { path: '/admin', cookie: session });
  assert.equal(dashboard.status, 200);
  const csrf = (await dashboard.text()).match(/name="csrf" value="([^"]+)"/)![1];
  assert.equal((await authedFetch(env, { path: '/api/admin/users', headers: { Cookie: session } })).status, 401);
  assert.equal(
    (await portalFetch(env, { method: 'POST', path: '/admin/login/logout', form: {}, cookie: session })).status,
    403,
  );
  assert.equal(
    (
      await portalFetch(env, {
        method: 'POST',
        path: '/admin/login/logout',
        form: { csrf },
        cookie: session,
        headers: { Origin: 'https://evil.test' },
      })
    ).status,
    403,
  );
  assert.equal(
    (await portalFetch(env, { method: 'POST', path: '/admin/login/logout', form: { csrf }, cookie: session })).status,
    303,
  );
  assert.equal((await portalFetch(env, { path: '/admin', cookie: session })).status, 303);
  const audit = await getOrm(env.DB)
    .select({ actorUserId: auditLogs.actorUserId, metadata: auditLogs.metadata })
    .from(auditLogs)
    .where(eq(auditLogs.action, 'admin.portal.login'))
    .get();
  assert.equal(audit?.actorUserId, null);
  assert.equal(JSON.parse(audit!.metadata!).adminEmail, email);
});

test('admin request responses conceal directory membership, mail failure and per-admin budget', async (t) => {
  t.mock.method(console, 'warn', () => {});
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ADMIN_EMAILS: email });
  const statuses = [];
  for (const address of [email, 'unknown@' + MAILABLE_DOMAIN, email, email, email]) {
    const response = await portalFetch(env, { method: 'POST', path: '/admin/login', form: { email: address } });
    statuses.push([
      response.status,
      response.headers.get('Location'),
      await response.text(),
      cookie(response, '__Host-nw_admin_login').split('=')[0],
    ]);
    await drainWaitUntil();
  }
  statuses.forEach((status) => assert.deepEqual(status, statuses[0]));
  assert.equal(capture.sent.length, 3);
  assert.equal(await getOrm(env.DB).$count(verification, like(verification.id, 'admin-login:%')), 3);
  for (let i = 0; i < 5; i++)
    await portalFetch(env, { method: 'POST', path: '/admin/login', form: { email: 'unknown@' + MAILABLE_DOMAIN } });
  assert.equal((await portalFetch(env, { method: 'POST', path: '/admin/login', form: { email } })).status, 429);
  const failed = await createTestEnv({
    ...capture.overrides,
    EMAIL: failingEmail('E_RECIPIENT_SUPPRESSED'),
    ADMIN_EMAILS: email,
  });
  assert.equal((await portalFetch(failed, { method: 'POST', path: '/admin/login', form: { email } })).status, 303);
  await drainWaitUntil();
  failed.EMAIL = undefined;
  assert.match(await (await portalFetch(failed, { path: '/admin/login' })).text(), /cannot be sent/);
  assert.equal(
    (
      await authedFetch(failed, {
        method: 'POST',
        path: '/admin/login',
        body: new URLSearchParams({ email }),
        headers: { Origin: 'https://vault.example.test', 'CF-Connecting-IP': '' },
      })
    ).status,
    403,
  );
});

test('admin sessions expire and directory/stamp changes revoke both links and sessions', async () => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ADMIN_EMAILS: email });
  const session = await signInToAdminPortal(env, email);
  env.ADMIN_EMAILS = email + ':rotated';
  assert.equal((await portalFetch(env, { path: '/admin', cookie: session.cookie })).status, 303);
  const renewed = await signInToAdminPortal(env, email);
  await getOrm(env.DB).update(verification).set({ expiresAt: 0 }).where(like(verification.id, 'admin-session:%'));
  assert.equal((await portalFetch(env, { path: '/admin', cookie: renewed.cookie })).status, 303);
  const request = await portalFetch(env, { method: 'POST', path: '/admin/login', form: { email } });
  await drainWaitUntil();
  env.ADMIN_EMAILS = 'other@' + MAILABLE_DOMAIN;
  assert.equal(
    (
      await portalFetch(env, {
        method: 'POST',
        path: '/admin/login/confirm',
        form: { token: token(capture.sent) },
        cookie: cookie(request, '__Host-nw_admin_login'),
      })
    ).status,
    400,
  );
  env.ADMIN_EMAILS = email;
  const expiring = await portalFetch(env, { method: 'POST', path: '/admin/login', form: { email } });
  await drainWaitUntil();
  await getOrm(env.DB)
    .update(verification)
    .set({ expiresAt: 0 })
    .where(eq(verification.id, 'admin-login:' + (await sha256Base64Url(token(capture.sent)))));
  assert.equal(
    (
      await portalFetch(env, {
        method: 'POST',
        path: '/admin/login/confirm',
        form: { token: token(capture.sent) },
        cookie: cookie(expiring, '__Host-nw_admin_login'),
      })
    ).status,
    400,
  );
});

test('throttled or failed resends preserve earlier links from the same browser', async (t) => {
  t.mock.method(console, 'warn', () => {});
  for (const fail of [false, true]) {
    const capture = captureEmail();
    const env = await createTestEnv({ ...capture.overrides, ADMIN_EMAILS: email });
    const first = await portalFetch(env, { path: '/admin/login', method: 'POST', form: { email } });
    const browser = cookie(first, '__Host-nw_admin_login');
    await drainWaitUntil();
    const delivered = token(capture.sent);
    if (fail) env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
    for (let i = 0; i < (fail ? 1 : 3); i++) {
      const resend = await portalFetch(env, { path: '/admin/login', method: 'POST', form: { email }, cookie: browser });
      assert.equal(cookie(resend, '__Host-nw_admin_login'), browser);
      await drainWaitUntil();
    }
    assert.equal(capture.sent.length, fail ? 1 : 3);
    assert.equal(
      (
        await portalFetch(env, {
          path: '/admin/login/confirm',
          method: 'POST',
          form: { token: delivered },
          cookie: browser,
        })
      ).status,
      303,
    );
  }
});

test('portal cookies stay Secure on plain-http localhost, where SvelteKit would drop it and break __Host-', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: email });
  const origin = 'http://localhost:8787';
  const requested = await portalFetch(env, {
    method: 'POST',
    path: `${origin}/admin/login`,
    form: { email },
    headers: { Origin: origin },
  });
  await drainWaitUntil();
  assert.equal(requested.status, 303);
  assert.match(
    requested.headers.getSetCookie().find((c) => c.startsWith('__Host-nw_admin_login='))!,
    /; Secure;/,
  );
});
