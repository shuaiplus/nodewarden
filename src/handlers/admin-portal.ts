import type { Env } from '../types';
import { LIMITS } from '../config/limits';
import {
  parseAdminDirectory, checkPortalRequest, adminReturnPath, ADMIN_COOKIE, ADMIN_LOGIN_COOKIE,
  ADMIN_TOKEN_PATTERN, adminCookie, readAdminCookie, randomAdminToken, createAdminSession,
  readAdminSession, issueAdminLogin, redeemAdminLogin,
} from '../services/admin-portal-auth';
import { readMailConfig, EMAIL_PATTERN } from '../services/mail';
import { runInBackground } from '../services/mail-notify';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { StorageService } from '../services/storage';
import { webVaultNotFoundResponse } from '../web-vault-visibility';
import { constantTimeEquals } from '../utils/api-key';
import { html } from '../utils/html';
import { portalPage, portalRedirect, loginPage, LOGIN_MESSAGES, portalNavigation } from '../views/admin-portal';

const forbidden = () => portalPage('Forbidden', html`<p>This request is not allowed.</p>`, 403);
const methodNotAllowed = () => portalPage('Method not allowed', html`<p>This method is not supported.</p>`, 405);
const invalidLink = () => loginPage('/admin', true, LOGIN_MESSAGES.invalid, 400);

export async function handleAdminPortal(request: Request, env: Env): Promise<Response> {
  try {
    const directory = parseAdminDirectory(env);
    if (directory.kind === 'disabled') return webVaultNotFoundResponse(request);
    if (directory.kind === 'invalid') {
      console.error('Invalid ADMIN_EMAILS entry', { entryIndex: directory.entryIndex });
      return portalPage('Configuration error', html`<p>Administrator access is not configured correctly.</p>`, 500);
    }
    if (!checkPortalRequest(request)) { console.warn('Rejected administrator request'); return forbidden(); }
    const url = new URL(request.url);
    const path = url.pathname;
    const audit = (action: string, email?: string) => writeAuditEvent(new StorageService(env.DB), {
      action, category: 'security', level: 'security', actorUserId: null,
      metadata: { ...auditRequestMetadata(request), ...(email ? { adminEmail: email } : {}) },
    });
    if (path === '/admin/login') {
      const mailEnabled = readMailConfig(env).kind === 'enabled';
      if (request.method === 'GET') return loginPage(adminReturnPath(url.searchParams.get('returnUrl') ?? '/admin', url.origin), mailEnabled, LOGIN_MESSAGES[url.searchParams.get('m') ?? '']);
      if (request.method !== 'POST') return methodNotAllowed();
      const form = await request.formData();
      const email = String(form.get('email') ?? '').trim().toLowerCase();
      const returnPath = adminReturnPath(String(form.get('returnUrl') ?? '/admin'), url.origin);
      if (!EMAIL_PATTERN.test(email) || email.length > 256) return loginPage(returnPath, mailEnabled, 'Enter a valid email address.', 400);
      const clientId = getClientIdentifier(request);
      if (!clientId) return forbidden();
      const budget = await new RateLimitService(env.DB).consumeStrictBudgetWithWindow(`admin-login-ip:${clientId}`, LIMITS.admin.loginRequestsPerIpPerHour, 3600);
      if (!budget.allowed) return portalPage('Too many requests', html`<p>Try signing in later.</p>`, 429, { 'Retry-After': String(budget.retryAfterSeconds) });
      const nonce = randomAdminToken();
      runInBackground('admin-login', async () => {
        const stamp = directory.admins.get(email);
        if (stamp && mailEnabled) await issueAdminLogin(env, request, email, stamp, nonce, returnPath);
      });
      return portalRedirect('/admin/login?m=sent', [adminCookie(ADMIN_LOGIN_COOKIE, nonce, LIMITS.admin.loginLinkTtlSeconds)]);
    }
    if (path === '/admin/login/confirm') {
      if (request.method === 'GET') {
        const token = url.searchParams.get('token') ?? '';
        if (!ADMIN_TOKEN_PATTERN.test(token)) return invalidLink();
        return portalPage('Confirm administrator sign-in', html`<form method="post" action="/admin/login/confirm"><input type="hidden" name="token" value="${token}"><button type="submit">Sign in</button></form>`);
      }
      if (request.method !== 'POST') return methodNotAllowed();
      const form = await request.formData();
      const value = await redeemAdminLogin(env, String(form.get('token') ?? ''), readAdminCookie(request, ADMIN_LOGIN_COOKIE));
      if (!value) { console.warn('Invalid administrator sign-in link'); return invalidLink(); }
      if (directory.admins.get(value.email) !== value.stampHash) { await audit('admin.portal.login.denied'); return invalidLink(); }
      const session = await createAdminSession(env, value.email, value.stampHash);
      await env.DB.prepare("DELETE FROM verification WHERE (identifier LIKE 'admin-login:%' OR identifier LIKE 'admin-session:%') AND expires_at < ?").bind(Date.now()).run();
      await audit('admin.portal.login', value.email);
      return portalRedirect(adminReturnPath(value.returnPath, url.origin), [adminCookie(ADMIN_LOGIN_COOKIE), adminCookie(ADMIN_COOKIE, session.token, LIMITS.admin.sessionTtlSeconds)]);
    }
    const { session, denied } = await readAdminSession(request, env, directory.admins);
    if (!session) {
      if (denied) await audit('admin.portal.login.denied');
      return portalRedirect(`/admin/login?returnUrl=${encodeURIComponent(adminReturnPath(path + url.search, url.origin))}`, [adminCookie(ADMIN_COOKIE)]);
    }
    let form: FormData | null = null;
    if (request.method === 'POST') {
      form = await request.formData();
      if (!constantTimeEquals(String(form.get('csrf') ?? ''), session.csrf)) return forbidden();
    }
    if (path === '/admin/login/logout') {
      if (request.method !== 'POST') return methodNotAllowed();
      await env.DB.prepare('DELETE FROM verification WHERE id=?').bind(session.id).run();
      await audit('admin.portal.logout', session.email);
      return portalRedirect('/admin/login?m=loggedout', [adminCookie(ADMIN_COOKIE)]);
    }
    if (path === '/admin' || path === '/admin/') {
      if (request.method !== 'GET') return methodNotAllowed();
      const counts = await env.DB.prepare('SELECT (SELECT count(*) FROM users) AS users, (SELECT count(*) FROM organizations) AS organizations').first<{ users: number; organizations: number }>();
      return portalPage('Administration', html`${portalNavigation(session.csrf)}<p>Signed in as ${session.email}</p><dl><dt>Users</dt><dd>${counts?.users ?? 0}</dd><dt>Organizations</dt><dd>${counts?.organizations ?? 0}</dd><dt>Administrators</dt><dd>${directory.admins.size}</dd></dl>`);
    }
    return portalPage('Not found', html`${portalNavigation(session.csrf)}<p>This page does not exist.</p>`, 404);
  } catch {
    console.error('Administrator portal request failed');
    return portalPage('Server error', html`<p>Unable to complete this request.</p>`, 500);
  }
}
