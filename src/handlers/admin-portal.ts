import { twoFactorProviders, twoFactorClearStatements } from '../services/two-factor-providers';
import { AuthService } from '../services/auth';
import { notifyUserLogout } from '../durable/notifications-hub';
import { markEmailVerified } from '../services/vault-admin-role';
import * as orgRepo from '../services/storage-org-repo';
import { canAccessSecretsManager } from '../services/org-authz';
import { MembershipStatus, MembershipType, publicMembershipStatus } from '../services/org-types';
import { searchUsersByEmailPrefix } from '../services/storage-user-repo';
import { countPersonalCiphers } from '../services/storage-cipher-repo';
import { deleteUserAccount, deleteOrganizationAccount, setUserStatus } from '../services/account-deletion';
import { sha256Base64Url } from '../utils/account-passkeys';
import { listAuditLogs } from '../services/storage-admin-repo';
import { isOpenRegistrationEnabled } from '../services/register-payload';
import { getConfiguredWebVaultOrigins } from '../utils/origins';
import { isSsoEnabled } from './sso';
import { getYubicoCredentials } from '../services/yubico-config';
import type { Env } from '../types';
import { LIMITS } from '../config/limits';
import {
  parseAdminDirectory, checkPortalRequest, adminReturnPath, ADMIN_COOKIE, ADMIN_LOGIN_COOKIE,
  ADMIN_TOKEN_PATTERN, adminCookie, readAdminCookie, randomAdminToken, createAdminSession,
  readAdminSession, issueAdminLogin, redeemAdminLogin,
} from '../services/admin-portal-auth';
import { readMailConfig, EMAIL_PATTERN } from '../services/mail';
import { runInBackground, notifyMail } from '../services/mail-notify';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent, auditEventStatement } from '../services/audit-events';
import { StorageService } from '../services/storage';
import { webVaultNotFoundResponse } from '../web-vault-visibility';
import { constantTimeEquals } from '../utils/api-key';
import { html } from '../utils/html';
import { portalPage, portalRedirect, loginPage, LOGIN_MESSAGES, portalNavigation, portalFields, deleteForm, portalPagination, userStatusForm, verifyEmailForm, removeTwoFactorForm } from '../views/admin-portal';

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
      const existingNonce = readAdminCookie(request, ADMIN_LOGIN_COOKIE);
      const nonce = ADMIN_TOKEN_PATTERN.test(existingNonce) ? existingNonce : randomAdminToken();
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
    const requestedPage = Number(url.searchParams.get('page'));
    const page = Number.isFinite(requestedPage) ? Math.max(1, Math.floor(requestedPage)) : 1;
    const count = Math.min(LIMITS.admin.pageSizeMax, Math.max(1, Math.floor(Number(url.searchParams.get('count')) || LIMITS.admin.pageSizeDefault)));
    const sensitiveActionCheck = async (confirmation: string, expected: string, viewPath: string): Promise<Response | null> => {
      if (Date.now() - session.authTime > LIMITS.admin.destructiveReauthSeconds * 1000) return portalRedirect(`/admin/login?returnUrl=${encodeURIComponent(viewPath)}&m=reauth`);
      if (confirmation !== expected) return portalPage('Confirmation does not match', html`${portalNavigation(session.csrf)}<p>The typed confirmation does not match.</p><a href="${viewPath}">Return</a>`, 400);
      const budget = await new RateLimitService(env.DB).consumeStrictBudgetWithWindow(`admin-portal-sensitive:${await sha256Base64Url(session.email)}`, LIMITS.admin.sensitiveActionsPerAdminPerHour, 3600);
      return budget.allowed ? null : portalPage('Too many requests', html`<p>Try again later.</p>`, 429, { 'Retry-After': String(budget.retryAfterSeconds) });
    };
    if (path === '/admin/users') {
      if (request.method !== 'GET') return methodNotAllowed();
      const email = url.searchParams.get('email') ?? '';
      const rows = await searchUsersByEmailPrefix(env.DB, email, (page - 1) * count, count);
      return portalPage('Users', html`${portalNavigation(session.csrf)}<form method="get" action="/admin/users"><label>Email prefix <input name="email" value="${email}"></label><input type="hidden" name="count" value="${count}"><button type="submit">Search</button></form><table><thead><tr><th>Email</th><th>Name</th><th>Created</th><th>Status</th><th>Vault role</th><th>Two-factor</th></tr></thead><tbody>${rows.slice(0, count).map((user) => html`<tr><td><a href="${'/admin/users/view/' + encodeURIComponent(user.id)}">${user.email}</a></td><td>${user.name ?? ''}</td><td>${user.createdAt}</td><td>${user.status}</td><td>${user.role}</td><td>${user.twoFactor ? 'Yes' : 'No'}</td></tr>`)}</tbody></table>${portalPagination(url, page, rows.length > count)}`);
    }
    const userActionPath = path.match(/^\/admin\/users\/([^/]+)\/(disable|enable|verify-email|remove-2fa)$/);
    const userPath = path.match(/^\/admin\/users\/(view|delete)\/([^/]+)$/)
      ?? (userActionPath ? [userActionPath[0], userActionPath[2], userActionPath[1]] : null);
    if (userPath) {
      const deleting = userPath[1] === 'delete';
      if (request.method !== (userPath[1] === 'view' ? 'GET' : 'POST')) return methodNotAllowed();
      const storage = new StorageService(env.DB);
      const user = await storage.getUserById(decodeURIComponent(userPath[2]));
      if (!user) return portalPage('Not found', html`<p>User not found.</p>`, 404);
      const viewPath = '/admin/users/view/' + encodeURIComponent(user.id);
      let refusal = '';
      if (deleting) {
        const check = await sensitiveActionCheck(String(form?.get('confirmation') ?? '').trim().toLowerCase(), user.email.toLowerCase(), viewPath);
        if (check) return check;
        const outcome = await deleteUserAccount(env, user.id, { action: 'admin.portal.user.delete', category: 'security', level: 'security', actorUserId: null, targetType: 'user', targetId: user.id, metadata: { adminEmail: session.email, ...auditRequestMetadata(request) } });
        if (outcome.kind === 'deleted') return portalRedirect('/admin/users?m=deleted');
        if (outcome.kind === 'not-found') return portalPage('Not found', html`<p>User not found.</p>`, 404);
        refusal = outcome.kind === 'last-vault-admin' ? 'Cannot delete the last active instance administrator.' : 'Transfer or delete these organizations first: ' + outcome.orgIds.join(', ');
      }
      if (userPath[1] === 'disable' || userPath[1] === 'enable') {
        const next = userPath[1] === 'disable' ? 'banned' : 'active';
        const outcome = await setUserStatus(env, user.id, next, {
          action: `admin.portal.user.${userPath[1]}`, category: 'security', level: 'security', actorUserId: null,
          targetType: 'user', targetId: user.id, metadata: { adminEmail: session.email, ...auditRequestMetadata(request) },
        });
        if (outcome.kind === 'updated' || outcome.kind === 'unchanged') return portalRedirect(viewPath + (next === 'banned' ? '?m=disabled' : '?m=enabled'));
        if (outcome.kind === 'not-found') return portalPage('Not found', html`<p>User not found.</p>`, 404);
        refusal = 'Cannot disable the last active instance administrator.';
      }
      if (userPath[1] === 'verify-email') {
        const check = await sensitiveActionCheck(String(form?.get('confirmation') ?? '').trim().toLowerCase(), user.email.toLowerCase(), viewPath);
        if (check) return check;
        await markEmailVerified(env, user.id);
        await writeAuditEvent(storage, {
          action: 'admin.portal.user.email_verified', category: 'security', level: 'security', actorUserId: null,
          targetType: 'user', targetId: user.id, metadata: { adminEmail: session.email, ...auditRequestMetadata(request) },
        });
        return portalRedirect(viewPath + '?m=verified');
      }
      if (userPath[1] === 'remove-2fa') {
        const passkeys = await storage.countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor');
        if (!twoFactorProviders(user, passkeys > 0).length) return portalRedirect(viewPath + '?m=nothing-to-reset');
        const check = await sensitiveActionCheck(String(form?.get('confirmation') ?? '').trim().toLowerCase(), user.email.toLowerCase(), viewPath);
        if (check) return check;
        const event = auditEventStatement(env.DB, {
          action: 'admin.portal.user.two_factor.reset', category: 'security', level: 'security', actorUserId: null,
          targetType: 'user', targetId: user.id, metadata: { adminEmail: session.email, ...auditRequestMetadata(request) },
        }).toSQL();
        await env.DB.batch([
          ...twoFactorClearStatements(env.DB, user.id, { recoveryCode: null, securityStamp: crypto.randomUUID() }),
          env.DB.prepare(event.sql).bind(...event.params),
        ]);
        AuthService.invalidateUserCache(user.id);
        notifyUserLogout(env, user.id, null);
        notifyMail(env, user.email, 'twoFactorRecovered', { by: 'administrator' });
        return portalRedirect(viewPath + '?m=two-factor-reset');
      }
      const [personalItems, memberships, passkeys] = await Promise.all([
        countPersonalCiphers(env.DB, user.id),
        env.DB.prepare('SELECT count(*) AS total FROM organization_memberships WHERE user_id=?').bind(user.id).first<{ total: number }>(),
        storage.countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor'),
      ]);
      const providers = twoFactorProviders(user, passkeys > 0);
      return portalPage('User details', html`${portalNavigation(session.csrf)}${refusal ? html`<p class="notice">${refusal}</p>` : html``}${portalFields([
        ['Id', user.id], ['Email', user.email], ['Email verified', user.emailVerified ? 'Yes' : 'No (registered without an emailed token)'], ['Name', user.name ?? ''], ['Status', user.status], ['Vault role', user.role], ['Created', user.createdAt], ['Modified', user.updatedAt], ['Two-factor', providers.map(provider => ({ 0: 'Authenticator', 1: 'Email', 3: 'YubiKey', 7: 'WebAuthn' })[provider]).join(', ') || 'None'], ['Personal items', personalItems], ['Organization memberships', memberships?.total ?? 0],
      ])}${user.emailVerified ? html`` : verifyEmailForm(user.id, session.csrf, user.email, directory.admins.has(user.email))}${userStatusForm(user.id, session.csrf, user.status)}${providers.length ? removeTwoFactorForm(user.id, session.csrf, user.email) : html``}${deleteForm('/admin/users/delete/' + encodeURIComponent(user.id), session.csrf, user.email)}`, refusal ? 400 : 200);
    }
    if (path === '/admin/organizations') {
      if (request.method !== 'GET') return methodNotAllowed();
      const name = url.searchParams.get('name') ?? '';
      const userEmail = url.searchParams.get('userEmail') ?? '';
      const rows = await orgRepo.searchOrganizations(env.DB, { nameContains: name, memberEmail: userEmail, offset: (page - 1) * count, limit: count });
      return portalPage('Organizations', html`${portalNavigation(session.csrf)}<form method="get" action="/admin/organizations"><label>Name contains <input name="name" value="${name}"></label><label>Member email <input name="userEmail" value="${userEmail}"></label><input type="hidden" name="count" value="${count}"><button type="submit">Search</button></form><table><thead><tr><th>Name</th><th>Created</th><th>Billing email</th></tr></thead><tbody>${rows.slice(0, count).map((org) => html`<tr><td><a href="${'/admin/organizations/view/' + encodeURIComponent(org.id)}">${org.name}</a></td><td>${org.createdAt}</td><td>${org.billingEmail}</td></tr>`)}</tbody></table>${portalPagination(url, page, rows.length > count)}`);
    }
    const orgPath = path.match(/^\/admin\/organizations\/(view|delete)\/([^/]+)$/);
    if (orgPath) {
      const deleting = orgPath[1] === 'delete';
      if (request.method !== (deleting ? 'POST' : 'GET')) return methodNotAllowed();
      const org = await orgRepo.getOrganization(env.DB, decodeURIComponent(orgPath[2]));
      if (!org) return portalPage('Not found', html`<p>Organization not found.</p>`, 404);
      if (deleting) {
        const check = await sensitiveActionCheck(String(form?.get('confirmation') ?? ''), org.name, '/admin/organizations/view/' + encodeURIComponent(org.id));
        if (check) return check;
        await deleteOrganizationAccount(env, org.id, { action: 'admin.portal.org.delete', category: 'security', level: 'security', actorUserId: null, targetType: 'organization', targetId: org.id, metadata: { adminEmail: session.email, ...auditRequestMetadata(request) } });
        return portalRedirect('/admin/organizations?m=deleted');
      }
      const [members, stats] = await Promise.all([orgRepo.listMembershipsWithAccountsByOrg(env.DB, org.id), orgRepo.getOrganizationPortalStats(env.DB, org.id)]);
      const membershipCounts: Array<[string, number]> = Object.entries(MembershipStatus).filter(([name]) => name !== 'Staged').map(([name, status]) => [name, members.filter(({ item }) => publicMembershipStatus(item.status) === status).length]);
      const admins = members.filter(({ item }) => item.type === MembershipType.Owner || item.type === MembershipType.Admin);
      return portalPage('Organization details', html`${portalNavigation(session.csrf)}${portalFields([
        ['Id', org.id], ['Name', org.name], ['Created', org.createdAt], ['Modified', org.updatedAt], ['Billing email', org.billingEmail], ['SSO identifier', org.identifier ?? ''], ['Has keys', org.privateKey && org.publicKey ? 'Yes' : 'No'], ...membershipCounts, ['SM access', members.filter(({ item }) => canAccessSecretsManager(item)).length], ...stats,
      ])}<h2>Administrators</h2><table><thead><tr><th>Email</th><th>Type</th><th>Status</th></tr></thead><tbody>${admins.map(({ item, account }) => html`<tr><td>${account?.email ?? item.email ?? ''}</td><td>${item.type === MembershipType.Owner ? 'Owner' : 'Admin'}</td><td>${Object.entries(MembershipStatus).find(([, status]) => status === publicMembershipStatus(item.status))?.[0] ?? 'Unknown'}</td></tr>`)}</tbody></table>${deleteForm('/admin/organizations/delete/' + encodeURIComponent(org.id), session.csrf, org.name)}`);
    }
    if (path === '/admin' || path === '/admin/') {
      if (request.method !== 'GET') return methodNotAllowed();
      const counts = await env.DB.prepare('SELECT (SELECT count(*) FROM users) AS users, (SELECT count(*) FROM organizations) AS organizations').first<{ users: number; organizations: number }>();
      const mail = readMailConfig(env);
      const storage = new StorageService(env.DB);
      const [events, pushId, pushKey, yubico] = await Promise.all([
        listAuditLogs(env.DB, { actionPrefix: 'admin.portal.', limit: LIMITS.admin.recentAuditEvents, offset: 0 }),
        storage.getConfigValue('push.installation.id'), storage.getConfigValue('push.installation.key'), getYubicoCredentials(env.DB),
      ]);
      const settings: Array<[string, string | number]> = [
        ['Users', counts?.users ?? 0], ['Organizations', counts?.organizations ?? 0], ['Administrators', directory.admins.size],
        ['Compatible server version', LIMITS.compatibility.bitwardenServerVersion], ['Mail', mail.kind],
        ['Sender', mail.kind === 'enabled' ? `${mail.from.name} <${mail.from.email}>` : 'Unavailable'],
        ['Open registration', isOpenRegistrationEnabled(env) ? 'Yes' : 'No'], ['Vault origins', getConfiguredWebVaultOrigins(env).join(', ') || 'None'],
        ['SSO configured', isSsoEnabled(env) ? 'Yes' : 'No'], ['Push relay configured', pushId && pushKey ? 'Yes' : 'No'], ['Yubico configured', yubico ? 'Yes' : 'No'],
        ['Disable new-device email', env.DISABLE_EMAIL_NEW_DEVICE || 'false'], ['Email sends per hour', env.EMAIL_SENDS_PER_HOUR || '100'],
      ];
      return portalPage('Administration', html`${portalNavigation(session.csrf)}<p>Signed in as ${session.email}</p><dl>${settings.map(([name, value]) => html`<dt>${name}</dt><dd>${value}</dd>`)}</dl><h2>Recent administrator events</h2><table><thead><tr><th>Time</th><th>Action</th><th>Administrator</th></tr></thead><tbody>${events.logs.map((event) => html`<tr><td>${event.createdAt}</td><td>${event.action}</td><td>${String(JSON.parse(event.metadata ?? '{}').adminEmail ?? '')}</td></tr>`)}</tbody></table>`);
    }
    return portalPage('Not found', html`${portalNavigation(session.csrf)}<p>This page does not exist.</p>`, 404);
  } catch {
    console.error('Administrator portal request failed');
    return portalPage('Server error', html`<p>Unable to complete this request.</p>`, 500);
  }
}
