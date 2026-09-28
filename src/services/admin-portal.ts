import { and, eq, like, lt, or } from 'drizzle-orm';

import type { AdminPortal, AdminSession, Page } from '../admin/portal-contract';
import { LIMITS } from '../config/limits';
import { getOrm } from '../db/client';
import { organizationMemberships, organizations, verification } from '../db/schema';
import { notifyUserLogout } from '../durable/notifications-hub';
import { isSsoEnabled } from '../handlers/sso';
import type { Env } from '../types';
import { sha256Base64Url } from '../utils/account-passkeys';
import { constantTimeEquals } from '../utils/api-key';
import { getConfiguredWebVaultOrigins } from '../utils/origins';
import { deleteOrganizationAccount, deleteUserAccount, setUserStatus } from './account-deletion';
import {
  ADMIN_COOKIE,
  ADMIN_LOGIN_COOKIE,
  ADMIN_TOKEN_PATTERN,
  adminReturnPath,
  checkPortalRequest,
  createAdminSession,
  issueAdminLogin,
  parseAdminDirectory,
  randomAdminToken,
  readAdminCookie,
  readAdminSession,
  redeemAdminLogin,
} from './admin-portal-auth';
import { auditEventStatement, auditRequestMetadata, writeAuditEvent, type AuditEventInput } from './audit-events';
import { AuthService } from './auth';
import { EMAIL_PATTERN, readMailConfig } from './mail';
import { notifyMail, runInBackground } from './mail-notify';
import { canAccessSecretsManager } from './org-authz';
import { MembershipStatus, MembershipType, publicMembershipStatus } from './org-types';
import { RateLimitService, getClientIdentifier } from './ratelimit';
import { isOpenRegistrationEnabled } from './register-payload';
import * as passkeyRepo from './storage-account-passkey-repo';
import { listAuditLogs } from './storage-admin-repo';
import { countPersonalCiphers } from './storage-cipher-repo';
import * as configRepo from './storage-config-repo';
import * as orgRepo from './storage-org-repo';
import * as userRepo from './storage-user-repo';
import { twoFactorClearStatements, twoFactorProviders } from './two-factor-providers';
import { markEmailVerified } from './vault-admin-role';
import { getYubicoCredentials } from './yubico-config';

const HOUR_SECONDS = 3600;
const PROVIDER_NAMES: Record<number, string> = { 0: 'Authenticator', 1: 'Email', 3: 'YubiKey', 7: 'WebAuthn' };

// Paging for the user and organization lists: page from 1, count within the configured bounds.
function pageParams(query: URLSearchParams): { page: number; count: number } {
  const requestedPage = Number(query.get('page'));
  return {
    page: Number.isFinite(requestedPage) ? Math.max(1, Math.floor(requestedPage)) : 1,
    count: Math.min(
      LIMITS.admin.pageSizeMax,
      Math.max(1, Math.floor(Number(query.get('count')) || LIMITS.admin.pageSizeDefault)),
    ),
  };
}

// Searches fetch one row past the page, so a longer result means a next page exists.
function toPage<Row>(rows: Row[], page: number, count: number): Page<Row> {
  return { rows: rows.slice(0, count), page, count, hasMore: rows.length > count };
}

// The portal's services for one request, handed to the SvelteKit pages as `platform.portal`. Callers
// construct it only when ADMIN_EMAILS is set; a malformed directory leaves `configured` false.
export function adminPortal(env: Env, request: Request): AdminPortal {
  const directory = parseAdminDirectory(env);
  if (directory.kind === 'invalid') console.error('Invalid ADMIN_EMAILS entry', { entryIndex: directory.entryIndex });
  const admins: ReadonlyMap<string, string> = directory.kind === 'enabled' ? directory.admins : new Map();
  const origin = new URL(request.url).origin;
  const audit = (action: string, email?: string) =>
    writeAuditEvent(env.DB, {
      action,
      category: 'security',
      level: 'security',
      actorUserId: null,
      metadata: { ...auditRequestMetadata(request), ...(email ? { adminEmail: email } : {}) },
    });
  const actionAudit = (
    action: string,
    session: AdminSession,
    targetType: 'user' | 'organization',
    targetId: string,
  ): AuditEventInput => ({
    action,
    category: 'security',
    level: 'security',
    actorUserId: null,
    targetType,
    targetId,
    metadata: { adminEmail: session.email, ...auditRequestMetadata(request) },
  });

  return {
    cookies: {
      session: { name: ADMIN_COOKIE, maxAge: LIMITS.admin.sessionTtlSeconds },
      login: { name: ADMIN_LOGIN_COOKIE, maxAge: LIMITS.admin.loginLinkTtlSeconds },
    },
    configured: directory.kind === 'enabled',
    acceptsRequest() {
      const accepted = checkPortalRequest(request);
      if (!accepted) console.warn('Rejected administrator request');
      return accepted;
    },
    readCookie: (name) => readAdminCookie(request, name),
    returnPath: (input) => adminReturnPath(input, origin),
    mailEnabled: () => readMailConfig(env).kind === 'enabled',
    isLoginToken: (token) => ADMIN_TOKEN_PATTERN.test(token),

    async requestLoginLink(input, returnUrl) {
      const email = input.trim().toLowerCase();
      const returnPath = adminReturnPath(returnUrl, origin);
      if (!EMAIL_PATTERN.test(email) || email.length > 256) return { kind: 'invalid-email' };
      const clientId = getClientIdentifier(request);
      if (!clientId) return { kind: 'no-client' };
      const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
        `admin-login-ip:${clientId}`,
        LIMITS.admin.loginRequestsPerIpPerHour,
        HOUR_SECONDS,
      );
      if (!budget.allowed) return { kind: 'throttled', retryAfterSeconds: budget.retryAfterSeconds };
      // A resend from the same browser keeps its nonce, so links sent earlier stay redeemable there.
      const existingNonce = readAdminCookie(request, ADMIN_LOGIN_COOKIE);
      const nonce = ADMIN_TOKEN_PATTERN.test(existingNonce) ? existingNonce : randomAdminToken();
      // Sending in the background keeps the response identical for listed and unlisted addresses.
      runInBackground('admin-login', async () => {
        const stamp = admins.get(email);
        if (stamp && readMailConfig(env).kind === 'enabled')
          await issueAdminLogin(env, request, email, stamp, nonce, returnPath);
      });
      return { kind: 'sent', nonce };
    },

    async redeemLoginLink(token) {
      const value = await redeemAdminLogin(env, token, readAdminCookie(request, ADMIN_LOGIN_COOKIE));
      if (!value) {
        console.warn('Invalid administrator sign-in link');
        return { kind: 'invalid' };
      }
      if (admins.get(value.email) !== value.stampHash) {
        await audit('admin.portal.login.denied');
        return { kind: 'invalid' };
      }
      const session = await createAdminSession(env, value.email, value.stampHash);
      await getOrm(env.DB)
        .delete(verification)
        .where(
          and(
            or(like(verification.identifier, 'admin-login:%'), like(verification.identifier, 'admin-session:%')),
            lt(verification.expiresAt, Date.now()),
          ),
        );
      await audit('admin.portal.login', value.email);
      return { kind: 'signed-in', session, returnPath: adminReturnPath(value.returnPath, origin) };
    },

    async readSession() {
      const { session, denied } = await readAdminSession(request, env, admins);
      if (denied) await audit('admin.portal.login.denied');
      return session;
    },
    csrfMatches: (session, csrf) => typeof csrf === 'string' && constantTimeEquals(csrf, session.csrf),
    async signOut(session) {
      await getOrm(env.DB).delete(verification).where(eq(verification.id, session.id));
      await audit('admin.portal.logout', session.email);
    },

    async checkSensitiveAction(session, confirmation, expected) {
      if (Date.now() - session.authTime > LIMITS.admin.destructiveReauthSeconds * 1000) return { kind: 'reauth' };
      if (confirmation !== expected) return { kind: 'mismatch' };
      const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
        `admin-portal-sensitive:${await sha256Base64Url(session.email)}`,
        LIMITS.admin.sensitiveActionsPerAdminPerHour,
        HOUR_SECONDS,
      );
      return budget.allowed ? { kind: 'allowed' } : { kind: 'throttled', retryAfterSeconds: budget.retryAfterSeconds };
    },

    async dashboard() {
      const mail = readMailConfig(env);
      const [userCount, organizationCount, events, pushId, pushKey, yubico] = await Promise.all([
        userRepo.getUserCount(env.DB),
        getOrm(env.DB).$count(organizations),
        listAuditLogs(env.DB, { actionPrefix: 'admin.portal.', limit: LIMITS.admin.recentAuditEvents, offset: 0 }),
        configRepo.getConfigValue(env.DB, 'push.installation.id'),
        configRepo.getConfigValue(env.DB, 'push.installation.key'),
        getYubicoCredentials(env.DB),
      ]);
      return {
        settings: [
          ['Users', userCount],
          ['Organizations', organizationCount],
          ['Administrators', admins.size],
          ['Compatible server version', LIMITS.compatibility.bitwardenServerVersion],
          ['Mail', mail.kind],
          ['Sender', mail.kind === 'enabled' ? `${mail.from.name} <${mail.from.email}>` : 'Unavailable'],
          ['Open registration', isOpenRegistrationEnabled(env) ? 'Yes' : 'No'],
          ['Vault origins', getConfiguredWebVaultOrigins(env).join(', ') || 'None'],
          ['SSO configured', isSsoEnabled(env) ? 'Yes' : 'No'],
          ['Push relay configured', pushId && pushKey ? 'Yes' : 'No'],
          ['Yubico configured', yubico ? 'Yes' : 'No'],
          ['Disable new-device email', env.DISABLE_EMAIL_NEW_DEVICE || 'false'],
          ['Email sends per hour', env.EMAIL_SENDS_PER_HOUR || '100'],
        ],
        events: events.logs.map((event) => ({
          createdAt: event.createdAt,
          action: event.action,
          adminEmail: String(JSON.parse(event.metadata ?? '{}').adminEmail ?? ''),
        })),
      };
    },

    async searchUsers(query) {
      const { page, count } = pageParams(query);
      const rows = await userRepo.searchUsersByEmailPrefix(env.DB, query.get('email') ?? '', (page - 1) * count, count);
      return toPage(rows, page, count);
    },

    async userDetail(id) {
      const user = await userRepo.getUserById(env.DB, id);
      if (!user) return null;
      const [personalItems, memberships, passkeys] = await Promise.all([
        countPersonalCiphers(env.DB, user.id),
        getOrm(env.DB).$count(organizationMemberships, eq(organizationMemberships.userId, user.id)),
        passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor'),
      ]);
      const providers = twoFactorProviders(user, passkeys > 0);
      return {
        id: user.id,
        email: user.email,
        emailVerified: user.emailVerified,
        status: user.status,
        hasTwoFactor: providers.length > 0,
        verificationGrantsVaultAdmin: admins.has(user.email),
        fields: [
          ['Id', user.id],
          ['Email', user.email],
          ['Email verified', user.emailVerified ? 'Yes' : 'No (registered without an emailed token)'],
          ['Name', user.name ?? ''],
          ['Status', user.status],
          ['Vault role', user.role],
          ['Created', user.createdAt],
          ['Modified', user.updatedAt],
          ['Two-factor', providers.map((provider) => PROVIDER_NAMES[provider]).join(', ') || 'None'],
          ['Personal items', personalItems],
          ['Organization memberships', memberships],
        ],
      };
    },

    async deleteUser(session, id) {
      const outcome = await deleteUserAccount(env, id, actionAudit('admin.portal.user.delete', session, 'user', id));
      if (outcome.kind === 'deleted') return { kind: 'done' };
      if (outcome.kind === 'not-found') return { kind: 'not-found' };
      return {
        kind: 'refused',
        refusal:
          outcome.kind === 'last-vault-admin'
            ? 'Cannot delete the last active instance administrator.'
            : 'Transfer or delete these organizations first: ' + outcome.orgIds.join(', '),
      };
    },

    async setUserStatus(session, id, next) {
      const action = next === 'banned' ? 'admin.portal.user.disable' : 'admin.portal.user.enable';
      const outcome = await setUserStatus(env, id, next, actionAudit(action, session, 'user', id));
      if (outcome.kind === 'updated' || outcome.kind === 'unchanged') return { kind: 'done' };
      if (outcome.kind === 'not-found') return { kind: 'not-found' };
      return { kind: 'refused', refusal: 'Cannot disable the last active instance administrator.' };
    },

    async verifyUserEmail(session, id) {
      await markEmailVerified(env, id);
      await writeAuditEvent(env.DB, actionAudit('admin.portal.user.email_verified', session, 'user', id));
    },

    async resetUserTwoFactor(session, id) {
      const user = await userRepo.getUserById(env.DB, id);
      if (!user) return;
      // The factor wipe, its new stamp and the audit row commit together or not at all.
      await getOrm(env.DB).batch([
        ...twoFactorClearStatements(env.DB, user.id, { recoveryCode: null, securityStamp: crypto.randomUUID() }),
        auditEventStatement(env.DB, actionAudit('admin.portal.user.two_factor.reset', session, 'user', user.id)),
      ]);
      AuthService.invalidateUserCache(user.id);
      notifyUserLogout(env, user.id, null);
      notifyMail(env, user.email, 'twoFactorRecovered', { by: 'administrator' });
    },

    async searchOrganizations(query) {
      const { page, count } = pageParams(query);
      const rows = await orgRepo.searchOrganizations(env.DB, {
        nameContains: query.get('name') ?? '',
        memberEmail: query.get('userEmail') ?? '',
        offset: (page - 1) * count,
        limit: count,
      });
      return toPage(rows, page, count);
    },

    async organizationDetail(id) {
      const org = await orgRepo.getOrganization(env.DB, id);
      if (!org) return null;
      const [members, stats] = await Promise.all([
        orgRepo.listMembershipsWithAccountsByOrg(env.DB, org.id),
        orgRepo.getOrganizationPortalStats(env.DB, org.id),
      ]);
      const statusName = (status: number) =>
        Object.entries(MembershipStatus).find(([, value]) => value === publicMembershipStatus(status))?.[0] ??
        'Unknown';
      return {
        id: org.id,
        name: org.name,
        fields: [
          ['Id', org.id],
          ['Name', org.name],
          ['Created', org.createdAt],
          ['Modified', org.updatedAt],
          ['Billing email', org.billingEmail],
          ['SSO identifier', org.identifier ?? ''],
          ['Has keys', org.privateKey && org.publicKey ? 'Yes' : 'No'],
          ...Object.entries(MembershipStatus)
            .filter(([name]) => name !== 'Staged')
            .map(([name, status]): [string, number] => [
              name,
              members.filter(({ item }) => publicMembershipStatus(item.status) === status).length,
            ]),
          ['SM access', members.filter(({ item }) => canAccessSecretsManager(item)).length],
          ...stats,
        ],
        administrators: members
          .filter(({ item }) => item.type === MembershipType.Owner || item.type === MembershipType.Admin)
          .map(({ item, account }) => ({
            email: account?.email ?? item.email ?? '',
            type: item.type === MembershipType.Owner ? 'Owner' : 'Admin',
            status: statusName(item.status),
          })),
      };
    },

    async deleteOrganization(session, id) {
      await deleteOrganizationAccount(env, id, actionAudit('admin.portal.org.delete', session, 'organization', id));
    },
  };
}
