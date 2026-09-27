import { LIMITS } from '../config/limits';
import { EMAIL_PATTERN } from '../config/env';
import { RateLimitService } from './ratelimit';
import { sha256Base64Url } from '../utils/account-passkeys';
import type { Env } from '../types';
import { MAIL_TEMPLATES, renderMail, type TemplateName, type TemplateModel, type MailContent } from './mail-templates';
import {
  getConfiguredWebVaultOrigins,
  isConfiguredWebVaultOrigin,
  normalizeOrigin,
} from '../utils/origins';

// RFC 2606 / 6761 names. Sending to these bounces and hurts sender reputation.
const RESERVED_EMAIL_HOSTS = new Set(['example.com', 'example.net', 'example.org']);
const RESERVED_EMAIL_TLDS = new Set(['test', 'invalid', 'localhost', 'example']);

export interface SendEmailBinding {
  send(message: { to: string; from: { email: string; name: string }; subject: string;
    text: string; html: string; headers?: Record<string, string> }): Promise<{ messageId: string }>;
}
export { EMAIL_PATTERN };
export type MailConfig = { kind: 'disabled' } | { kind: 'misconfigured' }
  | { kind: 'enabled'; binding: SendEmailBinding; from: { email: string; name: string }; sendsPerHour: number; newDeviceNotices: boolean; newDeviceVerification: boolean };
export type MailOutcome = { kind: 'sent' } | { kind: 'disabled' } | { kind: 'misconfigured' }
  | { kind: 'throttled'; retryAfterSeconds: number } | { kind: 'failed'; code: string };
export type StatusCheck = { ok: true } | { ok: false; status: number; message: string; headers: Record<string, string> };

export function readMailConfig(env: Pick<Env, 'EMAIL' | 'EMAIL_FROM' | 'EMAIL_FROM_NAME' | 'EMAIL_SENDS_PER_HOUR' | 'DISABLE_EMAIL_NEW_DEVICE' | 'ENABLE_NEW_DEVICE_VERIFICATION'>): MailConfig {
  if (!env.EMAIL) return { kind: 'disabled' };
  const email = (env.EMAIL_FROM ?? '').trim();
  const name = env.EMAIL_FROM_NAME?.trim() || 'NodeWarden';
  const sendsPerHour = env.EMAIL_SENDS_PER_HOUR === undefined ? LIMITS.mail.instanceSendsPerHour : Number(env.EMAIL_SENDS_PER_HOUR);
  const field = !EMAIL_PATTERN.test(email) || email.length > 256 ? 'EMAIL_FROM'
    : /[\p{Cc}\p{Cf}\u2028\u2029]/u.test(env.EMAIL_FROM_NAME ?? '') ? 'EMAIL_FROM_NAME' : env.EMAIL_SENDS_PER_HOUR !== undefined && (!/^[1-9][0-9]*$/.test(env.EMAIL_SENDS_PER_HOUR) || !Number.isSafeInteger(sendsPerHour)) ? 'EMAIL_SENDS_PER_HOUR' : null;
  if (field) { console.error('mail', { field }); return { kind: 'misconfigured' }; }
  const disableNewDevice = env.DISABLE_EMAIL_NEW_DEVICE?.toLowerCase() ?? 'false';
  const validNewDevice = ['0', '1', 'true', 'false'].includes(disableNewDevice);
  if (!validNewDevice) { console.error('mail', { field: 'DISABLE_EMAIL_NEW_DEVICE' }); return { kind: 'misconfigured' }; }
  const verifyNewDevice = env.ENABLE_NEW_DEVICE_VERIFICATION?.toLowerCase() ?? 'false';
  const validVerification = ['0', '1', 'true', 'false'].includes(verifyNewDevice);
  if (!validVerification) console.error('mail', { field: 'ENABLE_NEW_DEVICE_VERIFICATION' });
  return { kind: 'enabled', binding: env.EMAIL, from: { email, name }, sendsPerHour,
    newDeviceNotices: ['0', 'false'].includes(disableNewDevice), newDeviceVerification: validVerification && ['1', 'true'].includes(verifyNewDevice) };
}

export async function sendMail<N extends TemplateName>(env: Env, to: string, name: N, model: TemplateModel<N>): Promise<MailOutcome> {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled') return config;
  const log = (outcome: MailOutcome) => {
    console.warn('mail', { template: name, outcome: outcome.kind, code: outcome.kind === 'failed' ? outcome.code : undefined, recipientDomain: emailHost(to) });
    return outcome;
  };
  if (!EMAIL_PATTERN.test(to) || to.length > 256) return log({ kind: 'failed', code: 'E_NODEWARDEN_RECIPIENT' });
  if (isReservedDocumentationEmail(to)) { log({ kind: 'sent' }); return { kind: 'sent' }; }
  try {
    if (MAIL_TEMPLATES[name].throttle === 'user') {
      const limiter = new RateLimitService(env);
      const instance = await limiter.consumeStrictBudgetWithWindow('mail-instance', config.sendsPerHour, 3600);
      if (!instance.allowed) return log({ kind: 'throttled', retryAfterSeconds: instance.retryAfterSeconds ?? 3600 });
      const recipient = await limiter.consumeStrictBudgetWithWindow(`mail-rcpt:${await sha256Base64Url(to.toLowerCase())}`, LIMITS.mail.perRecipientPerHour, 3600);
      if (!recipient.allowed) return log({ kind: 'throttled', retryAfterSeconds: recipient.retryAfterSeconds ?? 3600 });
    }
    const render = MAIL_TEMPLATES[name].render as (model: TemplateModel<N>) => MailContent;
    await config.binding.send({ to, from: config.from, ...renderMail(render(model)), headers: { 'Auto-Submitted': 'auto-generated' } });
    return { kind: 'sent' };
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' && /^E_[A-Z_]+$/.test(error.code) ? error.code : 'E_NODEWARDEN_SEND';
    return log({ kind: 'failed', code });
  }
}

export function mailStatusCheck(outcome: MailOutcome): StatusCheck {
  switch (outcome.kind) {
    case 'sent': case 'disabled': return { ok: true };
    case 'misconfigured': return { ok: false, status: 503, message: 'Email sending is not configured', headers: {} };
    case 'failed': return { ok: false, status: 502, message: 'Unable to send email', headers: {} };
    case 'throttled': return { ok: false, status: 429, message: 'Email sending limit reached. Try again later.', headers: { 'Retry-After': String(outcome.retryAfterSeconds) } };
    default: { const exhaustive: never = outcome; return exhaustive; }
  }
}

export function emailHost(email: string): string {
  const at = email.lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1).trim().toLowerCase() : '';
}

export function isReservedDocumentationEmail(email: string): boolean {
  const host = emailHost(email);
  if (!host) return true;
  if (RESERVED_EMAIL_HOSTS.has(host)) return true;
  const tld = host.split('.').pop() || '';
  return RESERVED_EMAIL_TLDS.has(tld);
}

export function registerVerifyVaultOrigin(request: Request, env: Pick<Env, 'WEB_VAULT_ORIGINS'>): string {
  const originHeader = request.headers.get('Origin');
  if (isConfiguredWebVaultOrigin(env, originHeader)) return String(originHeader).replace(/\/+$/, '');
  return getConfiguredWebVaultOrigins(env)[0] || new URL(request.url).origin;
}

// Any org admin picks the invite recipients and the mail comes from EMAIL_FROM, so its link only
// ever points at a configured web vault (upstream BaseServiceUri.VaultWithHash). Falling back to
// the caller-controlled X-Forwarded-Host would make the instance a phishing relay.
export function configuredVaultOrigin(request: Request, env: Pick<Env, 'WEB_VAULT_ORIGINS'>): string | null {
  const configured = getConfiguredWebVaultOrigins(env);
  const requested = normalizeOrigin(request.headers.get('Origin'));
  return configured.find((origin) => origin === requested) ?? configured[0] ?? null;
}

// Official web redirect-connector turns the fragment into /#/finish-signup?...
export function buildRegisterVerifyUrl(vaultOrigin: string, email: string, token: string): string {
  const origin = vaultOrigin.replace(/\/+$/, '');
  const params = new URLSearchParams({
    token,
    email,
    fromEmail: 'true',
  });
  return `${origin}/redirect-connector.html#finish-signup?${params.toString()}`;
}

// .NET's \w matches any Unicode letter, so an IDN like "evil.éxample" is defused too.
const EMAIL_DOT_PATTERN = /\.([\p{L}\p{N}_])/gu;
const EMAIL_SCHEME_PATTERN = /(^|\b)\w*:\/\//gi;

// Upstream CoreHelpers.SanitizeForEmail. Text another user chose (an org name) goes out from
// EMAIL_FROM, so it must not carry anything a mail client would turn into a link or address.
// Schemes are stripped until none remain because removing one can join the text around it into
// another ("https:x:////" leaves "https://").
export function sanitizeForEmail(value: string): string {
  const stripSchemes = (text: string): string => {
    const stripped = text.replace(EMAIL_SCHEME_PATTERN, '');
    return stripped === text ? text : stripSchemes(stripped);
  };
  return stripSchemes(value.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ').replace(/@/g, '[at]').replace(EMAIL_DOT_PATTERN, '[dot]$1')).replace(/\s+/g, ' ').trim();
}

export interface OrganizationInvite {
  vaultOrigin: string;
  organizationId: string;
  organizationUserId: string;
  organizationName: string;
  email: string;
  token: string;
  hasExistingUser: boolean;
  inviterEmail?: string;
  expiresAt: string;
}

// Upstream OrganizationUserInvitedViewModel.Url. Official web's /#/accept-organization route
// requires every param (DirectOrganizationInvite.fromUrlParams) and sends existing users to
// login instead of signup.
export function buildOrganizationInviteUrl(invite: OrganizationInvite): string {
  const params = new URLSearchParams({
    organizationId: invite.organizationId,
    organizationUserId: invite.organizationUserId,
    email: invite.email,
    organizationName: invite.organizationName,
    token: invite.token,
    initOrganization: 'false',
    orgUserHasExistingUser: String(invite.hasExistingUser),
  });
  return `${invite.vaultOrigin.replace(/\/+$/, '')}/#/accept-organization?${params.toString()}`;
}
