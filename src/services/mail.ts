import type { Env } from '../types';
import { ORG_INVITE_TTL_DAYS } from '../utils/jwt';
import {
  getConfiguredWebVaultOrigins,
  isConfiguredWebVaultOrigin,
  normalizeOrigin,
  requestPublicOrigin,
} from '../utils/origins';

// RFC 2606 / 6761 names. Sending to these bounces and hurts sender reputation.
const RESERVED_EMAIL_HOSTS = new Set(['example.com', 'example.net', 'example.org']);
const RESERVED_EMAIL_TLDS = new Set(['test', 'invalid', 'localhost', 'example']);

export interface EmailAddress {
  email: string;
  name?: string;
}

export interface SendEmailMessage {
  to: string | EmailAddress | Array<string | EmailAddress>;
  from: string | EmailAddress;
  subject: string;
  html?: string;
  text?: string;
  replyTo?: string | EmailAddress;
}

export interface SendEmailBinding {
  send(message: SendEmailMessage): Promise<{ messageId: string }>;
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

export function getEmailSender(env: Pick<Env, 'EMAIL_FROM' | 'EMAIL_FROM_NAME'>): EmailAddress | null {
  const email = String(env.EMAIL_FROM || '').trim();
  if (!email || !email.includes('@')) return null;
  const name = String(env.EMAIL_FROM_NAME || 'NodeWarden').trim() || 'NodeWarden';
  return { email, name };
}

export function registerVerifyVaultOrigin(request: Request, env: Pick<Env, 'WEB_VAULT_ORIGINS'>): string {
  const originHeader = request.headers.get('Origin');
  if (isConfiguredWebVaultOrigin(env, originHeader)) return String(originHeader).replace(/\/+$/, '');
  const forwarded = requestPublicOrigin(request);
  if (isConfiguredWebVaultOrigin(env, forwarded)) return forwarded;
  return getConfiguredWebVaultOrigins(env)[0] || forwarded;
}

// Any org admin picks the invite recipients and the mail comes from EMAIL_FROM, so its link only
// ever points at a configured web vault (upstream BaseServiceUri.VaultWithHash). Falling back to
// the caller-controlled X-Forwarded-Host would make the instance a phishing relay.
export function organizationInviteVaultOrigin(request: Request, env: Pick<Env, 'WEB_VAULT_ORIGINS'>): string | null {
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

export function buildRegisterVerificationEmail(vaultOrigin: string, email: string, token: string): {
  subject: string;
  text: string;
  html: string;
} {
  const verifyUrl = buildRegisterVerifyUrl(vaultOrigin, email, token);
  const subject = 'Verify your NodeWarden email';
  const text = [
    'Verify your email to finish creating your NodeWarden account.',
    '',
    verifyUrl,
    '',
    'This link expires in 30 minutes. If you did not request an account, ignore this email.',
  ].join('\n');
  const html = [
    '<p>Verify your email to finish creating your NodeWarden account.</p>',
    `<p><a href="${verifyUrl}">Verify email</a></p>`,
    '<p>This link expires in 30 minutes. If you did not request an account, ignore this email.</p>',
  ].join('');
  return { subject, text, html };
}

export async function sendRegisterVerificationEmail(
  env: Pick<Env, 'EMAIL' | 'EMAIL_FROM' | 'EMAIL_FROM_NAME'>,
  to: string,
  vaultOrigin: string,
  token: string
): Promise<void> {
  const sender = getEmailSender(env);
  if (!env.EMAIL || !sender) {
    throw new Error('Email sending is not configured');
  }
  const body = buildRegisterVerificationEmail(vaultOrigin, to, token);
  await env.EMAIL.send({
    to,
    from: sender,
    subject: body.subject,
    text: body.text,
    html: body.html,
  });
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
  return stripSchemes(value.replace(/@/g, '[at]').replace(EMAIL_DOT_PATTERN, '[dot]$1'));
}

export interface OrganizationInvite {
  vaultOrigin: string;
  organizationId: string;
  organizationUserId: string;
  organizationName: string;
  email: string;
  token: string;
  hasExistingUser: boolean;
}

// Upstream OrganizationUserInvitedViewModel.Url. Official web's /#/accept-organization route
// requires every param (DirectOrganizationInvite.fromUrlParams) and sends existing users to
// login instead of signup.
function buildOrganizationInviteUrl(invite: OrganizationInvite): string {
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

export async function sendOrganizationInviteEmail(
  env: Pick<Env, 'EMAIL' | 'EMAIL_FROM' | 'EMAIL_FROM_NAME'>,
  invite: OrganizationInvite
): Promise<void> {
  const sender = getEmailSender(env);
  if (!env.EMAIL || !sender) {
    throw new Error('Email sending is not configured');
  }
  // Text only: the organization name is chosen by the inviting admin, so it never reaches HTML.
  // The link keeps the raw name, URL-encoded, because official web displays it on the accept page.
  const organizationName = sanitizeForEmail(invite.organizationName);
  await env.EMAIL.send({
    to: invite.email,
    from: sender,
    subject: `Join ${organizationName}`,
    text: [
      `You have been invited to join the ${organizationName} organization.`,
      '',
      buildOrganizationInviteUrl(invite),
      '',
      `This link expires in ${ORG_INVITE_TTL_DAYS} days.`,
    ].join('\n'),
  });
}
