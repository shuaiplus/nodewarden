import type { Env } from '../types';
import {
  getConfiguredWebVaultOrigins,
  isConfiguredWebVaultOrigin,
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
