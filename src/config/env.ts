import { z } from 'zod';
import { LIMITS } from './limits';
import type { Env } from '../types';

// Upstream EmailValidation.IsValidEmail: a local part of printable ASCII other than "@", one "@",
// and a dotted host that ends in a letter.
export const EMAIL_PATTERN = /^[\x21-\x3f\x41-\x7e]+@[^\s@,;<>"()\[\]\\]+\.\p{L}+$/u;

export function normalizeOrigin(value: unknown): string | null {
  const raw = String(value || '').trim();
  if (!raw) return null;

  try {
    const url = new URL(raw);
    if (!url.protocol || !url.host) return null;
    return `${url.protocol}//${url.host}`;
  } catch {
    return null;
  }
}

// Every field falls back instead of failing: a malformed optional variable degrades its feature, never the Worker.
const text = z.string().trim().catch('');
const optionalText = z.coerce.string().optional();
// These switches have only ever accepted a literal "1"; "true" and friends keep them off.
const enabledByOne = z.coerce.string().trim().pipe(z.stringbool({ truthy: ['1'], falsy: [] })).catch(false);
const originList = z.string().catch('').transform((list) => [...new Set(list.split(',').map(normalizeOrigin).filter((origin) => origin !== null))]);

export const EnvConfig = z.object({
  JWT_SECRET: text.transform((secret) => secret.length >= LIMITS.auth.jwtSecretMinLength
    ? { kind: 'safe' as const, secret }
    : { kind: secret ? 'too_short' as const : 'missing' as const }),
  ALLOW_OPEN_REGISTRATION: enabledByOne,
  WEB_VAULT_ORIGINS: originList,
  WEBAUTHN_ALLOWED_ORIGINS: originList,
  ADMIN_EMAILS: z.string().catch('').transform((list) => list.split(',').map((entry) => entry.trim()).filter(Boolean)),
  SSO_ENABLED: enabledByOne,
  SSO_ONLY: enabledByOne,
  // Only an exact "0" turns SSO signups off.
  SSO_SIGNUPS: z.stringbool({ truthy: [], falsy: ['0'] }).catch(true),
  SSO_AUTHORITY: z.string().catch('').transform((authority) => authority.replace(/\/+$/, '')),
  SSO_CLIENT_ID: optionalText,
  SSO_CLIENT_SECRET: optionalText,
  SSO_SCOPES: z.string().min(1).catch('openid profile email'),
  R2_ACCOUNT_ID: text,
  R2_ACCESS_KEY_ID: text,
  R2_SECRET_ACCESS_KEY: text,
  R2_BUCKET: z.string().trim().min(1).catch('nodewarden-attachments'),
});
export type EnvConfig = z.output<typeof EnvConfig>;

export function readEnvConfig(env: Partial<Env>): EnvConfig {
  return EnvConfig.parse(env);
}

const newDeviceFlag = z.stringbool({ truthy: ['1', 'true'], falsy: ['0', 'false'] }).default(false);

// Parsed only when the EMAIL binding exists; the first failing field marks mail misconfigured.
export const MailSettings = z.object({
  EMAIL_FROM: z.string().trim().max(256).regex(EMAIL_PATTERN),
  EMAIL_FROM_NAME: z.string().regex(/^[^\p{Cc}\p{Cf}\u2028\u2029]*$/u).optional().transform((name) => name?.trim() || 'NodeWarden'),
  EMAIL_SENDS_PER_HOUR: z.string().regex(/^[1-9][0-9]*$/).transform(Number).refine(Number.isSafeInteger).default(LIMITS.mail.instanceSendsPerHour),
  DISABLE_EMAIL_NEW_DEVICE: newDeviceFlag,
  // A bad verification flag only switches verification off, so it logs instead of failing mail.
  ENABLE_NEW_DEVICE_VERIFICATION: newDeviceFlag.catch(() => {
    console.error('mail', { field: 'ENABLE_NEW_DEVICE_VERIFICATION' });
    return false;
  }),
});
