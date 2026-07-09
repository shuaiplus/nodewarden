import type { Env } from '../types';

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

export function isBrowserExtensionOrigin(origin: unknown): boolean {
  const normalized = normalizeOrigin(origin);
  return !!normalized && (
    normalized.startsWith('chrome-extension://')
    || normalized.startsWith('moz-extension://')
    || normalized.startsWith('safari-web-extension://')
  );
}

export function getConfiguredWebAuthnAllowedOrigins(
  env: Pick<Env, 'WEBAUTHN_ALLOWED_ORIGINS'>
): string[] {
  const seen = new Set<string>();
  for (const item of String(env.WEBAUTHN_ALLOWED_ORIGINS || '').split(',')) {
    const origin = normalizeOrigin(item);
    if (origin) seen.add(origin);
  }
  return Array.from(seen);
}

export function isConfiguredWebAuthnAllowedOrigin(
  env: Pick<Env, 'WEBAUTHN_ALLOWED_ORIGINS'>,
  origin: unknown
): boolean {
  const normalized = normalizeOrigin(origin);
  return !!normalized && getConfiguredWebAuthnAllowedOrigins(env).includes(normalized);
}
