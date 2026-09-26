import { sha256 } from '@noble/hashes/sha2.js';
import type { Env } from '../types';
import { bytesToBase64Url } from '../utils/passkey';
import { EMAIL_PATTERN } from './mail';
import { isAdminPortalPath } from '../web-vault-visibility';

export type AdminDirectory = { kind: 'disabled' } | { kind: 'invalid'; entryIndex: number }
  | { kind: 'enabled'; admins: ReadonlyMap<string, string> };

export function parseAdminDirectory(env: Pick<Env, 'ADMIN_EMAILS'>): AdminDirectory {
  const entries = (env.ADMIN_EMAILS ?? '').split(',').map((entry) => entry.trim()).filter(Boolean);
  if (!entries.length) return { kind: 'disabled' };
  const admins = new Map<string, string>();
  for (const [entryIndex, entry] of entries.entries()) {
    const colon = entry.indexOf(':');
    const email = (colon < 0 ? entry : entry.slice(0, colon)).toLowerCase();
    const stamp = colon < 0 ? email : entry.slice(colon + 1);
    if (entry.length > 256 || !EMAIL_PATTERN.test(email) || !stamp || /[\s\p{Cc}\p{Cf}]/u.test(stamp) || admins.has(email)) {
      return { kind: 'invalid', entryIndex };
    }
    admins.set(email, bytesToBase64Url(sha256(new TextEncoder().encode(stamp))));
  }
  return { kind: 'enabled', admins };
}

export function checkPortalRequest(request: Request): boolean {
  const mode = request.headers.get('Sec-Fetch-Mode');
  const destination = request.headers.get('Sec-Fetch-Dest');
  if ((mode !== null || destination !== null) && (mode !== 'navigate' || destination !== 'document')) return false;
  if (request.method !== 'POST') return true;
  const origin = request.headers.get('Origin');
  return origin === null ? request.headers.get('Sec-Fetch-Site') === 'same-origin' : origin === new URL(request.url).origin;
}

export function adminReturnPath(input: string, origin: string): string {
  try {
    const url = new URL(input, origin);
    return url.origin === origin && isAdminPortalPath(url.pathname) && !url.pathname.startsWith('/admin/login')
      ? url.pathname + url.search : '/admin';
  } catch { return '/admin'; }
}
