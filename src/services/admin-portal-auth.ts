import { LIMITS } from '../config/limits';
import { sha256Base64Url } from '../utils/account-passkeys';
import { toSafeUrl } from '../utils/html';
import { RateLimitService } from './ratelimit';
import { sendMail } from './mail';
import { sha256 } from '@noble/hashes/sha2.js';
import type { Env } from '../types';
import { bytesToBase64Url } from '../utils/passkey';
import { EMAIL_PATTERN } from './mail';
import { isAdminPortalPath } from '../web-vault-visibility';
import { parse, serialize } from 'hono/utils/cookie';

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

export const ADMIN_COOKIE = '__Host-nw_admin';
export const ADMIN_LOGIN_COOKIE = '__Host-nw_admin_login';
export const ADMIN_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
export type AdminSession = { email: string; stampHash: string; authTime: number; id: string; token: string; csrf: string };
export function adminCookie(name: string, token = '', seconds = 0): string {
  return serialize(name, token, { path: '/', httpOnly: true, secure: true, sameSite: 'Strict', maxAge: seconds });
}
export function readAdminCookie(request: Request, name: string): string {
  const cookie = request.headers.get('Cookie') ?? '';
  // A repeated name means another cookie is shadowing ours, so neither copy is trusted.
  return cookie.split(';').filter((part) => part.trim().startsWith(`${name}=`)).length === 1 ? parse(cookie, name)[name] ?? '' : '';
}
export function randomAdminToken(): string { return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32))); }

export async function createAdminSession(env: Env, email: string, stampHash: string): Promise<AdminSession> {
  const token = randomAdminToken();
  const authTime = Date.now();
  const id = `admin-session:${await sha256Base64Url(token)}`;
  await env.DB.prepare('INSERT INTO verification (id,identifier,value,expires_at,created_at,updated_at) VALUES (?,?,?,?,?,?)')
    .bind(id, id, JSON.stringify({ email, stampHash, authTime }), authTime + LIMITS.admin.sessionTtlSeconds * 1000, authTime, authTime).run();
  return { email, stampHash, authTime, id, token, csrf: await sha256Base64Url(`admin-csrf:${token}`) };
}

export async function readAdminSession(request: Request, env: Env, admins: ReadonlyMap<string, string>): Promise<{ session: AdminSession | null; denied: boolean }> {
  const token = readAdminCookie(request, ADMIN_COOKIE);
  if (!ADMIN_TOKEN_PATTERN.test(token)) return { session: null, denied: false };
  const id = `admin-session:${await sha256Base64Url(token)}`;
  const row = await env.DB.prepare('SELECT value, expires_at FROM verification WHERE id=?').bind(id).first<{ value: string; expires_at: number }>();
  if (!row || row.expires_at <= Date.now()) return { session: null, denied: false };
  const value = JSON.parse(row.value) as { email: string; stampHash: string; authTime: number };
  if (admins.get(value.email) !== value.stampHash) return { session: null, denied: true };
  return { session: { ...value, token, id, csrf: await sha256Base64Url(`admin-csrf:${token}`) }, denied: false };
}

export async function issueAdminLogin(env: Env, request: Request, email: string, stampHash: string, browser: string, returnPath: string): Promise<void> {
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(`admin-login-email:${await sha256Base64Url(email)}`, LIMITS.admin.loginLinksPerAdminPerWindow, LIMITS.admin.loginLinkTtlSeconds);
  if (!budget.allowed) { console.warn('Administrator link budget exhausted'); return; }
  const token = randomAdminToken();
  const id = `admin-login:${await sha256Base64Url(token)}`;
  const now = Date.now();
  await env.DB.prepare('INSERT INTO verification (id,identifier,value,expires_at,created_at,updated_at) VALUES (?,?,?,?,?,?)')
    .bind(id, id, JSON.stringify({ email, stampHash, returnPath, browser: await sha256Base64Url(browser) }), now + LIMITS.admin.loginLinkTtlSeconds * 1000, now, now).run();
  await sendMail(env, email, 'adminSignIn', { url: toSafeUrl(new URL(`/admin/login/confirm?token=${token}`, new URL(request.url).origin)) });
}

export async function redeemAdminLogin(env: Env, token: string, browser: string): Promise<{ email: string; stampHash: string; returnPath: string } | null> {
  if (!ADMIN_TOKEN_PATTERN.test(token) || !ADMIN_TOKEN_PATTERN.test(browser)) return null;
  const row = await env.DB.prepare("DELETE FROM verification WHERE id=? AND expires_at>? AND json_extract(value,'$.browser')=? RETURNING value")
    .bind(`admin-login:${await sha256Base64Url(token)}`, Date.now(), await sha256Base64Url(browser)).first<{ value: string }>();
  return row ? JSON.parse(row.value) : null;
}
