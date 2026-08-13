import { and, eq, isNull, lt, or, sql } from 'drizzle-orm';

import { LIMITS } from '../config/limits';
import { getOrm } from '../db/client';
import { loginAttemptsIp, rateLimitBuckets } from '../db/schema';

// Rate limiting service.
// - Login attempts: D1-backed (low volume, security-critical, needs cross-colo persistence).
// - API budgets: Cloudflare Cache API (high volume, auto-expires, zero D1 writes).
// - Strict budgets: D1-backed fixed windows for low-volume anonymous sensitive endpoints.

const CONFIG = {
  LOGIN_MAX_ATTEMPTS: LIMITS.rateLimit.loginMaxAttempts,
  LOGIN_LOCKOUT_MINUTES: LIMITS.rateLimit.loginLockoutMinutes,
  API_WINDOW_SECONDS: LIMITS.rateLimit.apiWindowSeconds,
};

export class RateLimitService {
  private static lastLoginIpCleanupAt = 0;
  private static lastStrictBudgetCleanupAt = 0;

  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.rateLimit.cleanupProbability;
  private static readonly LOGIN_IP_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;
  private static readonly LOGIN_IP_RETENTION_MS = LIMITS.rateLimit.loginIpRetentionMs;
  private static readonly STRICT_BUDGET_CLEANUP_INTERVAL_MS = LIMITS.rateLimit.loginIpCleanupIntervalMs;

  constructor(private db: D1Database) {}

  private shouldRunCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < RateLimitService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupLoginAttemptsIp(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastLoginIpCleanupAt, RateLimitService.LOGIN_IP_CLEANUP_INTERVAL_MS)) {
      return;
    }

    const cutoff = nowMs - RateLimitService.LOGIN_IP_RETENTION_MS;
    await getOrm(this.db)
      .delete(loginAttemptsIp)
      .where(and(
        lt(loginAttemptsIp.updatedAt, cutoff),
        or(isNull(loginAttemptsIp.lockedUntil), lt(loginAttemptsIp.lockedUntil, nowMs)),
      ));
    RateLimitService.lastLoginIpCleanupAt = nowMs;
  }

  private async maybeCleanupStrictBudgets(nowMs: number): Promise<void> {
    if (!this.shouldRunCleanup(RateLimitService.lastStrictBudgetCleanupAt, RateLimitService.STRICT_BUDGET_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await getOrm(this.db).delete(rateLimitBuckets).where(lt(rateLimitBuckets.expiresAt, nowMs));
    RateLimitService.lastStrictBudgetCleanupAt = nowMs;
  }

  async checkLoginAttempt(ip: string): Promise<{
    allowed: boolean;
    remainingAttempts: number;
    retryAfterSeconds?: number;
  }> {
    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);

    const [row] = await getOrm(this.db)
      .select({ attempts: loginAttemptsIp.attempts, lockedUntil: loginAttemptsIp.lockedUntil })
      .from(loginAttemptsIp)
      .where(eq(loginAttemptsIp.ip, key))
      .limit(1);

    if (!row) {
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    if (row.lockedUntil && row.lockedUntil > now) {
      return {
        allowed: false,
        remainingAttempts: 0,
        retryAfterSeconds: Math.ceil((row.lockedUntil - now) / 1000),
      };
    }

    if (row.lockedUntil && row.lockedUntil <= now) {
      await getOrm(this.db).delete(loginAttemptsIp).where(eq(loginAttemptsIp.ip, key));
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    const remainingAttempts = Math.max(0, CONFIG.LOGIN_MAX_ATTEMPTS - (row.attempts || 0));
    return { allowed: true, remainingAttempts };
  }

  async recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds?: number }> {
    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);
    const orm = getOrm(this.db);

    // D1 in Workers forbids raw BEGIN/COMMIT statements.
    // Use a single atomic UPSERT to increment attempts.
    // This is concurrency-safe because the row is keyed by IP.
    await orm
      .insert(loginAttemptsIp)
      .values({ ip: key, attempts: 1, lockedUntil: null, updatedAt: now })
      .onConflictDoUpdate({
        target: loginAttemptsIp.ip,
        set: {
          attempts: sql`${loginAttemptsIp.attempts} + 1`,
          updatedAt: now,
        },
      });

    const [row] = await orm
      .select({ attempts: loginAttemptsIp.attempts })
      .from(loginAttemptsIp)
      .where(eq(loginAttemptsIp.ip, key))
      .limit(1);

    const attempts = row?.attempts || 1;
    if (attempts >= CONFIG.LOGIN_MAX_ATTEMPTS) {
      const lockedUntil = now + CONFIG.LOGIN_LOCKOUT_MINUTES * 60 * 1000;
      await orm
        .update(loginAttemptsIp)
        .set({ lockedUntil, updatedAt: now })
        .where(eq(loginAttemptsIp.ip, key));
      return { locked: true, retryAfterSeconds: CONFIG.LOGIN_LOCKOUT_MINUTES * 60 };
    }

    return { locked: false };
  }

  async clearLoginAttempts(ip: string): Promise<void> {
    const key = ip.trim() || 'unknown';
    await getOrm(this.db).delete(loginAttemptsIp).where(eq(loginAttemptsIp.ip, key));
  }

  // Cache API-backed fixed-window rate limiter.
  // Uses Cloudflare edge cache instead of D1 — zero database writes, auto-expires via TTL.
  // Per-colo isolation is acceptable (matches Cloudflare's own rate limiting behaviour).
  private async consumeFixedWindowBudget(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    const nowSec = Math.floor(Date.now() / 1000);
    const windowStart = nowSec - (nowSec % windowSeconds);
    const windowEnd = windowStart + windowSeconds;
    const ttl = Math.max(1, windowEnd - nowSec);

    const cache = await caches.open('rate-limit');
    const cacheKey = new Request(`https://rl/${identifier}/${windowStart}`);

    const cached = await cache.match(cacheKey);
    let count = 0;
    if (cached) {
      count = parseInt(await cached.text(), 10) || 0;
    }

    if (count >= maxRequests) {
      return { allowed: false, remaining: 0, retryAfterSeconds: ttl };
    }

    count++;
    await cache.put(
      cacheKey,
      new Response(String(count), {
        headers: { 'Cache-Control': `public, max-age=${ttl}` },
      })
    );

    return { allowed: true, remaining: Math.max(0, maxRequests - count) };
  }

  async consumeStrictBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeStrictBudgetWithWindow(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeStrictBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    const key = String(identifier || '').trim() || 'unknown';
    const max = Math.max(1, Math.floor(maxRequests));
    const windowSize = Math.max(1, Math.floor(windowSeconds));
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const windowStart = nowSec - (nowSec % windowSize);
    const windowEndMs = (windowStart + windowSize) * 1000;
    const retryAfterSeconds = Math.max(1, Math.ceil((windowEndMs - nowMs) / 1000));
    const bucketKey = `${key}:${windowStart}`;
    const orm = getOrm(this.db);

    await this.maybeCleanupStrictBudgets(nowMs);
    await orm
      .insert(rateLimitBuckets)
      .values({ bucketKey, count: 0, expiresAt: windowEndMs, updatedAt: nowMs })
      .onConflictDoNothing({ target: rateLimitBuckets.bucketKey });

    const update = await orm
      .update(rateLimitBuckets)
      .set({
        count: sql`${rateLimitBuckets.count} + 1`,
        expiresAt: windowEndMs,
        updatedAt: nowMs,
      })
      .where(and(eq(rateLimitBuckets.bucketKey, bucketKey), sql`${rateLimitBuckets.count} < ${max}`))
      .run();

    const allowed = Number(update.meta?.changes ?? 0) > 0;
    const [row] = await orm
      .select({ count: rateLimitBuckets.count })
      .from(rateLimitBuckets)
      .where(eq(rateLimitBuckets.bucketKey, bucketKey))
      .limit(1);
    const count = Math.max(0, Number(row?.count || 0));

    if (!allowed) {
      return { allowed: false, remaining: 0, retryAfterSeconds };
    }
    return { allowed: true, remaining: Math.max(0, max - count) };
  }

  // General-purpose fixed-window budget.
  // Callers supply an identifier (must be unique per rate-limit category) and the
  // per-window maximum.  This single method replaces all previous specialised
  // budget helpers (write / sync / knownDevice / publicSend).
  async consumeBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  async consumeBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeFixedWindowBudget(identifier, maxRequests, windowSeconds);
  }
}

function parseIpv4Octets(input: string): number[] | null {
  const parts = input.split('.');
  if (parts.length !== 4) return null;

  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number(part);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    octets.push(value);
  }
  return octets;
}

function parseIpv6Hextets(input: string): number[] | null {
  let value = input.trim().toLowerCase();
  if (!value) return null;

  if (value.startsWith('[') && value.endsWith(']')) {
    value = value.slice(1, -1);
  }
  const zoneIndex = value.indexOf('%');
  if (zoneIndex >= 0) {
    value = value.slice(0, zoneIndex);
  }
  if (!value.includes(':')) return null;

  // Handle IPv4-mapped tail (e.g. ::ffff:192.0.2.1).
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const ipv4Tail = value.slice(lastColon + 1);
    const octets = parseIpv4Octets(ipv4Tail);
    if (!octets) return null;
    const high = ((octets[0] << 8) | octets[1]).toString(16);
    const low = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${value.slice(0, lastColon)}:${high}:${low}`;
  }

  const doubleColon = value.indexOf('::');
  if (doubleColon !== value.lastIndexOf('::')) return null;

  const parsePart = (part: string): number | null => {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    const n = parseInt(part, 16);
    return Number.isNaN(n) ? null : n;
  };

  const parseParts = (parts: string[]): number[] | null => {
    const out: number[] = [];
    for (const p of parts) {
      if (!p) return null;
      const n = parsePart(p);
      if (n === null) return null;
      out.push(n);
    }
    return out;
  };

  if (doubleColon >= 0) {
    const [headRaw, tailRaw] = value.split('::');
    const head = headRaw ? headRaw.split(':') : [];
    const tail = tailRaw ? tailRaw.split(':') : [];

    const headNums = parseParts(head);
    const tailNums = parseParts(tail);
    if (!headNums || !tailNums) return null;

    const missing = 8 - (headNums.length + tailNums.length);
    if (missing < 1) return null;

    return [...headNums, ...new Array<number>(missing).fill(0), ...tailNums];
  }

  const all = parseParts(value.split(':'));
  if (!all || all.length !== 8) return null;
  return all;
}

function normalizeClientIpForRateLimit(rawIp: string): string | null {
  const input = rawIp.trim();
  if (!input) return null;

  const ipv4 = parseIpv4Octets(input);
  if (ipv4) {
    return `ip4:${ipv4.join('.')}`;
  }

  const ipv6 = parseIpv6Hextets(input);
  if (!ipv6) return null;

  // Handle IPv4-mapped / IPv4-compatible IPv6 as IPv4 identity.
  // Examples: ::ffff:192.0.2.1, ::192.0.2.1
  if (
    ipv6[0] === 0 &&
    ipv6[1] === 0 &&
    ipv6[2] === 0 &&
    ipv6[3] === 0 &&
    ipv6[4] === 0 &&
    (ipv6[5] === 0xffff || ipv6[5] === 0)
  ) {
    const octets = [ipv6[6] >> 8, ipv6[6] & 0xff, ipv6[7] >> 8, ipv6[7] & 0xff];
    return `ip4:${octets.join('.')}`;
  }

  // Collapse to /64 to reduce brute-force bypass via IPv6 address rotation.
  const prefix64 = ipv6
    .slice(0, 4)
    .map(part => part.toString(16).padStart(4, '0'))
    .join(':');
  return `ip6:${prefix64}`;
}

function isLocalRequest(request: Request): boolean {
  const isLoopbackHost = (host: string | null): boolean => {
    if (!host) return false;
    const normalized = host.split(':')[0].trim().toLowerCase();
    return (
      normalized === 'localhost' ||
      normalized.endsWith('.localhost') ||
      normalized === '127.0.0.1' ||
      normalized === '0.0.0.0' ||
      normalized === '::1' ||
      normalized === '[::1]'
    );
  };

  try {
    if (isLoopbackHost(new URL(request.url).hostname)) return true;
  } catch {
    // Ignore malformed URL and fall back to Host header check.
  }

  return isLoopbackHost(request.headers.get('Host'));
}

export function getClientIdentifier(request: Request): string | null {
  // Strict fallback order:
  // 1) CF-Connecting-IP
  // 2) X-Real-IP
  // 3) first item of X-Forwarded-For
  // If none are present/valid, treat client IP as unavailable.
  const candidates: Array<string | null> = [
    request.headers.get('CF-Connecting-IP'),
    request.headers.get('X-Real-IP'),
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || null,
  ];

  for (const raw of candidates) {
    if (!raw) continue;
    const normalized = normalizeClientIpForRateLimit(raw);
    if (normalized) return normalized;
  }

  // Local dev (wrangler dev / localhost): allow a deterministic loopback identifier.
  if (isLocalRequest(request)) {
    return 'ip4:127.0.0.1';
  }

  return null;
}
