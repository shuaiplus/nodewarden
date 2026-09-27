import { and, eq, isNull, lt, or, sql } from 'drizzle-orm';
import {
  convertIPv4BinaryToString,
  convertIPv4MappedIPv6ToIPv4,
  convertIPv4ToBinary,
  convertIPv6BinaryToString,
  convertIPv6ToBinary,
  expandIPv6,
  isIPv4MappedIPv6,
} from 'hono/utils/ipaddr';

import { LIMITS } from '../config/limits';
import { getOrm } from '../db/client';
import { loginAttemptsIp, rateLimitBuckets } from '../db/schema';
import type { Env } from '../types';

// Rate limiting service.
// - Login attempts: D1-backed (low volume, security-critical, needs cross-colo persistence).
// - API budgets: Workers Rate Limiting bindings (high volume, per location, zero D1 writes).
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

  // Scoped per request: env carries D1 plus the per-minute Workers Rate Limiting bindings.
  constructor(private readonly env: Pick<Env, 'DB'> & Partial<Pick<Env, `RATE_LIMIT_${number}_PER_MINUTE`>>) {}

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
    await getOrm(this.env.DB)
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

    await getOrm(this.env.DB).delete(rateLimitBuckets).where(lt(rateLimitBuckets.expiresAt, nowMs));
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

    const [row] = await getOrm(this.env.DB)
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
      await getOrm(this.env.DB).delete(loginAttemptsIp).where(eq(loginAttemptsIp.ip, key));
      return { allowed: true, remainingAttempts: CONFIG.LOGIN_MAX_ATTEMPTS };
    }

    const remainingAttempts = Math.max(0, CONFIG.LOGIN_MAX_ATTEMPTS - (row.attempts || 0));
    return { allowed: true, remainingAttempts };
  }

  async recordFailedLogin(ip: string): Promise<{ locked: boolean; retryAfterSeconds?: number }> {
    const key = ip.trim() || 'unknown';
    const now = Date.now();
    await this.maybeCleanupLoginAttemptsIp(now);
    const orm = getOrm(this.env.DB);

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
    await getOrm(this.env.DB).delete(loginAttemptsIp).where(eq(loginAttemptsIp.ip, key));
  }

  async consumeStrictBudget(
    identifier: string,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds?: number }> {
    return this.consumeStrictBudgetWithWindow(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS);
  }

  // A cost above one spends several units in one step, all or nothing, so a batch either fits the
  // remaining budget whole or is refused whole.
  async consumeStrictBudgetWithWindow(
    identifier: string,
    maxRequests: number,
    windowSeconds: number,
    cost = 1
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
    const orm = getOrm(this.env.DB);

    await this.maybeCleanupStrictBudgets(nowMs);
    await orm
      .insert(rateLimitBuckets)
      .values({ bucketKey, count: 0, expiresAt: windowEndMs, updatedAt: nowMs })
      .onConflictDoNothing({ target: rateLimitBuckets.bucketKey });

    const update = await orm
      .update(rateLimitBuckets)
      .set({
        count: sql`${rateLimitBuckets.count} + ${cost}`,
        expiresAt: windowEndMs,
        updatedAt: nowMs,
      })
      .where(and(eq(rateLimitBuckets.bucketKey, bucketKey), sql`${rateLimitBuckets.count} + ${cost} <= ${max}`))
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

  // General-purpose per-minute budget; callers supply an identifier unique per rate-limit category.
  // It spends the Workers Rate Limiting binding named for its limit, which like the Cache API counters it
  // replaces counts per location and costs no D1 writes. A limit without a binding, or a cost charged
  // as several units at once (the binding cannot spend a batch all or nothing), uses the D1 window.
  async consumeBudget(
    identifier: string,
    maxRequests: number,
    cost?: number
  ): Promise<{ allowed: boolean; retryAfterSeconds?: number }> {
    const binding = this.env[`RATE_LIMIT_${maxRequests}_PER_MINUTE`];
    if (!binding || cost !== undefined) {
      return this.consumeStrictBudgetWithWindow(identifier, maxRequests, CONFIG.API_WINDOW_SECONDS, cost);
    }
    const { success } = await binding.limit({ key: identifier });
    return success ? { allowed: true } : { allowed: false, retryAfterSeconds: CONFIG.API_WINDOW_SECONDS };
  }
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
    const input = raw.trim();
    // hono's parsers throw on anything that is not an address; that candidate simply gives no identity.
    try {
      if (!input.includes(':')) return `ip4:${convertIPv4BinaryToString(convertIPv4ToBinary(input))}`;
      const ipv6 = convertIPv6ToBinary(input.replace(/^\[(.*)\]$/, '$1').split('%')[0]);
      // IPv4-mapped (::ffff:192.0.2.1) and IPv4-compatible (::192.0.2.1) addresses keep the IPv4 identity.
      if (isIPv4MappedIPv6(ipv6) || ipv6 >> 32n === 0n) return `ip4:${convertIPv4BinaryToString(convertIPv4MappedIPv6ToIPv4(ipv6))}`;
      // Collapse to /64 to reduce brute-force bypass via IPv6 address rotation.
      return `ip6:${expandIPv6(convertIPv6BinaryToString(ipv6)).split(':').slice(0, 4).join(':')}`;
    } catch {
      continue;
    }
  }

  // Local dev (wrangler dev / localhost): allow a deterministic loopback identifier.
  const loopbackIdentifier = 'ip4:127.0.0.1';
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
    if (isLoopbackHost(new URL(request.url).hostname)) return loopbackIdentifier;
  } catch {
    // Ignore malformed URL and fall back to Host header check.
  }

  return isLoopbackHost(request.headers.get('Host')) ? loopbackIdentifier : null;
}
