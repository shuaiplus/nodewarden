import { and, eq, gt, gte, lt } from 'drizzle-orm';

import { LIMITS } from '../config/limits';
import { getOrm } from '../db/client';
import { verification } from '../db/schema';
import type { Env } from '../types';
import { hmacSha256Base64Url } from '../utils/jwt';
import type { MailOutcome } from './mail';
import { RateLimitService } from './ratelimit';

export type EmailOtpPurpose = 'send-access' | 'two-factor-setup' | 'two-factor-login' | 'new-device' | 'email-change';

export interface EmailOtpTarget {
  purpose: EmailOtpPurpose;
  subject: string;
  binding: string;
}

async function emailOtpId(env: Env, target: EmailOtpTarget): Promise<string> {
  return `otp:${target.purpose}:${await hmacSha256Base64Url(env.JWT_SECRET, `${target.purpose}\n${target.subject}`)}`;
}

export async function spendEmailOtpIssueBudget(env: Env, target: EmailOtpTarget): Promise<boolean> {
  const limit = target.purpose === 'two-factor-login' || target.purpose === 'new-device'
    ? LIMITS.rateLimit.emailSignInCodeIssuesPerHour
    : LIMITS.rateLimit.emailOtpIssuesPerHour;
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
    `otp-issue:${await emailOtpId(env, target)}`, limit, 3600,
  );
  return budget.allowed;
}

function createEmailOtp(): string {
  const random = new Uint32Array(1);
  // Accept an exact multiple of one million outcomes so every code is equally likely.
  do { crypto.getRandomValues(random); } while (random[0] >= 4_294_000_000);
  return String(random[0] % 1_000_000).padStart(6, '0');
}

export async function issueEmailOtp(
  env: Env,
  target: EmailOtpTarget,
  send: (code: string) => Promise<MailOutcome>,
): Promise<MailOutcome> {
  if (!await spendEmailOtpIssueBudget(env, target)) {
    return { kind: 'throttled', retryAfterSeconds: 3600 - Math.floor(Date.now() / 1000) % 3600 };
  }
  const code = createEmailOtp();
  const outcome = await send(code);
  if (outcome.kind !== 'sent') return outcome;
  const id = await emailOtpId(env, target);
  const value = await hmacSha256Base64Url(env.JWT_SECRET, `${id}\n${target.binding}\n${code}`);
  const now = Date.now();
  const expiresAt = now + LIMITS.auth.emailOtpTtlSeconds * 1000;
  await getOrm(env.DB).insert(verification)
    .values({ id, identifier: id, value, expiresAt, createdAt: now, updatedAt: now })
    .onConflictDoUpdate({ target: verification.id, set: { value, expiresAt, updatedAt: now } });
  return outcome;
}

export async function redeemEmailOtp(env: Env, target: EmailOtpTarget, input: string): Promise<boolean> {
  const code = input.trim();
  if (!/^\d{6}$/.test(code)) return false;
  const id = await emailOtpId(env, target);
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
    `otp-try:${id}`, LIMITS.rateLimit.emailOtpAttemptsPerWindow, LIMITS.auth.emailOtpTtlSeconds,
  );
  if (!budget.allowed) return false;
  const value = await hmacSha256Base64Url(env.JWT_SECRET, `${id}\n${target.binding}\n${code}`);
  return !!await getOrm(env.DB).delete(verification)
    .where(and(eq(verification.id, id), gt(verification.expiresAt, Date.now()), eq(verification.value, value)))
    .returning({ id: verification.id }).get();
}

export async function purgeExpiredEmailOtps(env: Env): Promise<void> {
  // ';' follows ':' in byte order, so the range is exactly the 'otp:' prefix and stays on the identifier index.
  await getOrm(env.DB).delete(verification)
    .where(and(gte(verification.identifier, 'otp:'), lt(verification.identifier, 'otp;'), lt(verification.expiresAt, Date.now())));
}
