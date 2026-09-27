import { LIMITS } from '../config/limits';
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
  await env.DB.prepare(`INSERT INTO verification (id, identifier, value, expires_at, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at, updated_at = excluded.updated_at`)
    .bind(id, id, value, now + LIMITS.auth.emailOtpTtlSeconds * 1000, now, now).run();
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
  return !!await env.DB.prepare('DELETE FROM verification WHERE id = ? AND expires_at > ? AND value = ? RETURNING id')
    .bind(id, Date.now(), value).first();
}

export async function purgeExpiredEmailOtps(env: Env): Promise<void> {
  await env.DB.prepare("DELETE FROM verification WHERE identifier >= 'otp:' AND identifier < 'otp;' AND expires_at < ?")
    .bind(Date.now()).run();
}
