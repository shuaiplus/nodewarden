import { RateLimitService, getClientIdentifier } from './ratelimit';
import { sha256Base64Url } from '../utils/account-passkeys';
import { waitUntil } from 'cloudflare:workers';
import type { Env, User } from '../types';
import { issueEmailOtp } from './email-otp';
import { deviceTypeName } from '../utils/device';
import { sendMail } from './mail';
import type { TemplateName, TemplateModel } from './mail-templates';

export function runInBackground(label: string, task: () => Promise<unknown>): void {
  waitUntil(Promise.resolve().then(task).catch(() => console.error('Background task failed', { label })));
}

export function notifyMail<N extends TemplateName>(env: Env, to: string, name: N, model: TemplateModel<N>): void {
  runInBackground(name, () => sendMail(env, to, name, model));
}

export function notifyFailedTwoFactor(env: Env, request: Request, user: { email: string }, provider: number): void {
  if (provider === 5) return;
  runInBackground('failed-two-factor', async () => {
    const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(`failed-2fa-mail:${await sha256Base64Url(user.email.toLowerCase())}`, 1, 3600);
    if (budget.allowed) await sendMail(env, user.email, 'failedTwoFactor', { provider: [-1, 100].includes(provider) ? 8 : provider, time: new Date().toISOString(), ip: getClientIdentifier(request) ?? 'Unknown' });
  });
}

export function notifyNewDeviceVerification(env: Env, request: Request, user: Pick<User, 'id' | 'email' | 'securityStamp'>, deviceType: number): void {
  runInBackground('new-device-verification', async () => {
    const outcome = await issueEmailOtp(env, { purpose: 'new-device', subject: user.id, binding: user.securityStamp },
      code => sendMail(env, user.email, 'signInCode', { code, reason: 'new-device', ip: getClientIdentifier(request) ?? 'Unknown', deviceTypeName: deviceTypeName(deviceType), utc: new Date().toISOString() }));
    if (outcome.kind !== 'sent') console.warn('New device verification code was not sent', { outcome: outcome.kind });
  });
}
