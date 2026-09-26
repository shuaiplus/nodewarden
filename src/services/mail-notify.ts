import { RateLimitService, getClientIdentifier } from './ratelimit';
import { sha256Base64Url } from '../utils/account-passkeys';
import { waitUntil } from 'cloudflare:workers';
import type { Env } from '../types';
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
    const budget = await new RateLimitService(env.DB).consumeStrictBudgetWithWindow(`failed-2fa-mail:${await sha256Base64Url(user.email.toLowerCase())}`, 1, 3600);
    if (budget.allowed) await sendMail(env, user.email, 'failedTwoFactor', { provider: [-1, 100].includes(provider) ? 8 : provider, time: new Date().toISOString(), ip: getClientIdentifier(request) ?? 'Unknown' });
  });
}
