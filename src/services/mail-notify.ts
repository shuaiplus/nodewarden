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
