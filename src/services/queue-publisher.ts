import type { Env } from '../types';

export type PlatformEvent =
  | { type: 'org.revision'; orgId: string; actorUserId?: string | null }
  | { type: 'secret.changed'; orgId: string; secretId: string }
  | { type: 'directory.applied'; orgId: string; resource: 'user' | 'group'; resourceId: string };

export async function publishPlatformEvent(env: Env, event: PlatformEvent): Promise<void> {
  if (env.EVENTS_QUEUE) await env.EVENTS_QUEUE.send(event);
}

export async function publishSecretChanged(env: Env, orgId: string, secretId: string): Promise<void> {
  const event: PlatformEvent = { type: 'secret.changed', orgId, secretId };
  if (env.SECRET_CHANGES_QUEUE) {
    await env.SECRET_CHANGES_QUEUE.send(event);
    return;
  }
  await publishPlatformEvent(env, event);
}
