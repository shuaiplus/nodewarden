// Node stand-in for the workerd-only `cloudflare:workers` module (see env.ts).
export class DurableObject<TEnv = unknown> {
  constructor(
    protected readonly ctx: DurableObjectState,
    protected readonly env: TEnv,
  ) {}
}

// The importable env; src/test/support/env.ts fills in the bindings src reads through it.
export const env: Record<string, unknown> = {};

const pending = new Set<Promise<unknown>>();

export function waitUntil(task: Promise<unknown>): void {
  const tracked = task.catch((error: unknown) => console.error('waitUntil task failed:', error));
  pending.add(tracked);
  void tracked.finally(() => pending.delete(tracked));
}

export async function drainWaitUntil(): Promise<void> {
  while (pending.size) await Promise.all([...pending]);
}
