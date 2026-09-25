// Node stand-in for the workerd-only `cloudflare:workers` module (see env.ts).
export class DurableObject<TEnv = unknown> {
  constructor(protected readonly ctx: DurableObjectState, protected readonly env: TEnv) {}
}

export function waitUntil(task: Promise<unknown>): void {
  task.catch((error: unknown) => console.error('waitUntil task failed:', error));
}
