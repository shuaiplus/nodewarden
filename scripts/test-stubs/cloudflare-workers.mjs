// Minimal `cloudflare:workers` shim for plain-Node test runs (tsx / node:test).
// The real module only exists inside workerd. This stub lets handler unit tests
// import the sends/Auth call chains without a full Workers runtime.
export class DurableObject {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }
}

export function waitUntil(promise) {
  if (promise && typeof promise.catch === 'function') {
    promise.catch(() => {});
  }
}
