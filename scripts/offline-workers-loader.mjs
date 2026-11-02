import { registerHooks } from 'node:module';

// Vite injects this build constant into modules shared with Web draft helpers.
globalThis.__NODEWARDEN_DEMO__ = false;

// Tests exercise routes and storage without running Cloudflare Durable Objects.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      const source = 'export class DurableObject {} export function waitUntil(p) { p.catch(() => {}); }';
      return { url: 'data:text/javascript,' + encodeURIComponent(source), shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});
