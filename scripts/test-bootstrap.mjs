// Node module customization hook: redirect `cloudflare:workers` imports to the
// local test stub so handler unit tests can run under plain Node (tsx --test).
// Loaded via: tsx --test --import ./scripts/test-bootstrap.mjs <test-file>
import { register } from 'node:module';

register(new URL('./test-resolve-hook.mjs', import.meta.url));
