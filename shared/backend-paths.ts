// Request paths the Worker answers itself. wrangler.toml's run_worker_first lists the same paths (plus
// /admin and the connector pages), so Cloudflare runs the Worker only for these and serves the official
// web vault's static files for everything else on the same origin.
export const BACKEND_PATH_PREFIXES = [
  '/api',
  '/identity',
  '/icons',
  '/fill-assist',
  '/notifications',
  '/events',
  // Compatibility aliases retained for older Bitwarden clients and clients given the bare server URL.
  '/accounts',
  '/organizations',
  '/two-factor',
  '/devices',
  '/auth-requests',
  '/webauthn',
  '/scim',
  '/v2',
  '/connect',
  '/sso',
  '/oidc-signin',
  '/licenses',
  '/plans',
  '/emergency-access',
];

export const BACKEND_EXACT_PATHS = ['/v1/assetlinks:check', '/web-bootstrap', '/config', '/alive', '/settings/domains'];

export function isBackendPath(pathname: string, extraPrefixes: string[] = []): boolean {
  const path = pathname.toLowerCase();
  return (
    BACKEND_EXACT_PATHS.includes(path) ||
    [...BACKEND_PATH_PREFIXES, ...extraPrefixes].some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
  );
}
