// Request paths the Worker answers as API. The official web Pages proxy forwards these to the
// Worker and serves its own assets for everything else; the Worker serves the local web vault for
// everything else. /admin stays Worker-only because portal cookies and forms need the Worker origin.
export const BACKEND_PATH_PREFIXES = [
  '/api', '/identity', '/icons', '/fill-assist', '/notifications', '/events',
  // Compatibility aliases retained for older Bitwarden clients.
  '/devices', '/auth-requests', '/webauthn', '/scim', '/v2', '/connect', '/sso', '/oidc-signin',
  '/licenses', '/plans', '/emergency-access',
];

export const BACKEND_EXACT_PATHS = ['/v1/assetlinks:check', '/web-bootstrap', '/config', '/alive', '/accounts/kdf', '/settings/domains'];

export function isBackendPath(pathname: string, extraPrefixes: string[] = []): boolean {
  const path = pathname.toLowerCase();
  return BACKEND_EXACT_PATHS.includes(path)
    || [...BACKEND_PATH_PREFIXES, ...extraPrefixes].some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}
