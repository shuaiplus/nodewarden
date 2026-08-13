const BACKEND_PREFIXES = [
  '/api',
  '/identity',
  '/icons',
  '/fill-assist',
  '/notifications',
  '/.well-known',
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

const BACKEND_EXACT = new Set([
  '/v1/assetlinks:check',
  '/web-bootstrap',
  '/config',
  '/alive',
  '/accounts/kdf',
  '/settings/domains',
]);

function isBackendPath(pathname) {
  const path = pathname.toLowerCase();
  if (BACKEND_EXACT.has(path)) return true;
  return BACKEND_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const workerOrigin = String(context.env.WORKER_ORIGIN || '').trim().replace(/\/+$/, '');
  if (!workerOrigin || !isBackendPath(url.pathname)) {
    return context.next();
  }

  const target = new URL(url.pathname + url.search, workerOrigin);
  const headers = new Headers(context.request.headers);
  headers.set('X-Forwarded-Host', url.host);
  headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
  return fetch(new Request(target.toString(), {
    method: context.request.method,
    headers,
    body: context.request.body,
    redirect: 'manual',
  }));
}
