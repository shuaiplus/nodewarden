import { isBackendPath } from '../../shared/backend-paths.ts';
export async function onRequest(context) {
  const url = new URL(context.request.url);
  const workerOrigin = String(context.env.WORKER_ORIGIN || '')
    .trim()
    .replace(/\/+$/, '');
  if (!workerOrigin || !isBackendPath(url.pathname)) {
    return context.next();
  }

  const target = new URL(url.pathname + url.search, workerOrigin);
  const headers = new Headers(context.request.headers);
  headers.set('X-Forwarded-Host', url.host);
  headers.set('X-Forwarded-Proto', url.protocol.replace(':', ''));
  return fetch(
    new Request(target.toString(), {
      method: context.request.method,
      headers,
      body: context.request.body,
      redirect: 'manual',
    }),
  );
}
