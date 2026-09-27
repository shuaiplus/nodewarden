import { isBackendPath } from '../shared/backend-paths';
import { readEnvConfig } from './config/env';
import type { Env } from './types';

export function isBackendRequestPath(pathname: string): boolean {
  return isBackendPath(pathname, ['/admin']);
}


export function isWebVaultHidden(env: Env): boolean {
  return readEnvConfig(env).HIDE_WEB_VAULT;
}

export function webVaultNotFoundResponse(request: Request): Response {
  const body = request.method === 'HEAD' ? null : 'Not Found';
  return new Response(body, {
    status: 404,
    headers: {
      'Cache-Control': 'no-store, max-age=0',
      'Content-Type': 'text/plain; charset=utf-8',
      'X-Robots-Tag': 'noindex, nofollow, noarchive, nosnippet',
    },
  });
}

export function isAdminPortalPath(path: string): boolean {
  return path === '/admin' || path.startsWith('/admin/');
}
