import type { Env } from '../types';
import { parseAdminDirectory, checkPortalRequest, adminReturnPath } from '../services/admin-portal-auth';
import { readMailConfig } from '../services/mail';
import { webVaultNotFoundResponse } from '../web-vault-visibility';
import { html } from '../utils/html';
import { portalPage, portalRedirect, loginPage, LOGIN_MESSAGES } from '../views/admin-portal';

export async function handleAdminPortal(request: Request, env: Env): Promise<Response> {
  try {
    const directory = parseAdminDirectory(env);
    if (directory.kind === 'disabled') return webVaultNotFoundResponse(request);
    if (directory.kind === 'invalid') {
      console.error('Invalid ADMIN_EMAILS entry', { entryIndex: directory.entryIndex });
      return portalPage('Configuration error', html`<p>Administrator access is not configured correctly.</p>`, 500);
    }
    if (!checkPortalRequest(request)) {
      console.warn('Rejected administrator request');
      return portalPage('Forbidden', html`<p>This request is not allowed.</p>`, 403);
    }
    const url = new URL(request.url);
    if (url.pathname === '/admin/login' && request.method === 'GET') {
      return loginPage(adminReturnPath(url.searchParams.get('returnUrl') ?? '/admin', url.origin), readMailConfig(env).kind === 'enabled', LOGIN_MESSAGES[url.searchParams.get('m') ?? '']);
    }
    if (request.method !== 'GET') return portalPage('Method not allowed', html`<p>This method is not supported.</p>`, 405);
    return portalRedirect(`/admin/login?returnUrl=${encodeURIComponent(adminReturnPath(url.pathname + url.search, url.origin))}`);
  } catch {
    console.error('Administrator portal request failed');
    return portalPage('Server error', html`<p>Unable to complete this request.</p>`, 500);
  }
}
