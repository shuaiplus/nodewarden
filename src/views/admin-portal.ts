import { html, type SafeHtml } from '../utils/html';

export const PORTAL_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'Referrer-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
};
export function portalPage(title: string, content: SafeHtml, status = 200, headers: HeadersInit = {}): Response {
  const responseHeaders = new Headers(PORTAL_HEADERS);
  new Headers(headers).forEach((value, key) => responseHeaders.set(key, value));
  return new Response(html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} · NodeWarden</title><style>body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#182230;background:#f5f7fa}main{background:white;padding:2rem;border:1px solid #dce1e8;border-radius:8px}a{color:#1649a6}nav{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}label{display:block;margin:1rem 0}input,button{font:inherit;padding:.5rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;border-bottom:1px solid #dce1e8;padding:.5rem;overflow-wrap:anywhere}dt{font-weight:bold;margin-top:.75rem}dd{margin-left:0;overflow-wrap:anywhere}.notice{padding:1rem;background:#fff4d6}</style></head><body><main><h1>${title}</h1>${content}</main></body></html>`.safeHtml, { status, headers: responseHeaders });
}
export function portalRedirect(path: string, cookies: string[] = []): Response {
  const response = portalPage('Continue', html`<p><a href="${path}">Continue</a></p>`, 303, { Location: path });
  for (const cookie of cookies) response.headers.append('Set-Cookie', cookie);
  return response;
}
export const LOGIN_MESSAGES: Record<string, string> = {
  sent: 'If this address is configured for administration, a sign-in link has been sent. Open it in this browser.',
  invalid: 'This link is invalid, expired, or was requested in another browser. Request a new link in this browser.',
  loggedout: 'You have signed out.', denied: 'This sign-in is no longer authorized.', deleted: 'Deleted successfully.',
  reauth: 'Sign in again before making this change.',
};
export function loginPage(returnPath: string, mailEnabled: boolean, message = '', status = 200): Response {
  return portalPage('Administrator sign-in', html`${mailEnabled ? html`` : html`<p class="notice">Sign-in links cannot be sent. Check the instance email configuration.</p>`}${message ? html`<p class="notice">${message}</p>` : html``}<form method="post" action="/admin/login"><label>Email <input type="email" name="email" required maxlength="256" autocomplete="email"></label><input type="hidden" name="returnUrl" value="${returnPath}"><button type="submit">Send sign-in link</button></form>`, status);
}

export function portalNavigation(csrf: string): SafeHtml {
  return html`<nav><a href="/admin">Dashboard</a><a href="/admin/users">Users</a><a href="/admin/organizations">Organizations</a><form method="post" action="/admin/login/logout"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Sign out</button></form></nav>`;
}
