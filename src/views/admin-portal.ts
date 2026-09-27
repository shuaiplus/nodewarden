import { html } from 'hono/html';

export const PORTAL_HEADERS = {
  'Content-Type': 'text/html; charset=utf-8',
  'Content-Security-Policy':
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  'Referrer-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  'X-Robots-Tag': 'noindex, nofollow',
};
export function portalPage(
  title: string,
  content: ReturnType<typeof html>,
  status = 200,
  headers: HeadersInit = {},
): Response {
  const responseHeaders = new Headers(PORTAL_HEADERS);
  new Headers(headers).forEach((value, key) => responseHeaders.set(key, value));
  // html only returns a Promise when a child is one, and portal markup interpolates none.
  return new Response(
    String(
      html`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${title} · NodeWarden</title><style>body{font:16px system-ui,sans-serif;max-width:72rem;margin:2rem auto;padding:0 1rem;color:#182230;background:#f5f7fa}main{background:white;padding:2rem;border:1px solid #dce1e8;border-radius:8px}a{color:#1649a6}nav{display:flex;gap:1rem;align-items:center;flex-wrap:wrap}label{display:block;margin:1rem 0}input,button{font:inherit;padding:.5rem}table{border-collapse:collapse;width:100%;margin:1rem 0}th,td{text-align:left;border-bottom:1px solid #dce1e8;padding:.5rem;overflow-wrap:anywhere}dt{font-weight:bold;margin-top:.75rem}dd{margin-left:0;overflow-wrap:anywhere}.notice{padding:1rem;background:#fff4d6}</style></head><body><main><h1>${title}</h1>${content}</main></body></html>`,
    ),
    { status, headers: responseHeaders },
  );
}
export function portalRedirect(path: string, cookies: string[] = []): Response {
  const response = portalPage('Continue', html`<p><a href="${path}">Continue</a></p>`, 303, { Location: path });
  for (const cookie of cookies) response.headers.append('Set-Cookie', cookie);
  return response;
}
export const LOGIN_MESSAGES: Record<string, string> = {
  sent: 'If this address is configured for administration, a sign-in link has been sent. Open it in this browser.',
  invalid: 'This link is invalid, expired, or was requested in another browser. Request a new link in this browser.',
  loggedout: 'You have signed out.',
  denied: 'This sign-in is no longer authorized.',
  deleted: 'Deleted successfully.',
  reauth: 'Sign in again before making this change.',
};
export function loginPage(returnPath: string, mailEnabled: boolean, message = '', status = 200): Response {
  return portalPage(
    'Administrator sign-in',
    html`${mailEnabled ? html`` : html`<p class="notice">Sign-in links cannot be sent. Check the instance email configuration.</p>`}${message ? html`<p class="notice">${message}</p>` : html``}<form method="post" action="/admin/login"><label>Email <input type="email" name="email" required maxlength="256" autocomplete="email"></label><input type="hidden" name="returnUrl" value="${returnPath}"><button type="submit">Send sign-in link</button></form>`,
    status,
  );
}

export function portalNavigation(csrf: string) {
  return html`<nav><a href="/admin">Dashboard</a><a href="/admin/users">Users</a><a href="/admin/organizations">Organizations</a><form method="post" action="/admin/login/logout"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Sign out</button></form></nav>`;
}

export function portalFields(values: Array<[string, string | number]>) {
  return html`<dl>${values.map(([name, value]) => html`<dt>${name}</dt><dd>${value}</dd>`)}</dl>`;
}
export function deleteForm(action: string, csrf: string, label: string) {
  return html`<form method="post" action="${action}"><input type="hidden" name="csrf" value="${csrf}"><label>Type ${label} to confirm deletion <input name="confirmation" required autocomplete="off"></label><button type="submit">Delete</button></form>`;
}
export function portalPagination(url: URL, page: number, hasMore: boolean) {
  const pageUrl = (value: number) => {
    const params = new URLSearchParams(url.searchParams);
    params.set('page', String(value));
    return url.pathname + '?' + params;
  };
  return html`<nav>${page > 1 ? html`<a href="${pageUrl(page - 1)}">Previous</a>` : html``}<span>Page ${page}</span>${hasMore ? html`<a href="${pageUrl(page + 1)}">Next</a>` : html``}</nav>`;
}

export function userStatusForm(userId: string, csrf: string, status: 'active' | 'banned') {
  const action = status === 'active' ? 'disable' : 'enable';
  return html`<form method="post" action="${'/admin/users/' + encodeURIComponent(userId) + '/' + action}"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">${status === 'active' ? 'Disable user' : 'Enable user'}</button></form>`;
}

export function verifyEmailForm(userId: string, csrf: string, email: string, grantsVaultAdmin: boolean) {
  return html`<form method="post" action="${'/admin/users/' + encodeURIComponent(userId) + '/verify-email'}"><input type="hidden" name="csrf" value="${csrf}"><label>Type ${email} to confirm email verification <input name="confirmation" required autocomplete="off"></label><button type="submit">${grantsVaultAdmin ? 'Verify email and grant vault admin' : 'Verify email'}</button></form>`;
}

export function removeTwoFactorForm(userId: string, csrf: string, email: string) {
  return html`<form method="post" action="${'/admin/users/' + encodeURIComponent(userId) + '/remove-2fa'}"><input type="hidden" name="csrf" value="${csrf}"><label>Type ${email} to remove two-step login <input name="confirmation" required autocomplete="off"></label><button type="submit">Remove two-step login</button></form>`;
}
