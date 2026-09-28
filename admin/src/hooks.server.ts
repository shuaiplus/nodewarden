import { error, redirect, type Handle, type HandleServerError } from '@sveltejs/kit';

import { PORTAL_COOKIE } from '$lib/server/cookies';

// The sign-in flow is the only part of the portal reachable without a session.
const SIGN_IN_PATHS = new Set(['/admin/login', '/admin/login/confirm']);

export const handle: Handle = async ({ event, resolve }) => {
  const portal = event.platform!.portal;
  if (!portal.configured) error(500, 'Administrator access is not configured correctly.');
  if (!portal.acceptsRequest()) error(403, 'This request is not allowed.');
  if (!SIGN_IN_PATHS.has(event.url.pathname)) {
    const session = await portal.readSession();
    if (!session) {
      event.cookies.delete(portal.cookies.session.name, PORTAL_COOKIE);
      const returnPath = portal.returnPath(event.url.pathname + event.url.search);
      redirect(303, `/admin/login?returnUrl=${encodeURIComponent(returnPath)}`);
    }
    // Every form posted with a session carries its CSRF token; read a clone so actions still get the body.
    if (event.request.method === 'POST') {
      const form = await event.request.clone().formData();
      if (!portal.csrfMatches(session, form.get('csrf'))) error(403, 'This request is not allowed.');
    }
    event.locals.session = session;
  }
  const response = await resolve(event);
  if (response.status === 429 && event.locals.retryAfterSeconds)
    response.headers.set('Retry-After', String(event.locals.retryAfterSeconds));
  return response;
};

// Never echo or log the failure itself: it may carry bound query values or account data.
export const handleError: HandleServerError = () => {
  console.error('Administrator portal request failed');
  return { message: 'Unable to complete this request.' };
};
