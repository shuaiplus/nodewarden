import { error, fail, redirect } from '@sveltejs/kit';

import { LOGIN_MESSAGES } from '$lib/messages';
import { PORTAL_COOKIE } from '$lib/server/cookies';
import { formText } from '$lib/server/forms';
import type { Actions, PageServerLoad } from './$types';

export const load: PageServerLoad = ({ platform, url }) => ({
  returnPath: platform!.portal.returnPath(url.searchParams.get('returnUrl') ?? '/admin'),
  mailEnabled: platform!.portal.mailEnabled(),
  message: LOGIN_MESSAGES[url.searchParams.get('m') ?? ''] ?? '',
});

export const actions: Actions = {
  default: async ({ request, platform, cookies, locals }) => {
    const portal = platform!.portal;
    const form = await request.formData();
    const returnUrl = formText(form, 'returnUrl') || '/admin';
    const outcome = await portal.requestLoginLink(formText(form, 'email'), returnUrl);
    if (outcome.kind === 'invalid-email')
      return fail(400, { message: 'Enter a valid email address.', returnPath: portal.returnPath(returnUrl) });
    if (outcome.kind === 'no-client') error(403, 'This request is not allowed.');
    if (outcome.kind === 'throttled') {
      locals.retryAfterSeconds = outcome.retryAfterSeconds;
      error(429, 'Try signing in later.');
    }
    // The link only signs in the browser that holds this nonce.
    cookies.set(portal.cookies.login.name, outcome.nonce, { ...PORTAL_COOKIE, maxAge: portal.cookies.login.maxAge });
    redirect(303, '/admin/login?m=sent');
  },
};
