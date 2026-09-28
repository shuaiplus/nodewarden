import { error, fail, redirect } from '@sveltejs/kit';

import { LOGIN_MESSAGES } from '$lib/messages';
import { PORTAL_COOKIE } from '$lib/server/cookies';
import { formText } from '$lib/server/forms';
import type { Actions, PageServerLoad } from './$types';

// Opening the link only shows a form, so a mail scanner that fetches it cannot use it up.
export const load: PageServerLoad = ({ platform, url, request }) => {
  const token = url.searchParams.get('token') ?? '';
  if (request.method === 'GET' && !platform!.portal.isLoginToken(token)) error(400, LOGIN_MESSAGES.invalid);
  return { token, mailEnabled: platform!.portal.mailEnabled() };
};

export const actions: Actions = {
  default: async ({ request, platform, cookies }) => {
    const portal = platform!.portal;
    const outcome = await portal.redeemLoginLink(formText(await request.formData(), 'token'));
    if (outcome.kind === 'invalid') return fail(400, { invalid: true });
    cookies.delete(portal.cookies.login.name, PORTAL_COOKIE);
    cookies.set(portal.cookies.session.name, outcome.session.token, {
      ...PORTAL_COOKIE,
      maxAge: portal.cookies.session.maxAge,
    });
    redirect(303, outcome.returnPath);
  },
};
