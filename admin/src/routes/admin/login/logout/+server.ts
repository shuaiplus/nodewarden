import { redirect } from '@sveltejs/kit';

import { PORTAL_COOKIE } from '$lib/server/cookies';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ platform, locals, cookies }) => {
  await platform!.portal.signOut(locals.session!);
  cookies.delete(platform!.portal.cookies.session.name, PORTAL_COOKIE);
  redirect(303, '/admin/login?m=loggedout');
};
