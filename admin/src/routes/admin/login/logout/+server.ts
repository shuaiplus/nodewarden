import { redirect } from '@sveltejs/kit';

import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ platform, locals, cookies }) => {
  await platform!.portal.signOut(locals.session!);
  cookies.delete(platform!.portal.cookies.session.name, { path: '/', sameSite: 'strict' });
  redirect(303, '/admin/login?m=loggedout');
};
