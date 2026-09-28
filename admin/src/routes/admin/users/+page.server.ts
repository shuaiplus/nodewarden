import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ platform, url }) => ({
  email: url.searchParams.get('email') ?? '',
  results: await platform!.portal.searchUsers(url.searchParams),
});
