import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ platform, url }) => ({
  name: url.searchParams.get('name') ?? '',
  userEmail: url.searchParams.get('userEmail') ?? '',
  results: await platform!.portal.searchOrganizations(url.searchParams),
});
