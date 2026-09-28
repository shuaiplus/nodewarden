import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ platform }) => ({ dashboard: await platform!.portal.dashboard() });
