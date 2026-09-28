import { requireOrganization } from '$lib/server/forms';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => ({ detail: await requireOrganization(event, event.params.id) });
