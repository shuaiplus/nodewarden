import { requireUser } from '$lib/server/forms';
import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async (event) => ({ detail: await requireUser(event, event.params.id) });
