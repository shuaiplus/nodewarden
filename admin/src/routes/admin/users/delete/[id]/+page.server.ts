import { error, fail, redirect } from '@sveltejs/kit';

import { userViewPath } from '$lib/paths';
import { confirmUserAction, postOnly, requireUser } from '$lib/server/forms';
import type { Actions, PageServerLoad } from './$types';

// Rendered only to show why a deletion was refused.
export const load: PageServerLoad = async (event) => {
  postOnly(event);
  return { detail: await requireUser(event, event.params.id) };
};

export const actions: Actions = {
  default: async (event) => {
    const detail = await requireUser(event, event.params.id);
    const refusal = await confirmUserAction(event, detail, userViewPath(detail.id));
    if (refusal) return refusal;
    const outcome = await event.platform!.portal.deleteUser(event.locals.session!, detail.id);
    if (outcome.kind === 'done') redirect(303, '/admin/users?m=deleted');
    if (outcome.kind === 'not-found') error(404, 'User not found.');
    return fail(400, { notice: outcome.refusal });
  },
};
