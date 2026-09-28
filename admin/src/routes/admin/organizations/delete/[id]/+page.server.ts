import { redirect } from '@sveltejs/kit';

import { organizationViewPath } from '$lib/paths';
import { confirmSensitiveAction, formText, postOnly, requireOrganization } from '$lib/server/forms';
import type { Actions, PageServerLoad } from './$types';

// Rendered only to show why a deletion was refused.
export const load: PageServerLoad = async (event) => {
  postOnly(event);
  return { detail: await requireOrganization(event, event.params.id) };
};

export const actions: Actions = {
  default: async (event) => {
    const detail = await requireOrganization(event, event.params.id);
    const typed = formText(await event.request.formData(), 'confirmation');
    const refusal = await confirmSensitiveAction(event, typed, detail.name, organizationViewPath(detail.id));
    if (refusal) return refusal;
    await event.platform!.portal.deleteOrganization(event.locals.session!, detail.id);
    redirect(303, '/admin/organizations?m=deleted');
  },
};
