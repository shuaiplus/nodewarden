import { error, fail, redirect } from '@sveltejs/kit';

import { userViewPath } from '$lib/paths';
import { confirmUserAction, postOnly, requireUser } from '$lib/server/forms';
import type { Actions, PageServerLoad } from './$types';

// Rendered only to show why an action was refused.
export const load: PageServerLoad = async (event) => {
  postOnly(event);
  return { detail: await requireUser(event, event.params.id) };
};

export const actions: Actions = {
  default: async (event) => {
    const portal = event.platform!.portal;
    const session = event.locals.session!;
    const detail = await requireUser(event, event.params.id);
    const viewPath = userViewPath(detail.id);
    const action = event.params.action;
    // Disabling and enabling need only the CSRF token, as they are reversible.
    if (action === 'disable' || action === 'enable') {
      const outcome = await portal.setUserStatus(session, detail.id, action === 'disable' ? 'banned' : 'active');
      if (outcome.kind === 'done') redirect(303, `${viewPath}?m=${action}d`);
      if (outcome.kind === 'not-found') error(404, 'User not found.');
      return fail(400, { notice: outcome.refusal });
    }
    // Checked before the confirmation so a no-op spends no sensitive-action budget.
    if (action === 'remove-2fa' && !detail.hasTwoFactor) redirect(303, `${viewPath}?m=nothing-to-reset`);
    const refusal = await confirmUserAction(event, detail, viewPath);
    if (refusal) return refusal;
    if (action === 'verify-email') {
      await portal.verifyUserEmail(session, detail.id);
      redirect(303, `${viewPath}?m=verified`);
    }
    await portal.resetUserTwoFactor(session, detail.id);
    redirect(303, `${viewPath}?m=two-factor-reset`);
  },
};
