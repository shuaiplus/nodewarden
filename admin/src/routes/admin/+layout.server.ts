import type { LayoutServerLoad } from './$types';

export const load: LayoutServerLoad = ({ locals }) => ({
  csrf: locals.session?.csrf,
  adminEmail: locals.session?.email,
});
