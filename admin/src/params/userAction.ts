import type { ParamMatcher } from '@sveltejs/kit';

// The per-user actions posted to /admin/users/{id}/{action}.
export const match: ParamMatcher = (param) => ['disable', 'enable', 'verify-email', 'remove-2fa'].includes(param);
