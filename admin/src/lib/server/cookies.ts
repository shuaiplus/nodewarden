// Portal cookies use the __Host- prefix, which browsers accept only with Secure, Path=/ and no Domain.
// Passed explicitly because SvelteKit would drop Secure on http://localhost and the cookie would vanish.
export const PORTAL_COOKIE = { path: '/', httpOnly: true, secure: true, sameSite: 'strict' } as const;
