import adapter from './adapter.js';

/** @type {import('@sveltejs/kit').Config} */
export default {
  kit: {
    adapter: adapter(),
    // hooks.server.ts enforces origin itself (Fetch Metadata, Origin or Sec-Fetch-Site, and a per-session CSRF
    // token on every signed-in post), so SvelteKit's stricter Origin-only check would only duplicate it.
    csrf: { trustedOrigins: ['*'] },
    // Links stay absolute (/admin/...) instead of relative to the page being rendered.
    paths: { relative: false },
    // Pages ship no JavaScript (csr = false) and inline their CSS, so the portal loads nothing but its HTML.
    inlineStyleThreshold: Infinity,
  },
};
