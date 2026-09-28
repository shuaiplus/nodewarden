// The SvelteKit admin portal's server build (npm run build:admin), imported by src/admin/portal.ts. Declared
// here so the Worker type-checks without building the portal first.
declare module '*/admin/build/server/index.js' {
  export { Server } from '@sveltejs/kit';
}

declare module '*/admin/build/server/manifest.js' {
  export const manifest: import('@sveltejs/kit').SSRManifest;
}
