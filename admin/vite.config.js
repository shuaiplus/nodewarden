import { mkdirSync } from 'node:fs';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// Every portal page renders on the server only (csr = false), so SvelteKit skips its client build, yet its
// prerender step still lists .svelte-kit/output/client. An empty directory is all that step needs.
const clientOutputDirectory = {
  name: 'nodewarden-client-output-directory',
  writeBundle: { order: 'pre', handler: () => mkdirSync('.svelte-kit/output/client', { recursive: true }) },
};

export default defineConfig({ plugins: [clientOutputDirectory, sveltekit()] });
