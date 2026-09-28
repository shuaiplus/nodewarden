import { writeFileSync } from 'node:fs';

// Emits SvelteKit's server for the NodeWarden Worker to import, instead of a Worker of its own: the Worker
// stays the only entry point and hands the portal its services through `platform`, so the portal and the
// API share one copy of every module (the user cache, the ORM, the notification hub stubs). The pages ship
// no JavaScript and inline their CSS, so there are no client files to emit.
export default function workerEmbedAdapter() {
  return {
    name: 'nodewarden-worker-embed',
    async adapt(builder) {
      const out = 'build';
      builder.rimraf(out);
      builder.writeServer(`${out}/server`);
      writeFileSync(
        `${out}/server/manifest.js`,
        `export const manifest = ${builder.generateManifest({ relativePath: '.' })};\n`,
      );
    },
  };
}
