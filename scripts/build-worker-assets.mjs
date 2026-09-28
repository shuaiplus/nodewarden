import { cpSync, existsSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Assembles the Worker's static assets: the official web vault build, overlaid by our own pages in
// public/ (the connectors official clients use today), plus one _headers file for everything Cloudflare
// serves without running the Worker. Paths that run the Worker get their headers from its code instead.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const officialWeb = join(root, 'official-web', 'dist');
const out = join(root, 'dist', 'worker-assets');
if (!existsSync(join(officialWeb, 'index.html'))) {
  throw new Error('official-web/dist is missing: run npm run build:official-web first');
}
rmSync(out, { recursive: true, force: true });
// The official build's _redirects and _headers were written for Pages: assets.not_found_handling now
// provides the single-page fallback, and the headers below replace theirs rather than doubling them.
cpSync(officialWeb, out, { recursive: true, filter: (path) => !/[\\/]_(redirects|headers)$/.test(path) });
cpSync(join(root, 'public'), out, { recursive: true });
writeFileSync(
  join(out, '_headers'),
  `/*
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  X-Frame-Options: DENY
  Content-Security-Policy: frame-ancestors 'none'
  X-Robots-Tag: noindex, nofollow, noarchive, nosnippet
/
  Cache-Control: no-cache
/index.html
  Cache-Control: no-cache
`,
);
console.log(`Assembled Worker assets in ${out}`);
