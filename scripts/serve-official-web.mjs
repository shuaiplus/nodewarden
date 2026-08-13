import { createServer } from 'node:http';
import { createReadStream, existsSync, statSync } from 'node:fs';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../official-web/dist', import.meta.url)));
const workerOrigin = (process.env.WORKER_ORIGIN || 'http://127.0.0.1:8787').replace(/\/+$/, '');
const port = Number(process.env.OFFICIAL_WEB_PORT || 8080);

const BACKEND_PREFIXES = [
  '/api', '/identity', '/icons', '/fill-assist', '/notifications', '/.well-known',
  '/devices', '/auth-requests', '/webauthn', '/scim', '/v2', '/connect', '/sso', '/oidc-signin',
  '/licenses', '/plans', '/emergency-access',
];
const BACKEND_EXACT = new Set([
  '/v1/assetlinks:check', '/web-bootstrap', '/config', '/alive', '/accounts/kdf', '/settings/domains',
]);

function isBackend(pathname) {
  const path = pathname.toLowerCase();
  return BACKEND_EXACT.has(path) || BACKEND_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.map': 'application/json',
};

if (!existsSync(join(root, 'index.html'))) {
  console.error(`Official web is not built. Run npm run build:official-web first (${root})`);
  process.exit(1);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
  if (isBackend(url.pathname)) {
    const target = `${workerOrigin}${url.pathname}${url.search}`;
    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      if (value && name.toLowerCase() !== 'host') headers.set(name, Array.isArray(value) ? value.join(',') : value);
    }
    headers.set('X-Forwarded-Host', `127.0.0.1:${port}`);
    headers.set('X-Forwarded-Proto', 'http');
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = chunks.length ? Buffer.concat(chunks) : undefined;
    try {
      const upstream = await fetch(target, { method: req.method, headers, body });
      const responseHeaders = {};
      for (const [name, value] of upstream.headers.entries()) {
        const lower = name.toLowerCase();
        if (lower === 'content-encoding' || lower === 'content-length' || lower === 'transfer-encoding') continue;
        responseHeaders[name] = value;
      }
      const payload = Buffer.from(await upstream.arrayBuffer());
      responseHeaders['content-length'] = String(payload.length);
      res.writeHead(upstream.status, responseHeaders);
      res.end(payload);
    } catch (error) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(`Worker proxy failed: ${error instanceof Error ? error.message : String(error)}`);
    }
    return;
  }

  const safePath = normalize(url.pathname).replace(/^(\.\.[/\\])+/, '');
  const filePath = join(root, safePath === '/' ? 'index.html' : safePath.slice(1));
  const resolved = existsSync(filePath) && statSync(filePath).isFile()
    ? filePath
    : join(root, 'index.html');
  res.writeHead(200, { 'Content-Type': TYPES[extname(resolved)] || 'application/octet-stream' });
  createReadStream(resolved).pipe(res);
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Official Bitwarden web at http://127.0.0.1:${port} → ${workerOrigin}`);
});
