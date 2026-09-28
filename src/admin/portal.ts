import { Server } from '../../admin/build/server/index.js';
import { manifest } from '../../admin/build/server/manifest.js';
import { adminPortal } from '../services/admin-portal';
import { parseAdminDirectory } from '../services/admin-portal-auth';
import type { Env } from '../types';
import { webVaultNotFoundResponse } from '../web-vault-visibility';
import { PORTAL_HEADERS } from './headers';

// The SvelteKit portal (admin/) runs inside this Worker: one server per isolate, with the Worker's services
// passed in through `platform`, so the portal and the API share one module graph.
const server = new Server(manifest);
let ready: Promise<void> | undefined;

export async function handleAdminPortal(request: Request, env: Env): Promise<Response> {
  // Without ADMIN_EMAILS the portal does not exist, so /admin looks like any other missing page.
  if (parseAdminDirectory(env).kind === 'disabled') return webVaultNotFoundResponse(request);
  ready ??= server.init({ env: {} });
  await ready;
  // The portal ships no JavaScript, so every form post is a page navigation. Without this, SvelteKit answers
  // posts that do not ask for HTML with the JSON results its client-side forms expect.
  const pageHeaders = new Headers(request.headers);
  pageHeaders.set('Accept', 'text/html');
  const response = await server.respond(new Request(request, { headers: pageHeaders }), {
    platform: { portal: adminPortal(env, request) },
    getClientAddress: () => request.headers.get('CF-Connecting-IP') ?? '',
  });
  const headers = new Headers(response.headers);
  for (const [name, value] of Object.entries(PORTAL_HEADERS)) headers.set(name, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}
