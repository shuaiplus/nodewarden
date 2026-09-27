import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { isMachineAllowedRoute, secretsManagerRoutes } from './router-sm';
import { isAdminPortalPath } from './web-vault-visibility';
import { handleAdminPortal } from './handlers/admin-portal';
import type { Env, User } from './types';
import { AuthService, type Principal } from './services/auth';
import { RateLimitService } from './services/ratelimit';
import { corsPolicy, errorResponse } from './utils/response';
import { normalizeOrigin } from './utils/origins';
import { LIMITS } from './config/limits';
import { authenticatedRoutes } from './router-authenticated';
import { jwtSecretUnsafeReason, publicRoutes, tooManyRequests } from './router-public';

// Per-request state the gates below derive for the route handlers. `userId` and `currentUser`
// are only set for user principals; the guard before the authenticated routes keeps machine
// tokens out of them.
export type AppEnv = {
  Bindings: Env;
  Variables: { principal: Principal; userId: string; currentUser: User };
};

function canServeWithUnsafeJwtSecret(path: string, method: string): boolean {
  if (method === 'GET' && (path === '/api/web-bootstrap' || path === '/web-bootstrap')) return true;
  if (method === 'GET' && (path === '/config' || path === '/api/config' || path === '/api/version')) return true;
  if (method === 'GET' && path === '/fill-assist/manifest.json') return true;
  if (method === 'GET' && /^\/fill-assist\/[^/]+$/i.test(path)) return true;
  if (method === 'GET' && (path === '/v1/assetlinks:check' || path === '/api/v1/assetlinks:check')) return true;
  if (method === 'GET' && /^\/icons\/[^/]+\/icon\.png$/i.test(path)) return true;
  return false;
}

function isImportBypassRequest(request: Request, path: string, method: string): boolean {
  if (request.headers.get('X-NodeWarden-Import') !== '1') return false;

  if (method === 'POST') {
    if (path === '/api/ciphers/import') return true;
    if (/^\/api\/ciphers\/[a-f0-9-]+\/attachment\/v2$/i.test(path)) return true;
    if (/^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path)) return true;
  }

  return false;
}

const BODY_LIMIT_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function isLargeUploadPath(path: string): boolean {
  return (
    /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path) ||
    /^\/api\/sends\/[a-f0-9-]+\/file\/[a-f0-9-]+$/i.test(path) ||
    path === '/api/admin/backup/import'
  );
}

async function enforceRequestBodyLimit(
  request: Request,
  path: string,
  method: string
): Promise<Request | Response> {
  if (!BODY_LIMIT_METHODS.has(method) || isLargeUploadPath(path) || !request.body) {
    return request;
  }

  const contentLengthRaw = request.headers.get('Content-Length');
  if (contentLengthRaw) {
    const contentLength = Number(contentLengthRaw);
    if (Number.isFinite(contentLength) && contentLength > LIMITS.request.maxBodyBytes) {
      return errorResponse('Request body too large', 413);
    }
    if (Number.isFinite(contentLength) && contentLength >= 0) {
      return request;
    }
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > LIMITS.request.maxBodyBytes) {
      try {
        await reader.cancel();
      } catch {
        // Ignore cancellation races after the oversized body is rejected.
      }
      return errorResponse('Request body too large', 413);
    }
    chunks.push(value);
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return new Request(request.url, {
    method: request.method,
    headers: request.headers,
    body,
    redirect: request.redirect,
  });
}

// Routes match the raw pathname exactly as index.ts normalised it (Hono's default path getter
// would percent-decode it first). Secrets Manager routes are the exception: they match a
// lower-cased path and hand lower-cased ids to their handlers, so upper-case ids keep working.
export const app = new Hono<AppEnv>({
  getPath: (request) => {
    const path = new URL(request.url).pathname;
    const lowerCased = path.toLowerCase();
    return secretsManagerRoutes.router.match(request.method, lowerCased)[0].length ? lowerCased : path;
  },
});

const corsOptions = {
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  exposeHeaders: ['*'],
  maxAge: LIMITS.cors.preflightMaxAgeSeconds,
};
// Only reached for origins corsPolicy already approved.
const credentialedCors = cors({ ...corsOptions, credentials: true, origin: (origin) => normalizeOrigin(origin) });
const publicCors = cors({ ...corsOptions, origin: '*' });

// hono's credentials flag is static, so corsPolicy picks the instance per request. WebSocket
// upgrades skip both because their 101 response must reach the runtime untouched.
app.use(async (c, next) => {
  if (c.req.header('Upgrade')?.toLowerCase() === 'websocket') return next();
  const policy = corsPolicy(c.req.raw, c.env);
  if (policy.kind === 'credentialed') return credentialedCors(c, next);
  if (policy.kind === 'public') return publicCors(c, next);
  return c.req.method === 'OPTIONS' && !isAdminPortalPath(c.req.path) ? c.body(null, 204) : next();
});

app.use(async (c, next) => {
  const limited = await enforceRequestBodyLimit(c.req.raw, c.req.path, c.req.method);
  if (limited instanceof Response) return limited;
  c.req.raw = limited;
  await next();
});

app.on('ALL', ['/admin', '/admin/*'], (c) => handleAdminPortal(c.req.raw, c.env));

app.use(async (c, next) => {
  if (jwtSecretUnsafeReason(c.env) && !canServeWithUnsafeJwtSecret(c.req.path, c.req.method)) {
    return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
  }
  await next();
});

app.route('/', publicRoutes);

app.use(async (c, next) => {
  const verified = await new AuthService(c.env).verifyPrincipal(c.req.raw.headers.get('Authorization'));
  if (!verified) return errorResponse('Unauthorized', 401);
  c.set('principal', verified);

  if (verified.kind === 'serviceAccount') {
    const budget = await new RateLimitService(c.env).consumeBudget(`sa:${verified.serviceAccountId}:api`, LIMITS.rateLimit.apiRequestsPerMinute);
    if (!budget.allowed) return errorResponse('Too many requests', 429, { 'Retry-After': String(budget.retryAfterSeconds || 60) });
    if (!isMachineAllowedRoute(c.req.path, c.req.method)) return errorResponse('Not found', 404);
    return next();
  }

  const { payload, user } = verified;
  const actingDeviceId = String(payload.did || '').trim();
  if (actingDeviceId) {
    const nextHeaders = new Headers(c.req.raw.headers);
    nextHeaders.set('X-NodeWarden-Acting-Device-Id', actingDeviceId);
    c.req.raw = new Request(c.req.raw, { headers: nextHeaders });
  }

  if (user.status !== 'active') return errorResponse('Account is disabled', 403);

  if (!isImportBypassRequest(c.req.raw, c.req.path, c.req.method)) {
    const budget = await new RateLimitService(c.env).consumeBudget(`${payload.sub}:api`, LIMITS.rateLimit.apiRequestsPerMinute);
    if (!budget.allowed) return tooManyRequests(budget.retryAfterSeconds);
  }

  c.set('userId', payload.sub);
  c.set('currentUser', user);
  await next();
});

app.route('/', secretsManagerRoutes);

// A machine token that passed the allowlist but matched no Secrets Manager route ends here.
app.use(async (c, next) => {
  if (c.get('principal').kind !== 'user') return errorResponse('Not found', 404);
  await next();
});

app.route('/', authenticatedRoutes);

app.notFound(() => errorResponse('Not found', 404));

app.onError((error) => {
  console.error('Request error:', error);
  return errorResponse('Internal server error', 500);
});
