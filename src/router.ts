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
import { withoutQueryParams } from './db/client';

// Per-request state the gates below derive for the route handlers. `userId` and `currentUser`
// are only set for user principals; the guard before the authenticated routes keeps machine
// tokens out of them.
export type AppEnv = {
  Bindings: Env;
  Variables: { principal: Principal; userId: string; currentUser: User };
};

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
// A callback rather than '*' keeps hono's Vary: Origin, since credentialed origins get another answer here.
const publicCors = cors({ ...corsOptions, origin: () => '*' });

// hono's credentials flag is static, so corsPolicy picks the instance per request. WebSocket
// upgrades skip both because their 101 response must reach the runtime untouched.
app.use(async (c, next) => {
  if (c.req.header('Upgrade')?.toLowerCase() === 'websocket') return next();
  const policy = corsPolicy(c.req.raw, c.env);
  if (policy.kind === 'credentialed') return credentialedCors(c, next);
  if (policy.kind === 'public') return publicCors(c, next);
  return c.req.method === 'OPTIONS' && !isAdminPortalPath(c.req.path) ? c.body(null, 204) : next();
});

const BODY_LIMIT_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Attachment and Send file uploads and backup imports are exempt from the buffered body cap.
app.use(async (c, next) => {
  const request = c.req.raw;
  const path = c.req.path;
  if (BODY_LIMIT_METHODS.has(c.req.method) && !(
    /^\/api\/ciphers\/[a-f0-9-]+\/attachment\/[a-f0-9-]+$/i.test(path) ||
    /^\/api\/sends\/[a-f0-9-]+\/file\/[a-f0-9-]+$/i.test(path) ||
    path === '/api/admin/backup/import'
  ) && request.body) {
    const contentLengthRaw = request.headers.get('Content-Length');
    const contentLength = Number(contentLengthRaw);
    if (contentLengthRaw && Number.isFinite(contentLength) && contentLength > LIMITS.request.maxBodyBytes) {
      return errorResponse('Request body too large', 413);
    }
    // A declared length within the cap is trusted; otherwise the body is read up to the cap and replayed.
    if (!contentLengthRaw || !Number.isFinite(contentLength) || contentLength < 0) {
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

      c.req.raw = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        body,
        redirect: request.redirect,
      });
    }
  }
  await next();
});

app.on('ALL', ['/admin', '/admin/*'], (c) => handleAdminPortal(c.req.raw, c.env));

app.use(async (c, next) => {
  if (jwtSecretUnsafeReason(c.env)) {
    const { path, method } = c.req;
    // Only the public config, fill-assist, asset-link and icon reads are served until JWT_SECRET is fixed.
    const servable = method === 'GET' && (
      path === '/config' || path === '/api/config' || path === '/api/version' ||
      path === '/fill-assist/manifest.json' || /^\/fill-assist\/[^/]+$/i.test(path) ||
      path === '/v1/assetlinks:check' || path === '/api/v1/assetlinks:check' ||
      /^\/icons\/[^/]+\/icon\.png$/i.test(path)
    );
    if (!servable) return errorResponse('Server configuration error: JWT_SECRET is not set or too weak', 500);
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

  const budget = await new RateLimitService(c.env).consumeBudget(`${payload.sub}:api`, LIMITS.rateLimit.apiRequestsPerMinute);
  if (!budget.allowed) return tooManyRequests(budget.retryAfterSeconds);

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
  console.error('Request error:', withoutQueryParams(error));
  return errorResponse('Internal server error', 500);
});
