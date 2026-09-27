import { Hono, type MiddlewareHandler } from 'hono';
import { sha256 } from 'hono/utils/crypto';
import { LIMITS } from './config/limits';
import { readEnvConfig } from './config/env';
import {
  handleAccessSend,
  handleAccessSendFile,
  handleAccessSendV2,
  handleAccessSendFileV2,
  handleDownloadSendFile,
} from './handlers/sends';
import { handleKnownDevice } from './handlers/devices';
import {
  handleDigitalAssetLinkCheck,
  handleFillAssistForms,
  handleFillAssistManifest,
} from './handlers/fill-assist';
import { handleToken, handlePrelogin, handleRevocation } from './handlers/identity';
import { handleOidcSignin, handleSsoAuthorize, handleSsoPrevalidate } from './handlers/sso';
import { handleScimRoute } from './handlers/scim';
import { handleGetAccountPasskeyAssertionOptions } from './handlers/account-passkeys';
import {
  handleRegister,
  handleRegisterFinish,
  handleRegisterSendVerificationEmail,
  handleGetPasswordHint,
  handleRecoverTwoFactor,
  handleSendTwoFactorEmailLogin,
  handleResendNewDeviceOtp,
  handleDeleteRecover,
  handleDeleteRecoverToken,
} from './handlers/accounts';
import {
  handleCreateAuthRequest,
  handleGetAuthRequestResponse,
} from './handlers/auth-requests';
import { handlePublicDownloadAttachment } from './handlers/attachments';
import { handlePublicUploadAttachment } from './handlers/attachments';
import {
  handleAnonymousNotificationsHub,
  handleNotificationsHub,
  handleNotificationsNegotiate,
} from './handlers/notifications';
import { handlePublicUploadSendFile } from './handlers/sends';
import { isSafeWebsiteIconContentType } from './utils/content-type';
import { jsonResponse, unsupportedResponse } from './utils/response';
import { createAuth } from './auth';
import type { Env } from './types';
import { getConfiguredWebAuthnAllowedOrigins, isConfiguredWebVaultOrigin, requestPublicOrigin } from './utils/origins';
import { buildConfigResponse } from './config-response';
import * as userRepo from './services/storage-user-repo';
import { RateLimitService, getClientIdentifier } from './services/ratelimit';
import type { AppEnv } from './router';

type JwtUnsafeReason = 'missing' | 'too_short' | null;

export interface WebBootstrapResponse {
  defaultKdfIterations: number;
  jwtUnsafeReason: JwtUnsafeReason;
  jwtSecretMinLength: number;
  registrationInviteRequired: boolean;
  webAuthnAllowedOrigins: string[];
}

export function jwtSecretUnsafeReason(env: Env): JwtUnsafeReason {
  const { kind } = readEnvConfig(env).JWT_SECRET;
  return kind === 'safe' ? null : kind;
}

function isSameOriginWriteRequest(request: Request, env: Env): boolean {
  const targetOrigin = new URL(request.url).origin;
  const originHeader = request.headers.get('Origin');
  if (originHeader) {
    if (originHeader === targetOrigin) return true;
    return isConfiguredWebVaultOrigin(env, originHeader);
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      const refererOrigin = new URL(referer).origin;
      if (refererOrigin === targetOrigin) return true;
      return isConfiguredWebVaultOrigin(env, refererOrigin);
    } catch {
      return false;
    }
  }

  // Non-browser API clients (CLI, Playwright request, curl) omit Origin.
  return true;
}

const DEFAULT_WEBSITE_ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="Globe icon"><circle cx="48" cy="48" r="34" fill="none" stroke="#8ea9c7" stroke-width="6"/><path d="M14 48h68M48 14c10 10 16 21.5 16 34s-6 24-16 34c-10-10-16-21.5-16-34s6-24 16-34zm-24 10c8 5 17 8 24 8s16-3 24-8m-48 48c8-5 17-8 24-8s16 3 24 8" fill="none" stroke="#8ea9c7" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function handleNwFavicon(): Response {
  return new Response(DEFAULT_WEBSITE_ICON_SVG, {
    status: 200,
    headers: {
      'Content-Type': 'image/svg+xml; charset=utf-8',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}, immutable`,
    },
  });
}

function handleMissingWebsiteIcon(): Response {
  return new Response(null, {
    status: 404,
    headers: {
      'Cache-Control': 'public, max-age=300',
    },
  });
}

function normalizeIconHost(rawHost: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(String(rawHost || '').trim()).toLowerCase().replace(/\.+$/, '');
  } catch {
    return null;
  }
  if (!decoded || decoded.includes('/') || decoded.includes('\\')) return null;
  try {
    const parsed = new URL(`https://${decoded}`);
    return parsed.hostname === decoded ? decoded : null;
  } catch {
    return null;
  }
}

const ICON_UPSTREAM_TIMEOUT_MS = 2500;
const ICON_MAX_BUFFER_BYTES = 256 * 1024;
const BITWARDEN_DEFAULT_GLOBE_ICON_BYTES = 500;
const BITWARDEN_DEFAULT_GLOBE_ICON_SHA256 = 'aaa64871332ad5b7d28fe8874efb19c2d9cc2f1e6de75d52b080b438225a0783';

type IconSource = {
  url: string;
  rejectImage?: {
    byteLength: number;
    sha256: string;
  };
  headers?: HeadersInit;
};

async function fetchIconSource(source: { url: string; headers?: HeadersInit }): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), ICON_UPSTREAM_TIMEOUT_MS);
  try {
    return await fetch(source.url, {
      headers: source.headers,
      redirect: 'follow',
      signal: controller.signal,
      cf: {
        cacheEverything: true,
        cacheTtl: LIMITS.cache.iconTtlSeconds,
      },
    } as RequestInit & { cf: { cacheEverything: boolean; cacheTtl: number } });
  } finally {
    clearTimeout(timeout);
  }
}

function getPositiveContentLength(headers: Headers): number | null {
  const raw = headers.get('Content-Length');
  if (!raw) return null;
  const value = Number(raw);
  return Number.isFinite(value) && value > 0 ? value : null;
}

async function readIconBytes(response: Response, maxBytes: number): Promise<ArrayBuffer | null> {
  if (!response.body) return null;
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    void reader.cancel().catch(() => undefined);
  }, ICON_UPSTREAM_TIMEOUT_MS);

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }

  if (timedOut || totalBytes === 0) return null;

  const output = new ArrayBuffer(totalBytes);
  const bytes = new Uint8Array(output);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function iconResponse(body: BodyInit | null, contentType: string | null): Response {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': contentType || 'image/png',
      'Cache-Control': `public, max-age=${LIMITS.cache.iconTtlSeconds}, immutable`,
      'Content-Security-Policy': "default-src 'none'; img-src 'self' data:; sandbox",
    },
  });
}

async function handleWebsiteIcon(host: string, fallbackMode: 'default' | 'not-found' = 'default'): Promise<Response> {
  const normalizedHost = normalizeIconHost(host);
  if (!normalizedHost) return fallbackMode === 'not-found' ? handleMissingWebsiteIcon() : handleNwFavicon();

  const encodedHost = encodeURIComponent(normalizedHost);
  const requestHeaders = { 'User-Agent': 'NodeWarden/1.0' };
  const upstreamSources: IconSource[] = [
    {
      url: `https://favicon.im/zh/${encodedHost}?larger=true&throw-error-on-404=true`,
      headers: requestHeaders,
    },
    {
      url: `https://icons.bitwarden.net/${encodedHost}/icon.png`,
      rejectImage: {
        byteLength: BITWARDEN_DEFAULT_GLOBE_ICON_BYTES,
        sha256: BITWARDEN_DEFAULT_GLOBE_ICON_SHA256,
      },
      headers: requestHeaders,
    },
  ];

  for (const source of upstreamSources) {
    try {
      const resp = await fetchIconSource(source);

      if (!resp.ok) continue;
      const contentType = String(resp.headers.get('Content-Type') || '').toLowerCase();
      if (!isSafeWebsiteIconContentType(contentType)) continue;

      const contentLength = getPositiveContentLength(resp.headers);
      if (contentLength !== null && contentLength > ICON_MAX_BUFFER_BYTES) continue;

      const bytes = await readIconBytes(resp, ICON_MAX_BUFFER_BYTES);
      if (!bytes) continue;
      if (
        source.rejectImage &&
        bytes.byteLength === source.rejectImage.byteLength &&
        (await sha256(bytes)) === source.rejectImage.sha256
      ) {
        continue;
      }

      return iconResponse(bytes, resp.headers.get('Content-Type'));
    } catch {
      continue;
    }
  }

  return fallbackMode === 'not-found' ? handleMissingWebsiteIcon() : handleNwFavicon();
}

export async function buildWebBootstrapResponse(env: Env): Promise<WebBootstrapResponse> {
  const jwtUnsafeReason = jwtSecretUnsafeReason(env);
  const userCount = await userRepo.getUserCount(env.DB);

  return {
    defaultKdfIterations: LIMITS.auth.defaultKdfIterations,
    jwtUnsafeReason,
    jwtSecretMinLength: LIMITS.auth.jwtSecretMinLength,
    registrationInviteRequired: userCount > 0,
    webAuthnAllowedOrigins: getConfiguredWebAuthnAllowedOrigins(env),
  };
}

export function tooManyRequests(retryAfterSeconds: number | undefined): Response {
  return new Response(
    JSON.stringify({
      error: 'Too many requests',
      error_description: `Rate limit exceeded. Try again in ${retryAfterSeconds} seconds.`,
    }),
    {
      status: 429,
      headers: {
        'Content-Type': 'application/json',
        'Retry-After': String(retryAfterSeconds || 60),
        'X-RateLimit-Remaining': '0',
      },
    }
  );
}

async function enforcePublicRateLimit(
  request: Request,
  env: Env,
  category: string = 'public',
  maxRequests: number = LIMITS.rateLimit.publicRequestsPerMinute
): Promise<Response | null> {
  const clientId = getClientIdentifier(request);
  if (!clientId) {
    return new Response(
      JSON.stringify({
        error: 'Forbidden',
        error_description: 'Client IP is required',
      }),
      {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      }
    );
  }

  const rateLimit = new RateLimitService(env);
  const shouldUseStrictBudget = category === 'public-sensitive' || category === 'register';
  const check = shouldUseStrictBudget
    ? await rateLimit.consumeStrictBudget(`${clientId}:${category}`, maxRequests)
    : await rateLimit.consumeBudget(`${clientId}:${category}`, maxRequests);
  return check.allowed ? null : tooManyRequests(check.retryAfterSeconds);
}

const publicRateLimit = (category?: string, maxRequests?: number): MiddlewareHandler<AppEnv> => async (c, next) => {
  const blocked = await enforcePublicRateLimit(c.req.raw, c.env, category, maxRequests);
  if (blocked) return blocked;
  await next();
};

const publicRead = publicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
const publicSensitive = publicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
const register = publicRateLimit('register', LIMITS.rateLimit.registerRequestsPerMinute);

const requireSameOriginWrite: MiddlewareHandler<AppEnv> = async (c, next) => {
  if (!isSameOriginWriteRequest(c.req.raw, c.env)) {
    return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
      status: 403,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  await next();
};

const hasUploadToken = (request: Request): boolean => new URL(request.url).searchParams.has('token');

export const publicRoutes = new Hono<AppEnv>();

publicRoutes.on('ALL', ['/api/auth', '/api/auth/*'], (c) => createAuth(c.env, c.req.raw).handler(c.req.raw));

publicRoutes.on('GET', ['/api/web-bootstrap', '/web-bootstrap'], publicRead, async (c) => jsonResponse(await buildWebBootstrapResponse(c.env)));
publicRoutes.get('/fill-assist/manifest.json', publicRead, () => handleFillAssistManifest());
publicRoutes.on('GET', ['/v1/assetlinks:check', '/api/v1/assetlinks:check'], publicRead, () => handleDigitalAssetLinkCheck());
publicRoutes.get('/fill-assist/:filename', publicRead, (c) => handleFillAssistForms(c.req.param('filename')));
publicRoutes.get('/icons/:host/icon.png', publicRateLimit('public-icon', LIMITS.rateLimit.publicIconRequestsPerMinute), (c) => {
  const fallbackMode = c.req.query('fallback') === '404' ? 'not-found' : 'default';
  return handleWebsiteIcon(c.req.param('host'), fallbackMode);
});

publicRoutes.get('/api/attachments/:cipherId{[a-f0-9-]+}/:attachmentId{[a-f0-9-]+}', (c) => handlePublicDownloadAttachment(c.req.raw, c.env, c.req.param('cipherId'), c.req.param('attachmentId')));
// Token-bearing uploads are anonymous; without a token the same paths fall through to the
// authenticated upload routes.
publicRoutes.on(['POST', 'PUT'], '/api/ciphers/:cipherId{[a-f0-9-]+}/attachment/:attachmentId{[a-f0-9-]+}', async (c, next) => {
  if (!hasUploadToken(c.req.raw)) return next();
  return handlePublicUploadAttachment(c.req.raw, c.env, c.req.param('cipherId'), c.req.param('attachmentId'));
});
publicRoutes.on(['POST', 'PUT'], '/api/sends/:sendId/file/:fileId', async (c, next) => {
  if (!hasUploadToken(c.req.raw)) return next();
  return handlePublicUploadSendFile(c.req.raw, c.env, c.req.param('sendId'), c.req.param('fileId'));
});

publicRoutes.post('/api/sends/access/:accessId', publicRateLimit(), (c) => handleAccessSend(c.req.raw, c.env, c.req.param('accessId')));
publicRoutes.post('/api/sends/access', publicRateLimit(), (c) => handleAccessSendV2(c.req.raw, c.env));
publicRoutes.post('/api/sends/access/file/:fileId', publicRateLimit(), (c) => handleAccessSendFileV2(c.req.raw, c.env, c.req.param('fileId')));
publicRoutes.post('/api/sends/:sendId/access/file/:fileId', publicRateLimit(), (c) => handleAccessSendFile(c.req.raw, c.env, c.req.param('sendId'), c.req.param('fileId')));
publicRoutes.get('/api/sends/:sendId/:fileId', (c) => handleDownloadSendFile(c.req.raw, c.env, c.req.param('sendId'), c.req.param('fileId')));

publicRoutes.on('POST', ['/api/auth-requests', '/auth-requests'], publicSensitive, (c) => handleCreateAuthRequest(c.req.raw, c.env));
publicRoutes.on('GET', ['/api/auth-requests/:id{[a-f0-9-]+}/response', '/auth-requests/:id{[a-f0-9-]+}/response'], publicSensitive, (c) => handleGetAuthRequestResponse(c.req.raw, c.env, c.req.param('id')));

publicRoutes.post('/identity/connect/token', (c) => handleToken(c.req.raw, c.env));
publicRoutes.on('GET', ['/identity/sso/prevalidate', '/sso/prevalidate'], (c) => handleSsoPrevalidate(c.env));
publicRoutes.on('GET', ['/identity/connect/authorize', '/connect/authorize'], (c) => handleSsoAuthorize(c.req.raw, c.env));
publicRoutes.on('GET', ['/identity/oidc-signin', '/oidc-signin'], (c) => handleOidcSignin(c.req.raw, c.env));

publicRoutes.use(async (c, next) => {
  const scim = await handleScimRoute(c.req.raw, c.env, c.req.path);
  if (scim) return scim;
  await next();
});

publicRoutes.get('/api/devices/knowndevice', async (c) => (await enforcePublicRateLimit(c.req.raw, c.env)) ? jsonResponse(false) : handleKnownDevice(c.req.raw, c.env));
publicRoutes.on(['PUT', 'POST'], '/api/devices/identifier/:deviceId/clear-token', () => new Response(null, { status: 200 }));

publicRoutes.on('POST', ['/identity/connect/revocation', '/identity/connect/revoke'], publicSensitive, (c) => handleRevocation(c.req.raw, c.env));
publicRoutes.on('POST', ['/identity/accounts/prelogin', '/identity/accounts/prelogin/password'], publicSensitive, (c) => handlePrelogin(c.req.raw, c.env));
publicRoutes.get('/identity/accounts/webauthn/assertion-options', publicSensitive, (c) => handleGetAccountPasskeyAssertionOptions(c.req.raw, c.env));
publicRoutes.on('POST', ['/identity/accounts/recover-2fa', '/api/accounts/recover-2fa'], publicSensitive, (c) => handleRecoverTwoFactor(c.req.raw, c.env));
publicRoutes.on('POST', ['/api/two-factor/send-email-login', '/two-factor/send-email-login'], publicSensitive, (c) => handleSendTwoFactorEmailLogin(c.req.raw, c.env));
publicRoutes.on('POST', ['/api/accounts/resend-new-device-otp', '/accounts/resend-new-device-otp'], publicSensitive, (c) => handleResendNewDeviceOtp(c.req.raw, c.env));
publicRoutes.on('POST', ['/api/accounts/delete-recover', '/accounts/delete-recover'], publicSensitive, (c) => handleDeleteRecover(c.req.raw, c.env));
publicRoutes.on('POST', ['/api/accounts/delete-recover-token', '/accounts/delete-recover-token'], publicSensitive, (c) => handleDeleteRecoverToken(c.req.raw, c.env));

publicRoutes.on('POST', [
  '/api/accounts/register/verification-email-clicked',
  '/accounts/register/verification-email-clicked',
  '/identity/accounts/register/verification-email-clicked',
  '/api/accounts/verify-email-token',
  '/accounts/verify-email-token',
], publicSensitive, () => unsupportedResponse('Email delivery is not supported by this server.'));

publicRoutes.post('/api/accounts/password-hint', publicSensitive, requireSameOriginWrite, (c) => handleGetPasswordHint(c.req.raw, c.env));

publicRoutes.on('GET', ['/alive', '/api/alive'], () => new Response('OK', {
  status: 200,
  headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
}));
publicRoutes.on('GET', ['/config', '/api/config'], publicRead, (c) => jsonResponse(buildConfigResponse(requestPublicOrigin(c.req.raw)), 200, { 'Cache-Control': 'no-store' }));
publicRoutes.get('/api/version', publicRead, () => jsonResponse(LIMITS.compatibility.bitwardenServerVersion));

publicRoutes.on('POST', [
  '/api/accounts/register/send-verification-email',
  '/accounts/register/send-verification-email',
  '/identity/accounts/register/send-verification-email',
], register, requireSameOriginWrite, (c) => handleRegisterSendVerificationEmail(c.req.raw, c.env));
publicRoutes.on('POST', [
  '/api/accounts/register/finish',
  '/accounts/register/finish',
  '/identity/accounts/register/finish',
], register, requireSameOriginWrite, (c) => handleRegisterFinish(c.req.raw, c.env));
publicRoutes.on('POST', ['/api/accounts/register', '/identity/accounts/register'], register, requireSameOriginWrite, (c) => handleRegister(c.req.raw, c.env));

publicRoutes.post('/notifications/hub/negotiate', (c) => handleNotificationsNegotiate(c.req.raw, c.env));
publicRoutes.get('/notifications/hub', (c) => handleNotificationsHub(c.req.raw, c.env));
publicRoutes.get('/notifications/anonymous-hub', publicSensitive, (c) => handleAnonymousNotificationsHub(c.req.raw, c.env));
