import { LIMITS } from './config/limits';
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
import { handleGetAccountPasskeyAssertionOptions } from './handlers/account-passkeys';
import {
  handleRegister,
  handleGetPasswordHint,
  handleRecoverTwoFactor,
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
import { StorageService } from './services/storage';
import type { Env } from './types';
import { getConfiguredWebAuthnAllowedOrigins } from './utils/origins';

type PublicRateLimiter = (category?: string, maxRequests?: number) => Promise<Response | null>;
type JwtUnsafeReason = 'missing' | 'too_short' | null;

export interface WebBootstrapResponse {
  defaultKdfIterations: number;
  jwtUnsafeReason: JwtUnsafeReason;
  jwtSecretMinLength: number;
  registrationInviteRequired: boolean;
  webAuthnAllowedOrigins: string[];
  websiteIconsEnabled: boolean;
}

function isWebsiteIconProxyEnabled(env: Env): boolean {
  return true;
}

function isSameOriginWriteRequest(request: Request): boolean {
  const targetOrigin = new URL(request.url).origin;
  const origin = request.headers.get('Origin');
  if (origin) {
    return origin === targetOrigin;
  }

  const referer = request.headers.get('Referer');
  if (referer) {
    try {
      return new URL(referer).origin === targetOrigin;
    } catch {
      return false;
    }
  }

  return false;
}

function getDefaultWebsiteIconSvg(): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 96 96" role="img" aria-label="Globe icon"><circle cx="48" cy="48" r="34" fill="none" stroke="#8ea9c7" stroke-width="6"/><path d="M14 48h68M48 14c10 10 16 21.5 16 34s-6 24-16 34c-10-10-16-21.5-16-34s6-24 16-34zm-24 10c8 5 17 8 24 8s16-3 24-8m-48 48c8-5 17-8 24-8s16 3 24 8" fill="none" stroke="#8ea9c7" stroke-width="6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

function handleNwFavicon(): Response {
  return new Response(getDefaultWebsiteIconSvg(), {
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

function buildIconServiceBase(origin: string): string {
  return `${origin}/icons`;
}

function buildIconServiceTemplate(origin: string): string {
  return `${buildIconServiceBase(origin)}/{}/icon.png`;
}

function buildIconServiceCsp(origin: string): string {
  return `img-src 'self' data: ${origin}`;
}

function buildConfigResponse(origin: string) {
  const fillAssistBase = `${origin}/fill-assist/`;
  return {
    version: LIMITS.compatibility.bitwardenServerVersion,
    gitHash: 'nodewarden',
    server: null,
    environment: {
      cloudRegion: 'self-hosted',
      vault: origin,
      api: origin + '/api',
      identity: origin + '/identity',
      notifications: origin + '/notifications',
      icons: origin,
      sso: '',
      fillAssistRules: fillAssistBase,
    },
    push: {
      pushTechnology: 0,
      vapidPublicKey: null,
    },
    communication: null,
    settings: {
      disableUserRegistration: false,
    },
    _icon_service_url: buildIconServiceTemplate(origin),
    _icon_service_csp: buildIconServiceCsp(origin),
    featureStates: {
      'cipher-key-encryption': LIMITS.compatibility.cipherKeyEncryptionFeatureEnabled,
      'duo-redirect': true,
      'email-verification': true,
      'fill-assist-targeting-rules': true,
      'pm-19051-send-email-verification': false,
      'pm-19148-innovation-archive': true,
      'pm-4516-devices-add-last-activity-date': true,
      'pm-30529-webauthn-related-origins': true,
      'unauth-ui-refresh': true,
      'web-push': false,
    },
    object: 'config',
  };
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

async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
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

async function handleWebsiteIcon(env: Env, host: string, fallbackMode: 'default' | 'not-found' = 'default'): Promise<Response> {
  if (!isWebsiteIconProxyEnabled(env)) {
    return fallbackMode === 'not-found' ? handleMissingWebsiteIcon() : handleNwFavicon();
  }

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
        (await sha256Hex(bytes)) === source.rejectImage.sha256
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
  const secret = (env.JWT_SECRET || '').trim();
  const jwtUnsafeReason =
    !secret
      ? 'missing'
      : secret.length < LIMITS.auth.jwtSecretMinLength
          ? 'too_short'
          : null;
  const storage = new StorageService(env.DB);
  const userCount = await storage.getUserCount();

  return {
    defaultKdfIterations: LIMITS.auth.defaultKdfIterations,
    jwtUnsafeReason,
    jwtSecretMinLength: LIMITS.auth.jwtSecretMinLength,
    registrationInviteRequired: userCount > 0,
    webAuthnAllowedOrigins: getConfiguredWebAuthnAllowedOrigins(env),
    websiteIconsEnabled: isWebsiteIconProxyEnabled(env),
  };
}

export async function handlePublicRoute(
  request: Request,
  env: Env,
  path: string,
  method: string,
  enforcePublicRateLimit: PublicRateLimiter
): Promise<Response | null> {
  if (path === '/.well-known/appspecific/com.chrome.devtools.json' && method === 'GET') {
    return new Response('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      },
    });
  }

  if ((path === '/api/web-bootstrap' || path === '/web-bootstrap') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(await buildWebBootstrapResponse(env));
  }

  if (path === '/fill-assist/manifest.json' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleFillAssistManifest();
  }

  if ((path === '/v1/assetlinks:check' || path === '/api/v1/assetlinks:check') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleDigitalAssetLinkCheck();
  }

  const fillAssistFormsMatch = path.match(/^\/fill-assist\/([^/]+)$/i);
  if (fillAssistFormsMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return handleFillAssistForms(fillAssistFormsMatch[1]);
  }

  const iconMatch = path.match(/^\/icons\/([^/]+)\/icon\.png$/i);
  if (iconMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-icon', LIMITS.rateLimit.publicIconRequestsPerMinute);
    if (blocked) return blocked;
    const fallbackMode = new URL(request.url).searchParams.get('fallback') === '404' ? 'not-found' : 'default';
    return handleWebsiteIcon(env, iconMatch[1], fallbackMode);
  }

  const publicAttachmentMatch = path.match(/^\/api\/attachments\/([a-f0-9-]+)\/([a-f0-9-]+)$/i);
  if (publicAttachmentMatch && method === 'GET') {
    return handlePublicDownloadAttachment(request, env, publicAttachmentMatch[1], publicAttachmentMatch[2]);
  }

  const publicAttachmentUploadMatch = path.match(/^\/api\/ciphers\/([a-f0-9-]+)\/attachment\/([a-f0-9-]+)$/i);
  if (publicAttachmentUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadAttachment(request, env, publicAttachmentUploadMatch[1], publicAttachmentUploadMatch[2]);
  }

  const publicSendUploadMatch = path.match(/^\/api\/sends\/([^/]+)\/file\/([^/]+)\/?$/i);
  if (publicSendUploadMatch && (method === 'POST' || method === 'PUT') && new URL(request.url).searchParams.has('token')) {
    return handlePublicUploadSendFile(request, env, publicSendUploadMatch[1], publicSendUploadMatch[2]);
  }

  const sendAccessMatch = path.match(/^\/api\/sends\/access\/([^/]+)$/i);
  if (sendAccessMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSend(request, env, sendAccessMatch[1]);
  }

  if (path === '/api/sends/access' && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendV2(request, env);
  }

  const sendAccessFileV2Match = path.match(/^\/api\/sends\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileV2Match && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFileV2(request, env, sendAccessFileV2Match[1]);
  }

  const sendAccessFileMatch = path.match(/^\/api\/sends\/([^/]+)\/access\/file\/([^/]+)\/?$/i);
  if (sendAccessFileMatch && method === 'POST') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return blocked;
    return handleAccessSendFile(request, env, sendAccessFileMatch[1], sendAccessFileMatch[2]);
  }

  const sendDownloadMatch = path.match(/^\/api\/sends\/([^/]+)\/([^/]+)\/?$/i);
  if (sendDownloadMatch && method === 'GET') {
    return handleDownloadSendFile(request, env, sendDownloadMatch[1], sendDownloadMatch[2]);
  }

  if ((path === '/api/auth-requests' || path === '/api/auth-requests/' || path === '/auth-requests' || path === '/auth-requests/') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleCreateAuthRequest(request, env);
  }

  const authRequestResponseMatch = path.match(/^\/(?:api\/)?auth-requests\/([a-f0-9-]+)\/response$/i);
  if (authRequestResponseMatch && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleGetAuthRequestResponse(request, env, authRequestResponseMatch[1]);
  }

  if (path === '/identity/connect/token' && method === 'POST') {
    return handleToken(request, env);
  }

  if (path === '/api/devices/knowndevice' && method === 'GET') {
    const blocked = await enforcePublicRateLimit();
    if (blocked) return jsonResponse(false);
    return handleKnownDevice(request, env);
  }

  const clearDeviceTokenMatch = path.match(/^\/api\/devices\/identifier\/([^/]+)\/clear-token$/i);
  if (clearDeviceTokenMatch && (method === 'PUT' || method === 'POST')) {
    return new Response(null, { status: 200 });
  }

  if ((path === '/identity/connect/revocation' || path === '/identity/connect/revoke') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleRevocation(request, env);
  }

  if (path === '/identity/accounts/prelogin' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handlePrelogin(request, env);
  }

  if (path === '/identity/accounts/prelogin/password' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handlePrelogin(request, env);
  }

  if (path === '/identity/accounts/webauthn/assertion-options' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleGetAccountPasskeyAssertionOptions(request, env);
  }

  if ((path === '/identity/accounts/recover-2fa' || path === '/api/accounts/recover-2fa') && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleRecoverTwoFactor(request, env);
  }

  const publicMailBackedPaths = new Set([
    '/api/accounts/resend-new-device-otp',
    '/accounts/resend-new-device-otp',
    '/api/accounts/register/send-verification-email',
    '/accounts/register/send-verification-email',
    '/identity/accounts/register/send-verification-email',
    '/api/accounts/register/verification-email-clicked',
    '/accounts/register/verification-email-clicked',
    '/identity/accounts/register/verification-email-clicked',
    '/api/accounts/register/finish',
    '/accounts/register/finish',
    '/identity/accounts/register/finish',
    '/api/accounts/verify-email-token',
    '/accounts/verify-email-token',
    '/api/two-factor/send-email-login',
    '/two-factor/send-email-login',
  ]);
  if (publicMailBackedPaths.has(path) && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return unsupportedResponse('Email delivery is not supported by this server.');
  }

  if (path === '/api/accounts/password-hint' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleGetPasswordHint(request, env);
  }

  if ((path === '/config' || path === '/api/config') && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    const origin = new URL(request.url).origin;
    return jsonResponse(buildConfigResponse(origin), 200, { 'Cache-Control': 'no-store' });
  }

  if (path === '/api/version' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-read', LIMITS.rateLimit.publicReadRequestsPerMinute);
    if (blocked) return blocked;
    return jsonResponse(LIMITS.compatibility.bitwardenServerVersion);
  }

  if (path === '/api/accounts/register' && method === 'POST') {
    const blocked = await enforcePublicRateLimit('register', LIMITS.rateLimit.registerRequestsPerMinute);
    if (blocked) return blocked;
    if (!isSameOriginWriteRequest(request)) {
      return new Response(JSON.stringify({ error: 'Forbidden origin' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return handleRegister(request, env);
  }

  if (path === '/notifications/hub/negotiate' && method === 'POST') {
    return handleNotificationsNegotiate(request, env);
  }

  if (path === '/notifications/hub' && method === 'GET') {
    return handleNotificationsHub(request, env);
  }

  if (path === '/notifications/anonymous-hub' && method === 'GET') {
    const blocked = await enforcePublicRateLimit('public-sensitive', LIMITS.rateLimit.sensitivePublicRequestsPerMinute);
    if (blocked) return blocked;
    return handleAnonymousNotificationsHub(request, env);
  }
  return null;
}
