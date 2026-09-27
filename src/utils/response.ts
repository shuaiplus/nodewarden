import { isAdminPortalPath } from '../web-vault-visibility';
import { LIMITS } from '../config/limits';
import type { Env } from '../types';
import {
  isBrowserExtensionOrigin,
  isConfiguredWebAuthnAllowedOrigin,
  isConfiguredWebVaultOrigin,
  isOfficialBitwardenDesktopOrigin,
  normalizeOrigin,
} from './origins';

const CORS_METHODS = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
const DEFAULT_CORS_HEADERS = [
  'Content-Type',
  'Authorization',
  'Accept',
  'Device-Type',
  'Device-Identifier',
  'Device-Name',
  'Bitwarden-Client-Name',
  'Bitwarden-Client-Version',
  'Bitwarden-Package-Type',
  'Is-Prerelease',
  'X-Request-Email',
  'X-Device-Identifier',
  'X-Device-Name',
  'X-NodeWarden-Web-Session',
];

function isWildcardCorsPath(path: string): boolean {
  return (
    path.startsWith('/icons/')
    || path.startsWith('/fill-assist/')
    || path === '/v1/assetlinks:check'
    || path === '/api/v1/assetlinks:check'
    || path === '/config'
    || path === '/api/config'
    || path === '/api/version'
  );
}

function getCorsPolicy(request: Request, env: Env): { allowOrigin: string | null; allowCredentials: boolean } {
  const url = new URL(request.url);
  const originHeader = request.headers.get('Origin');
  if (!originHeader) {
    return isWildcardCorsPath(url.pathname)
      ? { allowOrigin: '*', allowCredentials: false }
      : { allowOrigin: null, allowCredentials: false };
  }
  const origin = normalizeOrigin(originHeader);
  if (origin === url.origin || isConfiguredWebVaultOrigin(env, origin)) {
    return { allowOrigin: origin, allowCredentials: true };
  }
  if (
    (isBrowserExtensionOrigin(origin) || isOfficialBitwardenDesktopOrigin(origin))
    && isConfiguredWebAuthnAllowedOrigin(env, origin)
  ) {
    return { allowOrigin: origin, allowCredentials: true };
  }
  if (isWildcardCorsPath(url.pathname)) {
    return { allowOrigin: '*', allowCredentials: false };
  }
  return { allowOrigin: null, allowCredentials: false };
}

function buildCorsHeaders(request: Request, env: Env): Record<string, string> {
  if (isAdminPortalPath(new URL(request.url).pathname)) return {};
  const requestedHeaders = String(request.headers.get('Access-Control-Request-Headers') || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const allowHeaders = Array.from(new Set([...DEFAULT_CORS_HEADERS, ...requestedHeaders]));

  const headers: Record<string, string> = {
    'Access-Control-Allow-Methods': CORS_METHODS,
    'Access-Control-Allow-Headers': allowHeaders.join(', '),
    'Access-Control-Expose-Headers': '*',
    'Access-Control-Max-Age': String(LIMITS.cors.preflightMaxAgeSeconds),
  };

  const corsPolicy = getCorsPolicy(request, env);
  if (corsPolicy.allowOrigin) {
    headers['Access-Control-Allow-Origin'] = corsPolicy.allowOrigin;
    if (corsPolicy.allowCredentials) {
      headers['Access-Control-Allow-Credentials'] = 'true';
    }
    headers['Vary'] = 'Origin, Access-Control-Request-Headers';
  }

  return headers;
}

export function applyCors(
  request: Request,
  response: Response,
  env: Env
): Response {
  // WebSocket upgrade responses must be returned untouched.
  const webSocket = (response as Response & { webSocket?: unknown }).webSocket;
  if (response.status === 101 || webSocket) {
    return response;
  }

  const headers = new Headers(response.headers);
  const corsHeaders = buildCorsHeaders(request, env);
  for (const [k, v] of Object.entries(corsHeaders)) {
    headers.set(k, v);
  }
  // Security headers applied to every response.
  headers.set('X-Content-Type-Options', 'nosniff');
  if (!headers.has('Referrer-Policy')) headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  const isWebAuthnFrameConnector = new URL(request.url).pathname === '/webauthn-connector.html';
  if (isWebAuthnFrameConnector) {
    // Official desktop and browser clients render this exact endpoint inside a
    // 40px cross-origin iframe. The connector validates its parent before any
    // WebAuthn request or postMessage, so only this protocol page may be framed.
    headers.delete('X-Frame-Options');
    headers.set(
      'Content-Security-Policy',
      "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'"
    );
  } else {
    headers.set('X-Frame-Options', 'DENY');
  }
  if (!isWebAuthnFrameConnector && !headers.has('Content-Security-Policy')) {
    headers.set('Content-Security-Policy', "frame-ancestors 'none'; img-src 'self' data:");
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// JSON response helper
export function jsonResponse(data: any, status: number = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
  });
}

// Error response helper. The top-level fields mirror upstream ErrorResponseModel,
// which official clients read for non-identity calls; error/error_description and
// ErrorModel stay for identity-style readers and the NodeWarden webapp.
export function errorResponse(
  message: string,
  status: number = 400,
  headers: Record<string, string> = {},
  validationErrors: Record<string, string[]> | null = null
): Response {
  return jsonResponse(
    {
      message,
      validationErrors,
      object: 'error',
      error: message,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status,
    headers
  );
}

export function deviceErrorResponse(kind: 'required' | 'invalid_otp'): Response {
  return jsonResponse({
    error: 'device_error',
    error_description: kind === 'required' ? 'New device verification required' : 'Invalid New Device OTP',
    ErrorModel: { Message: kind === 'required' ? 'new device verification required' : 'invalid new device otp', Object: 'error' },
  }, 400, { 'Cache-Control': 'no-store' });
}

export function unsupportedResponse(message: string = 'This feature is not supported by this server.'): Response {
  return errorResponse(message, 501);
}

// Identity endpoint error response (for /identity/connect/token)
export function identityErrorResponse(
  message: string,
  error: string = 'invalid_grant',
  status: number = 400,
  headers: Record<string, string> = {}
): Response {
  return jsonResponse(
    {
      error: error,
      error_description: message,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    status,
    { 'Cache-Control': 'no-store', Pragma: 'no-cache', ...headers }
  );
}

// Handle CORS preflight
export function handleCors(request: Request, env: Env): Response {
  return new Response(null, {
    status: 204,
    headers: buildCorsHeaders(request, env),
  });
}

// HTML response helper
export function htmlResponse(html: string, status: number = 200): Response {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
    },
  });
}

// Official clients post camelCase; older and .NET-style clients post PascalCase. Lower-casing the
// first letter of every PascalCase key once at parse time lets handlers read one spelling. Keys whose
// second character is not lowercase (ids, acronyms such as OTP) keep their case, and a camelCase key
// already present wins over its PascalCase twin.
export function normalizeJsonKeys<T>(value: T): T {
  if (Array.isArray(value)) return value.map(normalizeJsonKeys) as T;
  if (!value || typeof value !== 'object') return value;
  const source = value as Record<string, unknown>;
  const normalized: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(source)) {
    const name = /^[A-Z][a-z]/.test(key) ? key[0].toLowerCase() + key.slice(1) : key;
    if (name !== key && name in source) continue;
    normalized[name] = normalizeJsonKeys(entry);
  }
  return normalized as T;
}

// Parses a JSON body with normalized keys, or answers 400. Scalars read as an empty object; arrays
// pass through for the routes that take a bare list.
export async function parseJsonBody<T extends object = Record<string, unknown>>(request: Request, message = 'Invalid JSON'): Promise<T | Response> {
  try {
    const body: unknown = normalizeJsonKeys(await request.json());
    return (body && typeof body === 'object' ? body : {}) as T;
  } catch {
    return errorResponse(message, 400);
  }
}

// Reads the first present key from a normalized body, telling absent apart from null.
export function prop<T = unknown>(source: unknown, keys: string | string[]): { present: boolean; value: T | undefined } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  const record = source as Record<string, unknown>;
  const key = (Array.isArray(keys) ? keys : [keys]).find((candidate) => Object.prototype.hasOwnProperty.call(record, candidate));
  return key === undefined ? { present: false, value: undefined } : { present: true, value: record[key] as T };
}

export function readString(source: unknown, keys: string | string[]): string {
  const { value } = prop(source, keys);
  return typeof value === 'string' ? value : '';
}
