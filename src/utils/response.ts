import { z } from 'zod';
import { isAdminPortalPath } from '../web-vault-visibility';
import type { Env } from '../types';
import {
  isBrowserExtensionOrigin,
  isConfiguredWebAuthnAllowedOrigin,
  isConfiguredWebVaultOrigin,
  isOfficialBitwardenDesktopOrigin,
  normalizeOrigin,
} from './origins';

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

export type CorsPolicy = { kind: 'credentialed'; origin: string } | { kind: 'public' } | { kind: 'none' };

// This Worker, configured vault origins and trusted extension or desktop origins may read responses
// with credentials; anyone may read the wildcard paths without them; the admin portal is never shared.
export function corsPolicy(request: Request, env: Env): CorsPolicy {
  const url = new URL(request.url);
  if (isAdminPortalPath(url.pathname)) return { kind: 'none' };
  const origin = normalizeOrigin(request.headers.get('Origin'));
  if (origin && (
    origin === url.origin
    || isConfiguredWebVaultOrigin(env, origin)
    || ((isBrowserExtensionOrigin(origin) || isOfficialBitwardenDesktopOrigin(origin)) && isConfiguredWebAuthnAllowedOrigin(env, origin))
  )) {
    return { kind: 'credentialed', origin };
  }
  return isWildcardCorsPath(url.pathname) ? { kind: 'public' } : { kind: 'none' };
}

// Responses built outside the Hono app (static assets, the database-unavailable error) miss its cors
// middleware, so they take the same origin decision here.
export function applyCors(request: Request, response: Response, env: Env): Response {
  const secured = applySecurityHeaders(request, response);
  const policy = corsPolicy(request, env);
  if (policy.kind === 'none') return secured;
  secured.headers.set('Access-Control-Allow-Origin', policy.kind === 'public' ? '*' : policy.origin);
  if (policy.kind === 'credentialed') secured.headers.set('Access-Control-Allow-Credentials', 'true');
  secured.headers.append('Vary', 'Origin');
  return secured;
}

export function applySecurityHeaders(request: Request, response: Response): Response {
  // WebSocket upgrade responses must be returned untouched.
  const webSocket = (response as Response & { webSocket?: unknown }).webSocket;
  if (response.status === 101 || webSocket) {
    return response;
  }

  const headers = new Headers(response.headers);
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
export function jsonResponse(data: unknown, status: number = 200, headers: Record<string, string> = {}): Response {
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
// ErrorModel stay for identity-style readers.
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

// Identity calls and some older clients post url-encoded forms; JSON arrives with normalized keys.
export async function readFormOrJson(request: Request): Promise<unknown> {
  return request.headers.get('content-type')?.includes('application/x-www-form-urlencoded')
    ? Object.fromEntries(await request.formData())
    : normalizeJsonKeys(await request.json());
}

// Reads the body or answers 400. Scalars read as an empty object; arrays pass through for the routes
// that take a bare list.
async function readBodyObject(request: Request, message = 'Invalid JSON'): Promise<object | Response> {
  try {
    const body = await readFormOrJson(request);
    return body && typeof body === 'object' ? body : {};
  } catch {
    return errorResponse(message, 400);
  }
}

// Zod request bodies. parseBody reads the body through readBodyObject, so the schema sees camelCase keys
// even when official clients send PascalCase, and resolves to the schema output or to a 400 Response callers
// return as is: `message` (default 'Invalid JSON') for an unreadable body, otherwise the first issue's
// message with validationErrors from bodyIssues, every issue message grouped under its dotted path ('' for
// the body itself) as in upstream ErrorResponseModel.
export function bodyIssues(error: z.ZodError): Record<string, string[]> {
  return Object.fromEntries(error.issues.reduce((byPath, { path, message }) => {
    const field = path.join('.');
    return byPath.set(field, [...(byPath.get(field) ?? []), message]);
  }, new Map<string, string[]>()));
}

export async function parseBody<S extends z.ZodType>(request: Request, schema: S, message?: string): Promise<z.output<S> | Response> {
  const body = await readBodyObject(request, message);
  if (body instanceof Response) return body;
  const result = schema.safeParse(body);
  return result.success ? result.data : errorResponse(result.error.issues[0].message, 400, {}, bodyIssues(result.error));
}
