import type { Env } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import * as orgRepo from '../services/storage-org-repo';
import { PolicyType } from '../services/org-types';

export const FAKE_SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

export function isSsoEnabled(env: Env): boolean {
  return String(env.SSO_ENABLED || '').trim() === '1' && !!env.SSO_AUTHORITY && !!env.SSO_CLIENT_ID;
}

export function isSsoOnly(env: Env): boolean {
  return String(env.SSO_ONLY || '').trim() === '1';
}

export async function userRequiresSso(env: Env, userId: string): Promise<boolean> {
  if (isSsoOnly(env)) return true;
  const policies = await orgRepo.listEnabledPoliciesForUser(env.DB, userId);
  return policies.some((policy) => policy.type === PolicyType.RequireSso && policy.enabled);
}

export async function handleSsoPrevalidate(env: Env): Promise<Response> {
  if (!isSsoEnabled(env)) return errorResponse('SSO is not enabled', 404);
  const now = Math.floor(Date.now() / 1000);
  const token = await signOpaque(env.JWT_SECRET, { sub: 'nodewarden-sso', nbf: now, exp: now + 120 });
  return jsonResponse({ token });
}

export async function handleSsoAuthorize(request: Request, env: Env): Promise<Response> {
  if (!isSsoEnabled(env)) return errorResponse('SSO is not enabled', 404);
  const url = new URL(request.url);
  const state = url.searchParams.get('state') || generateUUID();
  const codeChallenge = url.searchParams.get('code_challenge');
  const clientId = url.searchParams.get('client_id') || 'web';
  const rawRedirect = url.searchParams.get('redirect_uri') || '';
  const redirectUri = resolveClientRedirect(clientId, rawRedirect, url.origin);
  if (!redirectUri) return errorResponse('Invalid redirect_uri', 400);

  const now = new Date().toISOString();
  await orgRepo.saveSsoAuth(env.DB, {
    state,
    codeChallenge,
    redirectUri,
    clientId,
    bindingHash: null,
    createdAt: now,
    updatedAt: now,
  });
  if (env.CACHE_KV) {
    await env.CACHE_KV.put(`sso:state:${state}`, JSON.stringify({ redirectUri, clientId, codeChallenge }), { expirationTtl: 600 });
  }

  const authority = String(env.SSO_AUTHORITY || '').replace(/\/+$/, '');
  const target = new URL(await discoverAuthorizationEndpoint(authority));
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('client_id', String(env.SSO_CLIENT_ID));
  target.searchParams.set('redirect_uri', `${url.origin}/identity/oidc-signin`);
  target.searchParams.set('scope', env.SSO_SCOPES || 'openid profile email');
  target.searchParams.set('state', state);
  if (codeChallenge) {
    target.searchParams.set('code_challenge', codeChallenge);
    target.searchParams.set('code_challenge_method', 'S256');
  }
  return Response.redirect(target.toString(), 302);
}

export async function handleOidcSignin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const state = url.searchParams.get('state') || '';
  const code = url.searchParams.get('code');
  const error = url.searchParams.get('error');
  const session = await orgRepo.getSsoAuth(env.DB, state);
  if (!session) return errorResponse('Unknown SSO state', 400);
  const now = new Date().toISOString();
  await orgRepo.saveSsoAuth(env.DB, {
    ...session,
    codeChallenge: session.codeChallenge,
    redirectUri: session.redirectUri,
    clientId: session.clientId,
    bindingHash: session.bindingHash,
    codeResponse: code,
    codeResponseError: error,
    createdAt: now,
    updatedAt: now,
  });
  const redirect = new URL(session.redirectUri);
  if (code) redirect.searchParams.set('code', code);
  redirect.searchParams.set('state', state);
  if (error) redirect.searchParams.set('error', error);
  return Response.redirect(redirect.toString(), 302);
}

export interface OidcIdentity {
  email: string;
  name: string | null;
  identifier: string;
  /** Whether the identity provider asserts the `email` claim is verified. */
  emailVerified: boolean;
}

export async function exchangeOidcCode(env: Env, code: string, redirectOrigin: string): Promise<OidcIdentity | null> {
  const authority = String(env.SSO_AUTHORITY || '').replace(/\/+$/, '');
  const tokenUrl = await discoverTokenEndpoint(authority);
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: String(env.SSO_CLIENT_ID),
    redirect_uri: `${redirectOrigin}/identity/oidc-signin`,
  });
  if (env.SSO_CLIENT_SECRET) body.set('client_secret', env.SSO_CLIENT_SECRET);
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) return null;
  const payload = await response.json() as { id_token?: string; access_token?: string };
  const claims = await verifyIdToken(env, authority, payload.id_token || '');
  if (!claims) return null;
  const verifiedEmail = String(claims.email || '').trim().toLowerCase();
  const email = verifiedEmail || String(claims.preferred_username || '').trim().toLowerCase();
  const identifier = String(claims.sub || email);
  if (!email || !identifier) return null;
  return {
    email,
    name: claims.name ? String(claims.name) : null,
    identifier,
    // `email_verified` only attests the `email` claim, never the preferred_username
    // fallback. Some providers emit it as the string "true" instead of a boolean.
    emailVerified: !!verifiedEmail && (claims.email_verified === true || claims.email_verified === 'true'),
  };
}

function resolveClientRedirect(clientId: string, raw: string, origin: string): string | null {
  if (clientId === 'web' || clientId === 'browser') return `${origin}/sso-connector.html`;
  if (clientId === 'desktop' || clientId === 'mobile') return 'bitwarden://sso-callback';
  if (clientId === 'cli' && /^http:\/\/localhost:\d{4}$/.test(raw)) return raw;
  return isSameOrigin(raw, origin) ? raw : null;
}

// A prefix test would accept https://host.evil.com for the origin https://host.ev,
// so redirect targets must parse and match the origin exactly.
function isSameOrigin(raw: string, origin: string): boolean {
  try {
    return new URL(raw).origin === origin;
  } catch {
    return false;
  }
}

interface OidcDiscovery {
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
}

interface JsonWebKeyEntry extends JsonWebKey {
  kid?: string;
}

const DISCOVERY_CACHE_TTL_MS = 5 * 60 * 1000;
const discoveryCache = new Map<string, { expiresAt: number; document: OidcDiscovery }>();
const jwksCache = new Map<string, { expiresAt: number; keys: JsonWebKeyEntry[] }>();

// Signature algorithms we accept on an id_token, with the WebCrypto parameters and
// the JWK key type each one requires. `alg: none` and HMAC are excluded by omission.
const ID_TOKEN_ALGORITHMS = {
  RS256: {
    kty: 'RSA',
    importParams: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as SubtleCryptoImportKeyAlgorithm,
    verifyParams: { name: 'RSASSA-PKCS1-v1_5' } as SubtleCryptoSignAlgorithm,
  },
  ES256: {
    kty: 'EC',
    importParams: { name: 'ECDSA', namedCurve: 'P-256' } as SubtleCryptoImportKeyAlgorithm,
    verifyParams: { name: 'ECDSA', hash: 'SHA-256' } as SubtleCryptoSignAlgorithm,
  },
} as const;

const ID_TOKEN_CLOCK_SKEW_SECONDS = 60;

async function discoverOidcConfig(authority: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(authority);
  if (cached && cached.expiresAt > Date.now()) return cached.document;
  try {
    const response = await fetch(`${authority}/.well-known/openid-configuration`);
    if (!response.ok) return {};
    const document = await response.json() as OidcDiscovery;
    discoveryCache.set(authority, { expiresAt: Date.now() + DISCOVERY_CACHE_TTL_MS, document });
    return document;
  } catch {
    return {};
  }
}

async function discoverAuthorizationEndpoint(authority: string): Promise<string> {
  const { authorization_endpoint: endpoint } = await discoverOidcConfig(authority);
  return endpoint || `${authority}/authorize`;
}

async function discoverTokenEndpoint(authority: string): Promise<string> {
  const { token_endpoint: endpoint } = await discoverOidcConfig(authority);
  return endpoint || `${authority}/token`;
}

async function fetchJwks(authority: string): Promise<JsonWebKeyEntry[]> {
  const cached = jwksCache.get(authority);
  if (cached && cached.expiresAt > Date.now()) return cached.keys;
  const { jwks_uri: jwksUri } = await discoverOidcConfig(authority);
  try {
    const response = await fetch(jwksUri || `${authority}/.well-known/jwks.json`);
    if (!response.ok) return [];
    const body = await response.json() as { keys?: JsonWebKeyEntry[] };
    const keys = Array.isArray(body.keys) ? body.keys : [];
    jwksCache.set(authority, { expiresAt: Date.now() + DISCOVERY_CACHE_TTL_MS, keys });
    return keys;
  } catch {
    return [];
  }
}

function selectJwk(keys: JsonWebKeyEntry[], kid: string, kty: string, alg: string): JsonWebKeyEntry | null {
  const candidates = keys.filter((key) =>
    key.kty === kty && (!key.use || key.use === 'sig') && (!key.alg || key.alg === alg));
  return candidates.find((key) => !!kid && key.kid === kid) || candidates[0] || null;
}

// JWKS entries carry metadata (`use`, `key_ops`, `x5c`, …) that a verify-only
// WebCrypto import rejects or ignores, so hand importKey just the key material.
function toVerificationKey(jwk: JsonWebKeyEntry): JsonWebKey {
  return jwk.kty === 'RSA'
    ? { kty: 'RSA', n: jwk.n, e: jwk.e }
    : { kty: 'EC', crv: jwk.crv, x: jwk.x, y: jwk.y };
}

function decodeJwtSegment(segment: string): Record<string, unknown> | null {
  try {
    const json = new TextDecoder().decode(base64UrlDecode(segment));
    const parsed = JSON.parse(json) as unknown;
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function base64UrlDecode(segment: string): Uint8Array {
  const padded = segment.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(segment.length / 4) * 4, '=');
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

/** Verifies an id_token against the provider's JWKS and returns its claims, or null. */
async function verifyIdToken(env: Env, authority: string, token: string): Promise<Record<string, unknown> | null> {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerSegment, payloadSegment, signatureSegment] = parts;
  const header = decodeJwtSegment(headerSegment);
  const claims = decodeJwtSegment(payloadSegment);
  if (!header || !claims) return null;

  const alg = String(header.alg || '');
  const algorithm = ID_TOKEN_ALGORITHMS[alg as keyof typeof ID_TOKEN_ALGORITHMS];
  if (!algorithm) return null;
  const jwk = selectJwk(await fetchJwks(authority), String(header.kid || ''), algorithm.kty, alg);
  if (!jwk) return null;

  try {
    const key = await crypto.subtle.importKey('jwk', toVerificationKey(jwk), algorithm.importParams, false, ['verify']);
    const signed = await crypto.subtle.verify(
      algorithm.verifyParams,
      key,
      base64UrlDecode(signatureSegment),
      new TextEncoder().encode(`${headerSegment}.${payloadSegment}`)
    );
    if (!signed) return null;
  } catch {
    return null;
  }
  return hasValidIdTokenClaims(env, authority, claims) ? claims : null;
}

function hasValidIdTokenClaims(env: Env, authority: string, claims: Record<string, unknown>): boolean {
  if (String(claims.iss || '').replace(/\/+$/, '') !== authority) return false;
  const audiences = Array.isArray(claims.aud) ? claims.aud.map(String) : [String(claims.aud || '')];
  if (!audiences.includes(String(env.SSO_CLIENT_ID))) return false;

  const now = Math.floor(Date.now() / 1000);
  const { exp, nbf } = claims;
  if (typeof exp !== 'number' || exp + ID_TOKEN_CLOCK_SKEW_SECONDS < now) return false;
  if (typeof nbf === 'number' && nbf - ID_TOKEN_CLOCK_SKEW_SECONDS > now) return false;
  return true;
}

async function signOpaque(secret: string, claims: Record<string, unknown>): Promise<string> {
  const body = btoa(JSON.stringify(claims));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const sig = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${body}.${sig}`;
}
