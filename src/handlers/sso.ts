import { decode, verify } from 'hono/jwt';
import { signHs256Jwt } from '../utils/jwt';
import { readEnvConfig } from '../config/env';
import type { Env } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import * as orgRepo from '../services/storage-org-repo';
import { PolicyType } from '../services/org-types';

export const FAKE_SSO_IDENTIFIER = '00000000-01DC-01DC-01DC-000000000000';

export function isSsoEnabled(env: Env): boolean {
  const config = readEnvConfig(env);
  return config.SSO_ENABLED && !!config.SSO_AUTHORITY && !!config.SSO_CLIENT_ID;
}

export function isSsoOnly(env: Env): boolean {
  return readEnvConfig(env).SSO_ONLY;
}

export async function userRequiresSso(env: Env, userId: string): Promise<boolean> {
  if (isSsoOnly(env)) return true;
  const policies = await orgRepo.listEnabledPoliciesForUser(env.DB, userId);
  return policies.some((policy) => policy.type === PolicyType.RequireSso && policy.enabled);
}

export async function handleSsoPrevalidate(env: Env): Promise<Response> {
  if (!isSsoEnabled(env)) return errorResponse('SSO is not enabled', 404);
  const now = Math.floor(Date.now() / 1000);
  const token = await signHs256Jwt({ sub: 'nodewarden-sso', nbf: now, exp: now + 120 }, env.JWT_SECRET);
  return jsonResponse({ token });
}

export async function handleSsoAuthorize(request: Request, env: Env): Promise<Response> {
  if (!isSsoEnabled(env)) return errorResponse('SSO is not enabled', 404);
  const url = new URL(request.url);
  const state = url.searchParams.get('state') || generateUUID();
  const codeChallenge = url.searchParams.get('code_challenge');
  const clientId = url.searchParams.get('client_id') || 'web';
  const rawRedirect = url.searchParams.get('redirect_uri') || '';
  let redirectUri: string | null;
  if (clientId === 'web' || clientId === 'browser') redirectUri = `${url.origin}/sso-connector.html`;
  else if (clientId === 'desktop' || clientId === 'mobile') redirectUri = 'bitwarden://sso-callback';
  else if (clientId === 'cli' && /^http:\/\/localhost:\d{4}$/.test(rawRedirect)) redirectUri = rawRedirect;
  else {
    // A prefix test would accept https://host.evil.com for the origin https://host.ev,
    // so redirect targets must parse and match the origin exactly.
    try {
      redirectUri = new URL(rawRedirect).origin === url.origin ? rawRedirect : null;
    } catch {
      redirectUri = null;
    }
  }
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

  const config = readEnvConfig(env);
  const { authorization_endpoint: authorizationEndpoint } = await discoverOidcConfig(config.SSO_AUTHORITY);
  const target = new URL(authorizationEndpoint || `${config.SSO_AUTHORITY}/authorize`);
  target.searchParams.set('response_type', 'code');
  target.searchParams.set('client_id', String(config.SSO_CLIENT_ID));
  target.searchParams.set('redirect_uri', `${url.origin}/identity/oidc-signin`);
  target.searchParams.set('scope', config.SSO_SCOPES);
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

export async function exchangeOidcCode(env: Env, code: string, redirectOrigin: string, codeVerifier?: string): Promise<OidcIdentity | null> {
  const config = readEnvConfig(env);
  const authority = config.SSO_AUTHORITY;
  const { token_endpoint: tokenEndpoint } = await discoverOidcConfig(authority);
  const tokenUrl = tokenEndpoint || `${authority}/token`;
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    client_id: String(config.SSO_CLIENT_ID),
    redirect_uri: `${redirectOrigin}/identity/oidc-signin`,
  });
  if (config.SSO_CLIENT_SECRET) body.set('client_secret', config.SSO_CLIENT_SECRET);
  if (codeVerifier) body.set('code_verifier', codeVerifier);
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) return null;
  const payload = await response.json() as { id_token?: string; access_token?: string };
  // The id_token must verify against the provider's JWKS; any failure yields no identity.
  const idToken = payload.id_token || '';
  const { jwks_uri: jwksUri } = await discoverOidcConfig(authority);
  let claims: Record<string, unknown>;
  try {
    const { header } = decode(idToken);
    const alg = ID_TOKEN_ALGORITHMS.find((allowed) => allowed === header.alg);
    if (!alg) return null;
    // OIDC lets a provider with one signing key omit kid, which hono's verifyWithJwks refuses, so the
    // key is chosen here: the kid match, else the only key of the token's type.
    const { keys = [] } = await (await fetch(jwksUri || `${authority}/.well-known/jwks.json`)).json() as { keys?: ProviderJwk[] };
    const kty = alg.startsWith('ES') ? 'EC' : 'RSA';
    const candidates = keys.filter((jwk) => jwk.kty === kty && (!jwk.alg || jwk.alg === alg) && (!jwk.use || jwk.use === 'sig'));
    const key = candidates.find((candidate) => header.kid && candidate.kid === header.kid) ?? (candidates.length === 1 ? candidates[0] : undefined);
    if (!key) return null;
    // hono's time checks allow no clock skew, so the claim checks below own exp/nbf instead.
    claims = await verify(idToken, key, { alg, exp: false, nbf: false, iat: false });
    if (String(claims.iss || '').replace(/\/+$/, '') !== authority) return null;
    const audiences = Array.isArray(claims.aud) ? claims.aud.map(String) : [String(claims.aud || '')];
    if (!audiences.includes(String(config.SSO_CLIENT_ID))) return null;

    const now = Math.floor(Date.now() / 1000);
    const { exp, nbf } = claims;
    if (typeof exp !== 'number' || exp + ID_TOKEN_CLOCK_SKEW_SECONDS < now) return null;
    if (typeof nbf === 'number' && nbf - ID_TOKEN_CLOCK_SKEW_SECONDS > now) return null;
  } catch {
    return null;
  }
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

interface OidcDiscovery {
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
}

const DISCOVERY_CACHE_TTL_MS = 5 * 60 * 1000;
const discoveryCache = new Map<string, { expiresAt: number; document: OidcDiscovery }>();

// Signature algorithms we accept on an id_token. `alg: none` and HMAC are excluded by omission.
const ID_TOKEN_ALGORITHMS = ['RS256', 'ES256'] as const;

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

type ProviderJwk = JsonWebKey & { kid?: string; use?: string };
