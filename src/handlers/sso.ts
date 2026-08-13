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
  const authorize = new URL(`${authority}/authorize`);
  const wellKnown = await discoverAuthorizationEndpoint(authority);
  const target = new URL(wellKnown || authorize.toString());
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

export async function exchangeOidcCode(env: Env, code: string, redirectOrigin: string): Promise<{
  email: string;
  name: string | null;
  identifier: string;
} | null> {
  const authority = String(env.SSO_AUTHORITY || '').replace(/\/+$/, '');
  const tokenUrl = await discoverTokenEndpoint(authority);
  if (!tokenUrl) return null;
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
  const claims = decodeJwtClaims(payload.id_token || '');
  const email = String(claims.email || claims.preferred_username || '').trim().toLowerCase();
  const identifier = String(claims.sub || email);
  if (!email || !identifier) return null;
  return {
    email,
    name: claims.name ? String(claims.name) : null,
    identifier,
  };
}

function resolveClientRedirect(clientId: string, raw: string, origin: string): string | null {
  if (clientId === 'web' || clientId === 'browser') return `${origin}/sso-connector.html`;
  if (clientId === 'desktop' || clientId === 'mobile') return 'bitwarden://sso-callback';
  if (clientId === 'cli' && /^http:\/\/localhost:\d{4}$/.test(raw)) return raw;
  if (raw.startsWith(origin)) return raw;
  return null;
}

async function discoverAuthorizationEndpoint(authority: string): Promise<string | null> {
  try {
    const response = await fetch(`${authority}/.well-known/openid-configuration`);
    if (!response.ok) return `${authority}/authorize`;
    const body = await response.json() as { authorization_endpoint?: string };
    return body.authorization_endpoint || `${authority}/authorize`;
  } catch {
    return `${authority}/authorize`;
  }
}

async function discoverTokenEndpoint(authority: string): Promise<string | null> {
  try {
    const response = await fetch(`${authority}/.well-known/openid-configuration`);
    if (!response.ok) return `${authority}/token`;
    const body = await response.json() as { token_endpoint?: string };
    return body.token_endpoint || `${authority}/token`;
  } catch {
    return `${authority}/token`;
  }
}

function decodeJwtClaims(token: string): Record<string, unknown> {
  const parts = token.split('.');
  if (parts.length < 2) return {};
  try {
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(parts[1].length / 4) * 4, '=');
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return {};
  }
}

async function signOpaque(secret: string, claims: Record<string, unknown>): Promise<string> {
  const body = btoa(JSON.stringify(claims));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body));
  const sig = btoa(String.fromCharCode(...new Uint8Array(signature)));
  return `${body}.${sig}`;
}
