import type { Env, JWTPayload, User } from '../types';
import type { TwoFactorProviderType } from '../services/two-factor-providers';
import { sha256Base64Url } from './account-passkeys';
import { LIMITS } from '../config/limits';

const hmacKeyCache = new Map<string, Promise<CryptoKey>>();

// Base64 URL encode
function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Base64 URL decode
function base64UrlDecode(str: string): Uint8Array {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export async function hmacSha256Base64Url(secret: string, data: string): Promise<string> {
  const signature = await crypto.subtle.sign('HMAC', await getHmacKey(secret), new TextEncoder().encode(data));
  return base64UrlEncode(new Uint8Array(signature));
}

export async function signHs256Jwt(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;
  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return `${data}.${base64UrlEncode(new Uint8Array(signature))}`;
}

// Signature and JSON only. Callers that must tell an expired token from a forged one check exp
// themselves; everyone else uses verifyHs256Jwt.
async function decodeSignedHs256Jwt(token: string, secret: string): Promise<Record<string, unknown> | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();
    const key = await getHmacKey(secret);
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlDecode(signatureB64),
      encoder.encode(`${headerB64}.${payloadB64}`)
    );
    if (!valid) return null;
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function isExpired(payload: Record<string, unknown>): boolean {
  return typeof payload.exp === 'number' && payload.exp < Math.floor(Date.now() / 1000);
}

export async function verifyHs256Jwt(token: string, secret: string): Promise<Record<string, unknown> | null> {
  const payload = await decodeSignedHs256Jwt(token, secret);
  return payload && !isExpired(payload) ? payload : null;
}

const TWO_FACTOR_USER_VERIFICATION_ISSUER = 'nodewarden|two_factor_uv';

export async function createTwoFactorUserVerificationToken(
  env: Env,
  user: User,
  providerType: TwoFactorProviderType,
  totpKey?: string,
): Promise<string> {
  return signHs256Jwt({
    iss: TWO_FACTOR_USER_VERIFICATION_ISSUER,
    sub: user.id,
    ptype: providerType,
    ...(providerType === 0 ? { key: totpKey } : {}),
    sst: await sha256Base64Url(user.securityStamp),
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.twoFactorUserVerificationTtlSeconds,
  }, env.JWT_SECRET);
}

export async function verifyTwoFactorUserVerificationToken(
  env: Env,
  user: User,
  providerType: number,
  token: string,
  totpKey?: string,
): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
  return !!payload
    && payload.iss === TWO_FACTOR_USER_VERIFICATION_ISSUER
    && payload.sub === user.id
    && payload.ptype === providerType
    && typeof payload.exp === 'number' && Number.isFinite(payload.exp)
    && payload.exp > Math.floor(Date.now() / 1000)
    && (providerType !== 0 || (!!totpKey && payload.key === totpKey))
    && payload.sst === await sha256Base64Url(user.securityStamp);
}

const SSO_EMAIL_TWO_FACTOR_ISSUER = 'nodewarden|sso_email_2fa';

export async function createSsoEmail2faSessionToken(env: Env, user: User): Promise<string> {
  return signHs256Jwt({
    iss: SSO_EMAIL_TWO_FACTOR_ISSUER, sub: user.id, email: user.email,
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.ssoEmail2faSessionTtlSeconds,
  }, env.JWT_SECRET);
}

export async function verifySsoEmail2faSessionToken(env: Env, user: User, token: string): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
  return !!payload && payload.iss === SSO_EMAIL_TWO_FACTOR_ISSUER && payload.sub === user.id && payload.email === user.email
    && typeof payload.exp === 'number' && Number.isFinite(payload.exp) && payload.exp > Math.floor(Date.now() / 1000);
}

export const REGISTER_VERIFY_ISSUER = 'nodewarden|register_verify';

export async function createRegisterVerifyToken(
  secret: string,
  email: string,
  name: string | null
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt({
    nbf: now,
    exp: now + 30 * 60,
    iss: REGISTER_VERIFY_ISSUER,
    sub: email,
    name,
    verified: false,
  }, secret);
}

export async function verifyRegisterVerifyToken(
  token: string,
  secret: string
): Promise<{ email: string; name: string | null } | null> {
  const payload = await verifyHs256Jwt(token, secret);
  if (!payload || payload.iss !== REGISTER_VERIFY_ISSUER) return null;
  const email = String(payload.sub || '').trim().toLowerCase();
  if (!email) return null;
  const name = typeof payload.name === 'string' && payload.name.trim() ? payload.name.trim() : null;
  return { email, name };
}

const ORG_INVITE_ISSUER = 'nodewarden|org_invite';
const SECONDS_PER_DAY = 24 * 60 * 60;
// Upstream OrgUserInviteTokenable.GetTokenLifetime(). The invite email quotes it too.
export const ORG_INVITE_TTL_DAYS = 5;
const ORG_INVITE_TTL_SECONDS = ORG_INVITE_TTL_DAYS * SECONDS_PER_DAY;

// Upstream TokenableValidationError messages; official web's accept page branches on them.
export type OrgInviteTokenCheck = { ok: true } | { ok: false; message: 'Expired token.' | 'Invalid token.' };

// Binds an emailed invite to one membership row and the address it was sent to, as upstream
// OrgUserInviteTokenable does, so only that mailbox's owner can accept the row.
export async function createOrgInviteToken(secret: string, orgUserId: string, email: string, expiresAt = Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_SECONDS): Promise<string> {
  return signHs256Jwt({
    exp: expiresAt,
    iss: ORG_INVITE_ISSUER,
    sub: orgUserId,
    email: email.toLowerCase(),
  }, secret);
}

export async function verifyOrgInviteToken(
  token: string,
  secret: string,
  orgUserId: string,
  email: string | null
): Promise<OrgInviteTokenCheck> {
  const payload = await decodeSignedHs256Jwt(token, secret);
  // Upstream OrgUserInviteTokenable.ValidateOrgUserInvite reports expiry before the row binding.
  if (payload?.iss === ORG_INVITE_ISSUER && isExpired(payload)) return { ok: false, message: 'Expired token.' };
  const bound = !!payload && !!email
    && payload.iss === ORG_INVITE_ISSUER
    && payload.sub === orgUserId
    && payload.email === email.toLowerCase();
  return bound ? { ok: true } : { ok: false, message: 'Invalid token.' };
}

const EMERGENCY_ACCESS_INVITE_ISSUER = 'nodewarden|emergency_access_invite';

export async function createEmergencyAccessInviteToken(secret: string, id: string, email: string): Promise<string> {
  return signHs256Jwt({
    exp: Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_SECONDS,
    iss: EMERGENCY_ACCESS_INVITE_ISSUER,
    sub: id,
    email: email.toLowerCase(),
  }, secret);
}

export async function verifyEmergencyAccessInviteToken(token: string, secret: string, id: string, email: string): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, secret);
  return !!payload && payload.iss === EMERGENCY_ACCESS_INVITE_ISSUER && payload.sub === id
    && payload.email === email.toLowerCase() && typeof payload.exp === 'number'
    && payload.exp > Math.floor(Date.now() / 1000);
}

function getHmacKey(secret: string): Promise<CryptoKey> {
  const cacheKey = secret;
  let cached = hmacKeyCache.get(cacheKey);
  if (cached) return cached;

  const encoder = new TextEncoder();
  cached = crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
  hmacKeyCache.set(cacheKey, cached);
  return cached;
}

// Create JWT
export async function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp' | 'iss' | 'premium' | 'email_verified' | 'amr'>, secret: string, expiresIn: number = LIMITS.auth.accessTokenTtlSeconds): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const fullPayload: JWTPayload = {
    ...payload,
    email_verified: true,  // required by mobile client
    amr: ['Application'],  // authentication methods reference - required by mobile client
    iat: now,
    exp: now + expiresIn,
    iss: 'nodewarden',
    premium: true,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(fullPayload)));
  
  const data = `${headerB64}.${payloadB64}`;
  
  const key = await getHmacKey(secret);
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  
  return `${data}.${signatureB64}`;
}

// Verify JWT
export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: JWTPayload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;

    return payload;
  } catch {
    return null;
  }
}

// Create refresh token (simple random string)
export function createRefreshToken(): string {
  const bytes = new Uint8Array(LIMITS.auth.refreshTokenRandomBytes);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

// File download token payload
export interface FileDownloadClaims {
  cipherId: string;
  attachmentId: string;
  jti: string;
  exp: number;
}

export interface AttachmentUploadClaims {
  userId: string;
  cipherId: string;
  attachmentId: string;
  exp: number;
}

// Create file download token (short-lived, 5 minutes)
export async function createFileDownloadToken(
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const payload: FileDownloadClaims = {
    cipherId,
    attachmentId,
    jti: createRefreshToken(),
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds, // 5 minutes
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  
  const data = `${headerB64}.${payloadB64}`;
  
  const key = await getHmacKey(secret);
  
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  
  return `${data}.${signatureB64}`;
}

// Verify file download token
export async function verifyFileDownloadToken(
  token: string,
  secret: string
): Promise<FileDownloadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: FileDownloadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;

    return payload;
  } catch {
    return null;
  }
}

export async function createAttachmentUploadToken(
  userId: string,
  cipherId: string,
  attachmentId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: AttachmentUploadClaims = {
    userId,
    cipherId,
    attachmentId,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifyAttachmentUploadToken(
  token: string,
  secret: string
): Promise<AttachmentUploadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: AttachmentUploadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (!payload.userId || !payload.cipherId || !payload.attachmentId) return null;
    return payload;
  } catch {
    return null;
  }
}

export interface SendFileDownloadClaims {
  sendId: string;
  fileId: string;
  jti: string;
  exp: number;
}

export interface SendFileUploadClaims {
  userId: string;
  sendId: string;
  fileId: string;
  exp: number;
}

export async function createSendFileDownloadToken(
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendFileDownloadClaims = {
    sendId,
    fileId,
    jti: createRefreshToken(),
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendFileDownloadToken(
  token: string,
  secret: string
): Promise<SendFileDownloadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendFileDownloadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (
      typeof payload.sendId !== 'string' ||
      typeof payload.fileId !== 'string' ||
      typeof payload.jti !== 'string' ||
      !payload.jti ||
      typeof payload.exp !== 'number'
    ) {
      return null;
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;

    return payload;
  } catch {
    return null;
  }
}

export async function createSendFileUploadToken(
  userId: string,
  sendId: string,
  fileId: string,
  secret: string
): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendFileUploadClaims = {
    userId,
    sendId,
    fileId,
    exp: now + LIMITS.auth.fileDownloadTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);

  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendFileUploadToken(
  token: string,
  secret: string
): Promise<SendFileUploadClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendFileUploadClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (!payload.userId || !payload.sendId || !payload.fileId) return null;
    return payload;
  } catch {
    return null;
  }
}

export interface SendAccessTokenClaims {
  sub: string; // send id
  typ: 'send_access';
  iat: number;
  exp: number;
}

export async function createSendAccessToken(sendId: string, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload: SendAccessTokenClaims = {
    sub: sendId,
    typ: 'send_access',
    iat: now,
    exp: now + LIMITS.auth.sendAccessTokenTtlSeconds,
  };

  const encoder = new TextEncoder();
  const headerB64 = base64UrlEncode(encoder.encode(JSON.stringify(header)));
  const payloadB64 = base64UrlEncode(encoder.encode(JSON.stringify(payload)));
  const data = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  const signatureB64 = base64UrlEncode(new Uint8Array(signature));
  return `${data}.${signatureB64}`;
}

export async function verifySendAccessToken(token: string, secret: string): Promise<SendAccessTokenClaims | null> {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerB64, payloadB64, signatureB64] = parts;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendAccessTokenClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (payload.typ !== 'send_access') return null;
    if (!payload.sub) return null;
    return payload;
  } catch {
    return null;
  }
}
