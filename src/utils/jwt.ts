import { JWTPayload } from '../types';
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

export async function verifyHs256Jwt(token: string, secret: string): Promise<Record<string, unknown> | null> {
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
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as Record<string, unknown>;
    const exp = payload.exp;
    if (typeof exp === 'number' && exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
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
