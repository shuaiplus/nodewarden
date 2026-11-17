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

function verifyHs256Header(headerB64: string): boolean {
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(headerB64))) as { alg?: unknown };
    return header?.alg === 'HS256';
  } catch {
    return false;
  }
}

// Create JWT
export async function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp' | 'iss' | 'premium' | 'email_verified' | 'amr'>, secret: string, expiresIn: number = LIMITS.auth.accessTokenTtlSeconds): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  
  const fullPayload: JWTPayload = {
    ...payload,
    typ: 'access',
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as JWTPayload & { typ?: unknown };
    if (payload.typ !== undefined && payload.typ !== 'access') return null;
    if (typeof payload.sub !== 'string' || !payload.sub || typeof payload.sstamp !== 'string' || !payload.sstamp) {
      return null;
    }
    if (typeof payload.exp !== 'number') return null;
    
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
  typ?: 'file_download';
  cipherId: string;
  attachmentId: string;
  jti: string;
  exp: number;
}

export interface AttachmentUploadClaims {
  typ?: 'attachment_upload';
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
    typ: 'file_download',
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();
    
    const key = await getHmacKey(secret);
    
    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as FileDownloadClaims & { typ?: unknown };
    if (payload.typ !== 'file_download') return null;
    if (
      typeof payload.cipherId !== 'string' ||
      !payload.cipherId ||
      typeof payload.attachmentId !== 'string' ||
      !payload.attachmentId ||
      typeof payload.jti !== 'string' ||
      !payload.jti ||
      typeof payload.exp !== 'number'
    ) {
      return null;
    }
    
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
    typ: 'attachment_upload',
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as AttachmentUploadClaims & { typ?: unknown };
    if (payload.typ !== 'attachment_upload') return null;
    if (typeof payload.exp !== 'number') return null;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (
      typeof payload.userId !== 'string' ||
      !payload.userId ||
      typeof payload.cipherId !== 'string' ||
      !payload.cipherId ||
      typeof payload.attachmentId !== 'string' ||
      !payload.attachmentId
    ) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

export interface SendFileDownloadClaims {
  typ?: 'send_file_download';
  sendId: string;
  fileId: string;
  jti: string;
  exp: number;
}

export interface SendFileUploadClaims {
  typ?: 'send_file_upload';
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
    typ: 'send_file_download',
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as SendFileDownloadClaims & { typ?: unknown };
    if (payload.typ !== 'send_file_download') return null;
    if (
      typeof payload.sendId !== 'string' ||
      !payload.sendId ||
      typeof payload.fileId !== 'string' ||
      !payload.fileId ||
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
    typ: 'send_file_upload',
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))) as SendFileUploadClaims & { typ?: unknown };
    if (payload.typ !== 'send_file_upload') return null;
    if (typeof payload.exp !== 'number') return null;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (
      typeof payload.userId !== 'string' ||
      !payload.userId ||
      typeof payload.sendId !== 'string' ||
      !payload.sendId ||
      typeof payload.fileId !== 'string' ||
      !payload.fileId
    ) {
      return null;
    }
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
    if (!verifyHs256Header(headerB64)) return null;
    const encoder = new TextEncoder();

    const key = await getHmacKey(secret);

    const data = `${headerB64}.${payloadB64}`;
    const signature = base64UrlDecode(signatureB64);
    const valid = await crypto.subtle.verify('HMAC', key, signature, encoder.encode(data));
    if (!valid) return null;

    const payload: SendAccessTokenClaims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64)));
    if (typeof payload.exp !== 'number') return null;
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp < now) return null;
    if (payload.typ !== 'send_access') return null;
    if (typeof payload.sub !== 'string' || !payload.sub) return null;
    return payload;
  } catch {
    return null;
  }
}
