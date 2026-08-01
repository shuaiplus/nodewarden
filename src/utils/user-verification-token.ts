import type { Env } from '../types';
import { base64UrlToBytes, bytesToBase64Url } from './passkey';

const USER_VERIFICATION_TOKEN_TYPE = 'nodewarden.user-verification.v1';
const USER_VERIFICATION_TOKEN_TTL_MS = 5 * 60 * 1000;

export type UserVerificationPurpose = 'backup.settings.repair';

interface UserVerificationTokenPayload {
  typ: typeof USER_VERIFICATION_TOKEN_TYPE;
  userId: string;
  method: 'passkey';
  purpose: UserVerificationPurpose;
  iat: number;
  exp: number;
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', textBytes(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await importHmacKey(secret);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, textBytes(data)));
}

function encodeJson(value: unknown): string {
  return bytesToBase64Url(textBytes(JSON.stringify(value)));
}

function decodeJson<T>(value: string): T | null {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value))) as T;
  } catch {
    return null;
  }
}

export async function createPasskeyUserVerificationToken(
  env: Env,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<string> {
  const now = Date.now();
  const payload: UserVerificationTokenPayload = {
    typ: USER_VERIFICATION_TOKEN_TYPE,
    userId,
    method: 'passkey',
    purpose,
    iat: now,
    exp: now + USER_VERIFICATION_TOKEN_TTL_MS,
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const data = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = bytesToBase64Url(await hmacSha256(env.JWT_SECRET, data));
  return `${data}.${signature}`;
}

export async function verifyPasskeyUserVerificationToken(
  env: Env,
  token: string,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<boolean> {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return false;
    const data = `${parts[0]}.${parts[1]}`;
    const expected = await hmacSha256(env.JWT_SECRET, data);
    const actual = base64UrlToBytes(parts[2]);
    if (actual.length !== expected.length) return false;

    let diff = 0;
    for (let i = 0; i < actual.length; i += 1) diff |= actual[i] ^ expected[i];
    if (diff !== 0) return false;

    const payload = decodeJson<UserVerificationTokenPayload>(parts[1]);
    if (!payload || payload.typ !== USER_VERIFICATION_TOKEN_TYPE) return false;
    if (payload.userId !== userId || payload.purpose !== purpose || payload.method !== 'passkey') return false;
    if (!Number.isFinite(payload.exp) || payload.exp < Date.now()) return false;
    return true;
  } catch {
    return false;
  }
}
