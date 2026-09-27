import { encodeBase64, decodeBase64 } from 'hono/utils/encode';
import { constantTimeEquals } from '../utils/api-key';

const SERVER_HASH_ITERATIONS = 100_000;
const LEGACY_PREFIX = '$s$';
const S2_PREFIX = '$s2$';

async function pbkdf2Hex(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, keyMaterial, 256);
  return encodeBase64(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const digest = await pbkdf2Hex(password, salt, SERVER_HASH_ITERATIONS);
  return `${S2_PREFIX}${SERVER_HASH_ITERATIONS}$${encodeBase64(salt.buffer)}$${digest}`;
}

export async function verifyPassword(password: string, storedHash: string, email?: string): Promise<boolean> {
  if (storedHash.startsWith(S2_PREFIX)) {
    const parts = storedHash.split('$');
    if (parts.length !== 5 || parts[1] !== 's2') return false;
    const iterations = Number(parts[2]);
    if (!Number.isFinite(iterations) || iterations < 1) return false;
    const digest = await pbkdf2Hex(password, decodeBase64(parts[3]), iterations);
    return constantTimeEquals(digest, parts[4]);
  }
  if (storedHash.startsWith(LEGACY_PREFIX) && email) {
    // Legacy hashes were salted with the normalized account email.
    const digest = await pbkdf2Hex(
      password,
      new TextEncoder().encode(email.toLowerCase().trim()),
      SERVER_HASH_ITERATIONS,
    );
    return constantTimeEquals(`${LEGACY_PREFIX}${digest}`, storedHash);
  }
  return constantTimeEquals(password, storedHash);
}

export async function verifyBetterAuthPassword(data: { password: string; hash: string }): Promise<boolean> {
  return verifyPassword(data.password, data.hash);
}
