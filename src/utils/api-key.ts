import { sha256 } from 'hono/utils/crypto';

const API_KEY_HASH_PREFIX = 'sha256:';

// timingSafeEqual throws on unequal lengths, and a length mismatch alone reveals nothing secret.
export function constantTimeEquals(left: string, right: string): boolean {
  const [leftBytes, rightBytes] = [left, right].map((value) => new TextEncoder().encode(value));
  return leftBytes.length === rightBytes.length && crypto.subtle.timingSafeEqual(leftBytes, rightBytes);
}

export function isStoredApiKeyHash(value: string | null | undefined): boolean {
  return String(value || '').startsWith(API_KEY_HASH_PREFIX);
}

export async function hashApiKey(apiKey: string): Promise<string> {
  return `${API_KEY_HASH_PREFIX}${await sha256(apiKey)}`;
}

export async function verifyApiKey(apiKey: string, storedApiKey: string | null | undefined): Promise<boolean> {
  const stored = String(storedApiKey || '').trim();
  if (!stored) return false;

  // Legacy NodeWarden rows stored a one-way hash. Keep them usable until the
  // user explicitly rotates once into the Bitwarden-compatible readable form.
  if (!isStoredApiKeyHash(stored)) {
    return constantTimeEquals(apiKey, stored);
  }

  const hashed = await hashApiKey(apiKey);
  return constantTimeEquals(hashed, stored);
}

// Generate a random alphanumeric string of the given length using crypto.getRandomValues.
export function randomStringAlphanum(length: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const maxUnbiased = Math.floor(256 / chars.length) * chars.length;
  const bytes = new Uint8Array(Math.max(16, length));

  while (result.length < length) {
    crypto.getRandomValues(bytes);
    for (const value of bytes) {
      if (value >= maxUnbiased) continue;
      result += chars[value % chars.length];
      if (result.length >= length) break;
    }
  }

  return result;
}
