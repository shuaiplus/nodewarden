const API_KEY_HASH_PREFIX = 'sha256:';

export function constantTimeEquals(a: string, b: string): boolean {
  const encA = new TextEncoder().encode(a);
  const encB = new TextEncoder().encode(b);
  if (encA.length !== encB.length) return false;

  let diff = 0;
  for (let i = 0; i < encA.length; i++) {
    diff |= encA[i] ^ encB[i];
  }
  return diff === 0;
}

function toHex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

export function isStoredApiKeyHash(value: string | null | undefined): boolean {
  return String(value || '').startsWith(API_KEY_HASH_PREFIX);
}

export async function hashApiKey(apiKey: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(apiKey));
  return `${API_KEY_HASH_PREFIX}${toHex(digest)}`;
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
