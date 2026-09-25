const SERVER_HASH_ITERATIONS = 100_000;
const LEGACY_PREFIX = '$s$';
const S2_PREFIX = '$s2$';

function bytesToB64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function constantTimeEquals(left: string, right: string): boolean {
  const leftBytes = new TextEncoder().encode(left);
  const rightBytes = new TextEncoder().encode(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let diff = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    diff |= leftBytes[index] ^ rightBytes[index];
  }
  return diff === 0;
}

async function pbkdf2Hex(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    256
  );
  return bytesToB64(new Uint8Array(bits));
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const digest = await pbkdf2Hex(password, salt, SERVER_HASH_ITERATIONS);
  return `${S2_PREFIX}${SERVER_HASH_ITERATIONS}$${bytesToB64(salt)}$${digest}`;
}

async function verifyS2(password: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 5 || parts[1] !== 's2') return false;
  const iterations = Number(parts[2]);
  if (!Number.isFinite(iterations) || iterations < 1) return false;
  const digest = await pbkdf2Hex(password, b64ToBytes(parts[3]), iterations);
  return constantTimeEquals(digest, parts[4]);
}

async function verifyLegacyEmailSalt(password: string, stored: string, email: string): Promise<boolean> {
  const digest = await pbkdf2Hex(password, new TextEncoder().encode(email.toLowerCase().trim()), SERVER_HASH_ITERATIONS);
  return constantTimeEquals(`${LEGACY_PREFIX}${digest}`, stored);
}

export async function verifyPassword(password: string, storedHash: string, email?: string): Promise<boolean> {
  if (storedHash.startsWith(S2_PREFIX)) return verifyS2(password, storedHash);
  if (storedHash.startsWith(LEGACY_PREFIX) && email) return verifyLegacyEmailSalt(password, storedHash, email);
  return constantTimeEquals(password, storedHash);
}

export async function verifyBetterAuthPassword(data: { password: string; hash: string }): Promise<boolean> {
  return verifyPassword(data.password, data.hash);
}
