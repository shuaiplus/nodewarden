const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // allow previous/current/next step for small clock drift

function normalizeBase32(input: string): string {
  const raw = String(input || '').toUpperCase();
  let out = '';
  for (const char of raw) {
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === '-') continue;
    out += char;
  }
  while (out.endsWith('=')) {
    out = out.slice(0, -1);
  }
  return out;
}

function base32Decode(input: string): Uint8Array | null {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const normalized = normalizeBase32(input);
  if (!normalized) return null;

  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const idx = alphabet.indexOf(char);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((value >> bits) & 0xff);
    }
  }

  return output.length > 0 ? new Uint8Array(output) : null;
}

async function hotp(secret: Uint8Array, counter: number): Promise<string> {
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }

  const key = await crypto.subtle.importKey(
    'raw',
    secret,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);

  const otp = binary % (10 ** TOTP_DIGITS);
  return otp.toString().padStart(TOTP_DIGITS, '0');
}

function normalizeToken(token: string): string {
  return token.replace(/\s+/g, '');
}

export async function findMatchingTotpCounter(
  secretRaw: string,
  tokenRaw: string,
  nowMs: number = Date.now()
): Promise<number | null> {
  const token = normalizeToken(tokenRaw);
  if (!/^\d{6}$/.test(token)) return null;

  const secret = base32Decode(secretRaw);
  if (!secret) return null;

  const currentCounter = Math.floor(nowMs / 1000 / TOTP_STEP_SECONDS);
  let matchedCounter: number | null = null;
  for (let delta = -TOTP_WINDOW; delta <= TOTP_WINDOW; delta++) {
    const candidateCounter = currentCounter + delta;
    const expected = await hotp(secret, candidateCounter);
    // Constant-time comparison: always check all windows, never short-circuit.
    const a = new TextEncoder().encode(expected);
    const b = new TextEncoder().encode(token);
    let diff = a.length ^ b.length;
    for (let i = 0; i < a.length && i < b.length; i++) {
      diff |= a[i] ^ b[i];
    }
    if (diff === 0 && matchedCounter == null) matchedCounter = candidateCounter;
  }
  return matchedCounter;
}

export async function verifyTotpToken(secretRaw: string, tokenRaw: string, nowMs: number = Date.now()): Promise<boolean> {
  return (await findMatchingTotpCounter(secretRaw, tokenRaw, nowMs)) != null;
}

export function isTotpEnabled(secretRaw: string | undefined | null): boolean {
  return Boolean(secretRaw && normalizeBase32(secretRaw).length > 0);
}
