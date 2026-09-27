import { Secret, TOTP } from 'otpauth';

const TOTP_PERIOD_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // allow previous/current/next step for small clock drift
const TOTP_TOKEN_PATTERN = new RegExp(`^\\d{${TOTP_DIGITS}}$`);

// Authenticator keys are shown grouped with spaces or dashes, in either case and sometimes padded.
export function normalizeTotpSecret(input: string): string {
  return input.toUpperCase().replace(/[ \t\r\n-]/g, '').replace(/=+$/, '');
}

export async function findMatchingTotpCounter(
  secretRaw: string,
  tokenRaw: string,
  nowMs: number = Date.now()
): Promise<number | null> {
  const token = tokenRaw.replace(/\s+/g, '');
  if (!TOTP_TOKEN_PATTERN.test(token)) return null;
  let secret: Secret;
  try {
    secret = Secret.fromBase32(normalizeTotpSecret(secretRaw));
  } catch {
    // A stored or submitted key outside the base32 alphabet can never match, same as a wrong code.
    return null;
  }
  if (secret.bytes.length === 0) return null;
  const options = { period: TOTP_PERIOD_SECONDS, timestamp: nowMs };
  const delta = TOTP.validate({ ...options, token, secret, digits: TOTP_DIGITS, window: TOTP_WINDOW });
  // The replay guard stores absolute step counters, not the window-relative delta.
  return delta == null ? null : TOTP.counter(options) + delta;
}

export function isTotpEnabled(secretRaw: string | undefined | null): boolean {
  return Boolean(secretRaw && normalizeTotpSecret(secretRaw).length > 0);
}
