import { Secret, TOTP } from 'otpauth';

const DEFAULT_DIGITS = 6;
const DEFAULT_PERIOD = 30;
// The truncated HOTP value is 31 bits, so ten digits already carry all of it.
const MAX_DIGITS = 10;
const STEAM_ALPHABET = '23456789BCDFGHJKMNPQRTVWXY';
const STEAM_CODE_LENGTH = 5;
// Google Authenticator migration enums: Algorithm (0 unspecified) and DigitCount (2 = eight).
const GOOGLE_MIGRATION_ALGORITHMS = ['SHA1', 'SHA1', 'SHA256', 'SHA512'];
const GOOGLE_MIGRATION_EIGHT_DIGITS = 2;
const GOOGLE_MIGRATION_HOTP = 1;

export interface TotpCodeResult {
  code: string;
  remain: number;
  period: number;
}

// Keys are shown grouped with spaces or dashes, lowercased or padded; only base32 alphabet characters carry bits.
function secretFromBase32(raw: string): Secret {
  return Secret.fromBase32(raw.toUpperCase().replace(/[^A-Z2-7]/g, ''));
}

// Hand-typed and exported URIs are often too malformed for otpauth's URI.parse (spaces in the secret, no label,
// hotp type, odd algorithm spelling), so read the query directly and match keys case-insensitively.
function readOtpAuthParam(raw: string, name: string): string {
  const query = raw.split('#')[0].split('?').slice(1).join('?');
  return [...new URLSearchParams(query)].find(([key]) => key.trim().toLowerCase() === name)?.[1] ?? '';
}

function parseSteamSecret(raw: string): string {
  const match = raw.trim().match(/^steam:\/\/([^/?#]+)(?:[/?#].*)?$/i);
  if (!match?.[1]) return '';
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return match[1];
  }
}

function clampInteger(value: string, fallback: number, min: number, max: number): number {
  const parsed = Number(value);
  return value && Number.isSafeInteger(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function parseOtpAuthUri(uri: string): TOTP {
  const algorithm = readOtpAuthParam(uri, 'algorithm').toUpperCase().replace(/[^A-Z0-9]/g, '');
  return new TOTP({
    secret: secretFromBase32(readOtpAuthParam(uri, 'secret')),
    algorithm: ['SHA256', 'SHA512'].includes(algorithm) ? algorithm : 'SHA1',
    digits: clampInteger(readOtpAuthParam(uri, 'digits'), DEFAULT_DIGITS, 0, MAX_DIGITS),
    period: clampInteger(readOtpAuthParam(uri, 'period'), DEFAULT_PERIOD, 1, Number.MAX_SAFE_INTEGER),
  });
}

function base64ToBytesLoose(value: string): Uint8Array {
  const normalized = value.trim().replace(/\s/g, '+').replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized) return new Uint8Array();
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  try {
    const binary = atob(padded);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return new Uint8Array();
  }
}

function readProtoVarint(bytes: Uint8Array, state: { offset: number }): number | null {
  let result = 0;
  let factor = 1;
  for (let i = 0; i < 10 && state.offset < bytes.length; i += 1) {
    const byte = bytes[state.offset++];
    result += (byte & 0x7f) * factor;
    if ((byte & 0x80) === 0) return Number.isSafeInteger(result) ? result : null;
    factor *= 128;
  }
  return null;
}

function readProtoBytes(bytes: Uint8Array, state: { offset: number }): Uint8Array | null {
  const length = readProtoVarint(bytes, state);
  if (length == null || length < 0 || state.offset + length > bytes.length) return null;
  const out = bytes.slice(state.offset, state.offset + length);
  state.offset += length;
  return out;
}

function skipProtoField(bytes: Uint8Array, state: { offset: number }, wireType: number): boolean {
  if (wireType === 0) return readProtoVarint(bytes, state) != null;
  if (wireType === 1 && state.offset + 8 <= bytes.length) {
    state.offset += 8;
    return true;
  }
  if (wireType === 2) return readProtoBytes(bytes, state) != null;
  if (wireType === 5 && state.offset + 4 <= bytes.length) {
    state.offset += 4;
    return true;
  }
  return false;
}

function parseGoogleMigrationOtpParameter(bytes: Uint8Array): TOTP | null {
  const state = { offset: 0 };
  let secretBytes: Uint8Array | null = null;
  let name = '';
  let issuer = '';
  let algorithm: string | null = 'SHA1';
  let digits = DEFAULT_DIGITS;
  let otpType = 0;
  const decoder = new TextDecoder();

  while (state.offset < bytes.length) {
    const key = readProtoVarint(bytes, state);
    if (key == null) return null;
    const fieldNumber = Math.floor(key / 8);
    const wireType = key % 8;

    if (fieldNumber === 1 && wireType === 2) {
      secretBytes = readProtoBytes(bytes, state);
    } else if (fieldNumber === 2 && wireType === 2) {
      const value = readProtoBytes(bytes, state);
      name = value ? decoder.decode(value) : '';
    } else if (fieldNumber === 3 && wireType === 2) {
      const value = readProtoBytes(bytes, state);
      issuer = value ? decoder.decode(value) : '';
    } else if (fieldNumber === 4 && wireType === 0) {
      const value = readProtoVarint(bytes, state);
      algorithm = value == null ? null : GOOGLE_MIGRATION_ALGORITHMS[value] ?? null;
    } else if (fieldNumber === 5 && wireType === 0) {
      digits = readProtoVarint(bytes, state) === GOOGLE_MIGRATION_EIGHT_DIGITS ? 8 : DEFAULT_DIGITS;
    } else if (fieldNumber === 6 && wireType === 0) {
      otpType = readProtoVarint(bytes, state) ?? 0;
    } else if (!skipProtoField(bytes, state, wireType)) {
      return null;
    }
  }

  if (!secretBytes?.length || !algorithm || otpType === GOOGLE_MIGRATION_HOTP) return null;
  const label = name.trim();
  const issuerName = issuer.trim();
  return new TOTP({
    issuer: issuerName,
    label: label || issuerName || 'TOTP',
    // Apps often store the account name already prefixed with its issuer; do not prefix it twice.
    issuerInLabel: Boolean(label) && !label.toLowerCase().startsWith(`${issuerName.toLowerCase()}:`),
    secret: new Secret({ buffer: secretBytes.buffer }),
    algorithm,
    digits,
  });
}

function parseGoogleAuthenticatorMigration(raw: string): TOTP[] {
  const bytes = base64ToBytesLoose(readOtpAuthParam(raw, 'data'));
  if (!bytes.length) return [];

  const state = { offset: 0 };
  const out: TOTP[] = [];
  while (state.offset < bytes.length) {
    const key = readProtoVarint(bytes, state);
    if (key == null) return [];
    const fieldNumber = Math.floor(key / 8);
    const wireType = key % 8;
    if (fieldNumber === 1 && wireType === 2) {
      const parameterBytes = readProtoBytes(bytes, state);
      const parameter = parameterBytes ? parseGoogleMigrationOtpParameter(parameterBytes) : null;
      if (parameter) out.push(parameter);
    } else if (!skipProtoField(bytes, state, wireType)) {
      return [];
    }
  }
  return out;
}

export function normalizeTotpInput(raw: string): string {
  const s = raw.trim();
  if (!s) return '';
  if (/^otpauth-migration:\/\//i.test(s)) {
    const accounts = parseGoogleAuthenticatorMigration(s);
    return accounts.length === 1 ? accounts[0].toString() : '';
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^otpauth:\/\//i.test(s) && !/^steam:\/\//i.test(s)) {
    return '';
  }
  return s;
}

// Steam Guard is SHA-1/30 s TOTP rendered in its own 26-character alphabet instead of decimal digits.
function steamCode(value: number): string {
  return Array.from(
    { length: STEAM_CODE_LENGTH },
    (_, position) => STEAM_ALPHABET[Math.floor(value / STEAM_ALPHABET.length ** position) % STEAM_ALPHABET.length]
  ).join('');
}

export async function calcTotpNow(rawSecret: string, nowMs: number = Date.now()): Promise<TotpCodeResult | null> {
  const input = normalizeTotpInput(rawSecret);
  const steam = /^steam:\/\//i.test(input);
  const totp = steam
    ? new TOTP({ secret: secretFromBase32(parseSteamSecret(input)), digits: MAX_DIGITS })
    : /^otpauth:\/\//i.test(input)
      ? parseOtpAuthUri(input)
      : new TOTP({ secret: secretFromBase32(input) });
  if (!totp.secret.bytes.length) return null;
  const token = totp.generate({ timestamp: nowMs });
  const epoch = Math.floor(nowMs / 1000);
  return {
    code: steam ? steamCode(Number(token)) : token,
    remain: totp.period - (epoch % totp.period),
    period: totp.period,
  };
}
