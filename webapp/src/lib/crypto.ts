import { parseGoogleAuthenticatorMigrationPage } from './google-authenticator-migration';

export const WEB_CRYPTO_UNAVAILABLE_MESSAGE =
  'Secure browser cryptography is unavailable. Open NodeWarden over HTTPS in a supported browser.';

export class WebCryptoUnavailableError extends Error {
  constructor() {
    super(WEB_CRYPTO_UNAVAILABLE_MESSAGE);
    this.name = 'WebCryptoUnavailableError';
  }
}

interface WebCryptoEnvironment {
  crypto?: Crypto;
  isSecureContext?: boolean;
}

export function requireWebCrypto(
  environment: WebCryptoEnvironment = globalThis as unknown as WebCryptoEnvironment
): Crypto {
  const cryptoApi = environment.crypto;
  if (
    environment.isSecureContext === false ||
    !cryptoApi ||
    typeof cryptoApi.getRandomValues !== 'function' ||
    !cryptoApi.subtle ||
    typeof cryptoApi.subtle.importKey !== 'function'
  ) {
    throw new WebCryptoUnavailableError();
  }
  return cryptoApi;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 1) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

export function toBufferSource(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

export async function sha256Base64(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await requireWebCrypto().subtle.digest('SHA-256', toBufferSource(bytes));
  return bytesToBase64(new Uint8Array(hash));
}

const hmacSha256KeyCache = new WeakMap<Uint8Array, Promise<CryptoKey>>();
const aesCbcEncryptKeyCache = new WeakMap<Uint8Array, Promise<CryptoKey>>();
const aesCbcDecryptKeyCache = new WeakMap<Uint8Array, Promise<CryptoKey>>();

function getCachedCryptoKey(
  cache: WeakMap<Uint8Array, Promise<CryptoKey>>,
  keyBytes: Uint8Array,
  create: () => Promise<CryptoKey>
): Promise<CryptoKey> {
  const cached = cache.get(keyBytes);
  if (cached) return cached;
  const pending = create().catch((error) => {
    cache.delete(keyBytes);
    throw error;
  });
  cache.set(keyBytes, pending);
  return pending;
}

function getHmacSha256Key(keyBytes: Uint8Array): Promise<CryptoKey> {
  return getCachedCryptoKey(
    hmacSha256KeyCache,
    keyBytes,
    () => requireWebCrypto().subtle.importKey('raw', toBufferSource(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  );
}

function getAesCbcEncryptKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return getCachedCryptoKey(
    aesCbcEncryptKeyCache,
    keyBytes,
    () => requireWebCrypto().subtle.importKey('raw', toBufferSource(keyBytes), { name: 'AES-CBC' }, false, ['encrypt'])
  );
}

function getAesCbcDecryptKey(keyBytes: Uint8Array): Promise<CryptoKey> {
  return getCachedCryptoKey(
    aesCbcDecryptKeyCache,
    keyBytes,
    () => requireWebCrypto().subtle.importKey('raw', toBufferSource(keyBytes), { name: 'AES-CBC' }, false, ['decrypt'])
  );
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export async function pbkdf2(
  passwordOrBytes: string | Uint8Array,
  saltOrBytes: string | Uint8Array,
  iterations: number,
  keyLen: number
): Promise<Uint8Array> {
  const pwdBytes = typeof passwordOrBytes === 'string' ? new TextEncoder().encode(passwordOrBytes) : passwordOrBytes;
  const saltBytes = typeof saltOrBytes === 'string' ? new TextEncoder().encode(saltOrBytes) : saltOrBytes;
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey('raw', toBufferSource(pwdBytes), 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: toBufferSource(saltBytes), iterations },
    key,
    keyLen * 8
  );
  return new Uint8Array(bits);
}

export async function hkdfExpand(prk: Uint8Array, info: string, length: number): Promise<Uint8Array> {
  const infoBytes = new TextEncoder().encode(info || '');
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey('raw', toBufferSource(prk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const result = new Uint8Array(length);
  let previous = new Uint8Array(0);
  let offset = 0;
  let counter = 1;

  while (offset < length) {
    const input = new Uint8Array(previous.length + infoBytes.length + 1);
    input.set(previous, 0);
    input.set(infoBytes, previous.length);
    input[input.length - 1] = counter & 0xff;
    previous = new Uint8Array(await subtle.sign('HMAC', key, toBufferSource(input)));
    const copyLen = Math.min(previous.length, length - offset);
    result.set(previous.slice(0, copyLen), offset);
    offset += copyLen;
    counter += 1;
  }

  return result;
}

export async function hkdf(
  ikm: Uint8Array,
  salt: string | Uint8Array,
  info: string | Uint8Array,
  outputByteSize: number
): Promise<Uint8Array> {
  const saltBytes = typeof salt === 'string' ? new TextEncoder().encode(salt) : salt;
  const infoBytes = typeof info === 'string' ? new TextEncoder().encode(info) : info;
  const params: HkdfParams = {
    name: 'HKDF',
    salt: toBufferSource(saltBytes),
    info: toBufferSource(infoBytes),
    hash: 'SHA-256',
  };
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey('raw', toBufferSource(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await subtle.deriveBits(params, key, outputByteSize * 8);
  return new Uint8Array(bits);
}

async function hmacSha256(keyBytes: Uint8Array, dataBytes: Uint8Array): Promise<Uint8Array> {
  const key = await getHmacSha256Key(keyBytes);
  return new Uint8Array(await requireWebCrypto().subtle.sign('HMAC', key, toBufferSource(dataBytes)));
}

async function encryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await getAesCbcEncryptKey(key);
  return new Uint8Array(await requireWebCrypto().subtle.encrypt({ name: 'AES-CBC', iv: toBufferSource(iv) }, cryptoKey, toBufferSource(data)));
}

async function decryptAesCbc(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await getAesCbcDecryptKey(key);
  return new Uint8Array(await requireWebCrypto().subtle.decrypt({ name: 'AES-CBC', iv: toBufferSource(iv) }, cryptoKey, toBufferSource(data)));
}

export async function encryptBwFileData(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  const iv = requireWebCrypto().getRandomValues(new Uint8Array(16));
  const cipher = await encryptAesCbc(data, encKey, iv);
  const mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  const out = new Uint8Array(1 + iv.length + mac.length + cipher.length);
  out[0] = 2; // EncryptionType.AesCbc256_HmacSha256_B64
  out.set(iv, 1);
  out.set(mac, 1 + iv.length);
  out.set(cipher, 1 + iv.length + mac.length);
  return out;
}

export async function decryptBwFileData(encrypted: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  if (!encrypted || encrypted.length < 1 + 16 + 32 + 1) throw new Error('Invalid encrypted file data');
  const encType = encrypted[0];
  if (encType !== 2) throw new Error('Unsupported file encryption type');
  const iv = encrypted.slice(1, 17);
  const mac = encrypted.slice(17, 49);
  const cipher = encrypted.slice(49);
  const expected = await hmacSha256(macKey, concatBytes(iv, cipher));
  if (!constantTimeEqual(expected, mac)) throw new Error('MAC mismatch');
  return decryptAesCbc(cipher, encKey, iv);
}

export async function encryptBw(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<string> {
  const iv = requireWebCrypto().getRandomValues(new Uint8Array(16));
  const cipher = await encryptAesCbc(data, encKey, iv);
  const mac = await hmacSha256(macKey, concatBytes(iv, cipher));
  return `2.${bytesToBase64(iv)}|${bytesToBase64(cipher)}|${bytesToBase64(mac)}`;
}

function parseCipherString(s: string): { type: number; iv: Uint8Array; ct: Uint8Array; mac: Uint8Array | null } {
  if (!s || typeof s !== 'string') throw new Error('invalid encrypted string');
  const p = s.indexOf('.');
  if (p <= 0) throw new Error('invalid encrypted string');
  const type = Number(s.slice(0, p));
  const body = s.slice(p + 1);
  const parts = body.split('|');
  if (type === 2 && parts.length === 3) {
    return { type: 2, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: base64ToBytes(parts[2]) };
  }
  if ((type === 0 || type === 1 || type === 4) && parts.length >= 2) {
    return { type, iv: base64ToBytes(parts[0]), ct: base64ToBytes(parts[1]), mac: null };
  }
  throw new Error('unsupported enc type');
}

export async function decryptBw(cipherString: string, encKey: Uint8Array, macKey?: Uint8Array): Promise<Uint8Array> {
  const parsed = parseCipherString(cipherString);
  if (parsed.type === 2 && macKey && parsed.mac) {
    const expected = await hmacSha256(macKey, concatBytes(parsed.iv, parsed.ct));
    if (!constantTimeEqual(expected, parsed.mac)) throw new Error('MAC mismatch');
  }
  return decryptAesCbc(parsed.ct, encKey, parsed.iv);
}

export async function decryptStr(cipherString: string | null | undefined, encKey: Uint8Array, macKey?: Uint8Array): Promise<string> {
  if (!cipherString || typeof cipherString !== 'string') return '';
  const plain = await decryptBw(cipherString, encKey, macKey);
  return new TextDecoder().decode(plain);
}

function normalizeTotpSecret(secret: string): string {
  return secret.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/g, '');
}

function readOtpAuthParam(raw: string, name: string): string {
  const queryStart = raw.indexOf('?');
  if (queryStart < 0) return '';
  const fragmentStart = raw.indexOf('#', queryStart + 1);
  const query = raw.slice(queryStart + 1, fragmentStart > queryStart ? fragmentStart : undefined);
  for (const part of query.split('&')) {
    const eq = part.indexOf('=');
    const key = eq >= 0 ? part.slice(0, eq) : part;
    if (key.trim().toLowerCase() !== name.toLowerCase()) continue;
    const value = eq >= 0 ? part.slice(eq + 1) : '';
    try {
      return decodeURIComponent(value.replace(/\+/g, ' '));
    } catch {
      return value;
    }
  }
  return '';
}

function parseSteamSecret(raw: string): string {
  const match = raw.trim().match(/^steam:\/\/([^/?#]+)(?:[/?#].*)?$/i);
  if (!match?.[1]) return '';
  try {
    return normalizeTotpSecret(decodeURIComponent(match[1]));
  } catch {
    return normalizeTotpSecret(match[1]);
  }
}

type TotpHashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

interface TotpConfig {
  secret: string;
  steam: boolean;
  algorithm: TotpHashAlgorithm;
  digits: number;
  period: number;
}

const DEFAULT_TOTP_CONFIG: Omit<TotpConfig, 'secret' | 'steam'> = {
  algorithm: 'SHA-1',
  digits: 6,
  period: 30,
};

function parseTotpDigits(value: string | null): number {
  if (!value) return DEFAULT_TOTP_CONFIG.digits;
  const parsed = Number(value);
  if (!Number.isInteger(parsed)) return DEFAULT_TOTP_CONFIG.digits;
  return Math.max(0, Math.min(10, parsed));
}

function parseTotpPeriod(value: string | null): number {
  if (!value) return DEFAULT_TOTP_CONFIG.period;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) return DEFAULT_TOTP_CONFIG.period;
  return Math.max(1, parsed);
}

function parseTotpHashAlgorithm(value: string | null): TotpHashAlgorithm {
  const normalized = (value || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '');
  if (normalized === 'SHA256') return 'SHA-256';
  if (normalized === 'SHA512') return 'SHA-512';
  return 'SHA-1';
}

export function normalizeTotpInput(raw: string): string {
  const s = raw.trim();
  if (!s) return '';
  if (/^otpauth-migration:\/\//i.test(s)) {
    const parsed = parseGoogleAuthenticatorMigrationPage(s);
    const accepted = parsed.ok ? parsed.page.accounts.filter((account) => account.kind === 'accepted') : [];
    return accepted.length === 1 ? accepted[0].totp : '';
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^otpauth:\/\//i.test(s) && !/^steam:\/\//i.test(s)) {
    return '';
  }
  return s;
}

function parseTotpConfig(raw: string): TotpConfig {
  const s = normalizeTotpInput(raw);
  if (!s) return { secret: '', steam: false, ...DEFAULT_TOTP_CONFIG };
  if (/^steam:\/\//i.test(s)) {
    return {
      secret: parseSteamSecret(s),
      steam: true,
      algorithm: 'SHA-1',
      digits: 5,
      period: 30,
    };
  }
  if (/^otpauth:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      return {
        secret: normalizeTotpSecret(u.searchParams.get('secret') || ''),
        steam: false,
        algorithm: parseTotpHashAlgorithm(u.searchParams.get('algorithm')),
        digits: parseTotpDigits(u.searchParams.get('digits')),
        period: parseTotpPeriod(u.searchParams.get('period')),
      };
    } catch {
      return {
        secret: normalizeTotpSecret(readOtpAuthParam(s, 'secret')),
        steam: false,
        algorithm: parseTotpHashAlgorithm(readOtpAuthParam(s, 'algorithm')),
        digits: parseTotpDigits(readOtpAuthParam(s, 'digits')),
        period: parseTotpPeriod(readOtpAuthParam(s, 'period')),
      };
    }
  }
  return { secret: normalizeTotpSecret(s), steam: false, ...DEFAULT_TOTP_CONFIG };
}

export function extractTotpSecret(raw: string): string {
  return parseTotpConfig(raw).secret;
}

function base32ToBytes(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (let i = 0; i < clean.length; i += 1) {
    const idx = alphabet.indexOf(clean.charAt(i));
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export interface TotpCodeResult {
  code: string;
  remain: number;
  period: number;
}

export async function calcTotpNow(rawSecret: string, nowMs: number = Date.now()): Promise<TotpCodeResult | null> {
  const { secret, steam, algorithm, digits, period } = parseTotpConfig(rawSecret);
  if (!secret) return null;
  const keyBytes = base32ToBytes(secret);
  if (!keyBytes.length) return null;
  const epoch = Math.floor(nowMs / 1000);
  const counter = Math.floor(epoch / period);
  const remain = period - (epoch % period);

  const message = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i -= 1) {
    message[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const subtle = requireWebCrypto().subtle;
  const key = await subtle.importKey('raw', toBufferSource(keyBytes), { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const hs = new Uint8Array(await subtle.sign('HMAC', key, toBufferSource(message)));
  const offset = hs[hs.length - 1] & 0x0f;
  const bin = ((hs[offset] & 0x7f) << 24) | ((hs[offset + 1] & 0xff) << 16) | ((hs[offset + 2] & 0xff) << 8) | (hs[offset + 3] & 0xff);
  let code = (bin % (10 ** digits)).toString().padStart(digits, '0');
  if (steam) {
    const chars = '23456789BCDFGHJKMNPQRTVWXY';
    let value = bin;
    code = '';
    for (let i = 0; i < 5; i += 1) {
      code += chars[value % chars.length];
      value = Math.floor(value / chars.length);
    }
  }
  return { code, remain, period };
}
