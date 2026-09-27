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

// EncryptionType.Rsa2048_OaepSha1_B64: official clients hand a symmetric key to another account
// (auth request approval, org member confirm) by RSA-OAEP SHA-1 wrapping it with that account's
// SPKI public key, so only its private key can open it.
const RSA_OAEP_SHA1_ENC_TYPE = 4;
const RSA_OAEP_SHA1: RsaHashedImportParams = { name: 'RSA-OAEP', hash: 'SHA-1' };

export async function encryptBwRsa(data: Uint8Array, publicKeyB64: string): Promise<string> {
  const subtle = requireWebCrypto().subtle;
  const publicKey = await subtle.importKey('spki', toBufferSource(base64ToBytes(publicKeyB64)), RSA_OAEP_SHA1, false, ['encrypt']);
  const encrypted = await subtle.encrypt(RSA_OAEP_SHA1, publicKey, toBufferSource(data));
  return `${RSA_OAEP_SHA1_ENC_TYPE}.${bytesToBase64(new Uint8Array(encrypted))}`;
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
