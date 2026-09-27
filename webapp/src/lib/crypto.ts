import { PureCrypto, type Kdf } from '@bitwarden/sdk-internal';

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

// Master and export keys follow Bitwarden's KDF rules through the SDK: minimum parameters, and
// Argon2id over the SHA-256 of the salt, exactly as official clients derive them. The PBKDF2 helper
// above stays for what that KDF refuses: the one-iteration master-password hash and the Send hash.
export async function deriveKdfMaterial(password: string, salt: string, kdf: Kdf): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  return PureCrypto.derive_kdf_material(encoder.encode(password), encoder.encode(salt), kdf);
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

// Bitwarden EncString, EncArrayBuffer and RSA key wrapping come from the official SDK, so ciphertext
// formats, MAC checks and padding follow the clients exactly. PureCrypto addresses a symmetric key by
// its 64-byte enc||mac serialisation. The adapters stay async so SDK errors surface as rejections.
export async function encryptBwFileData(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  return PureCrypto.symmetric_encrypt_filedata(data, concatBytes(encKey, macKey));
}

export async function decryptBwFileData(encrypted: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  return PureCrypto.symmetric_decrypt_filedata(encrypted, concatBytes(encKey, macKey));
}

export async function encryptBw(data: Uint8Array, encKey: Uint8Array, macKey: Uint8Array): Promise<string> {
  return PureCrypto.symmetric_encrypt_bytes(data, concatBytes(encKey, macKey));
}

// Official clients hand a symmetric key to another account (auth request approval, org member confirm)
// as a type 4 (RSA-OAEP SHA-1) EncString under that account's SPKI public key.
export async function encryptBwRsa(symmetricKey: Uint8Array, publicKeyB64: string): Promise<string> {
  return PureCrypto.encapsulate_key_unsigned(symmetricKey, base64ToBytes(publicKeyB64));
}

export async function decryptBw(cipherString: string, encKey: Uint8Array, macKey: Uint8Array): Promise<Uint8Array> {
  return PureCrypto.symmetric_decrypt_bytes(cipherString, concatBytes(encKey, macKey));
}

// Lenient UTF-8 decoding keeps a damaged field readable instead of failing the whole item.
export async function decryptStr(cipherString: string | null | undefined, encKey: Uint8Array, macKey: Uint8Array): Promise<string> {
  if (!cipherString || typeof cipherString !== 'string') return '';
  return new TextDecoder().decode(await decryptBw(cipherString, encKey, macKey));
}
