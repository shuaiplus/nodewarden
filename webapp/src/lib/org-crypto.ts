// CONTRACT:
// Organization key cryptography, mirroring the Bitwarden client model:
// - An organization owns a random 64-byte symmetric key (enc 32 + mac 32).
// - The org key is distributed to each member encrypted with that member's
//   RSA public key ("4.<b64>" EncString), stored on the member row.
// - The org has its own RSA keypair; the private key is stored encrypted with
//   the org key ("2.iv|ct|mac").
// - Org ciphers/collections are encrypted with the org key. The server never
//   sees any of this material in the clear.
//
// OAEP HASH COMPATIBILITY (important):
// Official Bitwarden clients RSA-OAEP-encrypt org keys with **SHA-1** — the
// "Rsa2048_OaepSha256_B64" type name is historical; the actual OAEP hash in
// the official clients and the bitwarden SDK is SHA-1. Wraps produced by
// earlier NodeWarden webapp versions used SHA-256 and are unreadable by
// official clients. New wraps use SHA-1; unwrapping tries SHA-1 first and
// falls back to SHA-256 so legacy wraps keep working and can be repaired.
import { base64ToBytes, bytesToBase64, decryptBw, encryptBw, requireWebCrypto, toBufferSource } from './crypto';

export interface OrgKeyParts {
  encB64: string;
  macB64: string;
  encBytes: Uint8Array;
  macBytes: Uint8Array;
}

export interface UnwrappedOrgKey {
  parts: OrgKeyParts;
  /** True when the key was wrapped with the legacy SHA-256 OAEP hash and
   * should be re-wrapped with SHA-1 for official-client compatibility. */
  legacySha256Wrap: boolean;
  raw: Uint8Array;
}

function parseRsaEncString(value: string): Uint8Array {
  const trimmed = String(value || '').trim();
  const dot = trimmed.indexOf('.');
  if (dot !== 1 || trimmed.slice(0, dot) !== '4') {
    throw new Error('Invalid organization key format');
  }
  return base64ToBytes(trimmed.slice(dot + 1));
}

async function importPrivateKeyWithHash(
  pkcs8: Uint8Array,
  hash: 'SHA-1' | 'SHA-256'
): Promise<CryptoKey> {
  return requireWebCrypto().subtle.importKey(
    'pkcs8',
    toBufferSource(pkcs8),
    { name: 'RSA-OAEP', hash },
    false,
    ['decrypt']
  );
}

// Decrypt the user's RSA private key (profile.privateKey, encrypted with the
// user symmetric key) into raw PKCS8 bytes.
export async function decryptPrivateKeyPkcs8(
  privateKeyEnc: string | null | undefined,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<Uint8Array | null> {
  if (!privateKeyEnc || !userEnc || !userMac) return null;
  try {
    return await decryptBw(privateKeyEnc, userEnc, userMac);
  } catch {
    return null;
  }
}

// Back-compat helper: imports the private key with the legacy SHA-256 OAEP
// hash. Prefer decryptPrivateKeyPkcs8 + unwrapOrganizationKeyDetailed.
export async function importUserPrivateKey(
  privateKeyEnc: string | null | undefined,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<CryptoKey | null> {
  const pkcs8 = await decryptPrivateKeyPkcs8(privateKeyEnc, userEnc, userMac);
  if (!pkcs8) return null;
  try {
    return await importPrivateKeyWithHash(pkcs8, 'SHA-256');
  } catch {
    return null;
  }
}

// Unwrap an organization key "4." EncString: try the official SHA-1 OAEP
// hash first, then the legacy SHA-256 hash. Results are cached by the
// encrypted key string so repeated vault decrypts stay cheap.
const unwrappedOrgKeyCache = new Map<string, UnwrappedOrgKey>();

export async function unwrapOrganizationKeyDetailed(
  organizationId: string,
  orgKeyEnc: string | null | undefined,
  pkcs8: Uint8Array
): Promise<UnwrappedOrgKey | null> {
  const cacheKey = `${organizationId}:${orgKeyEnc || ''}`;
  const cached = unwrappedOrgKeyCache.get(cacheKey);
  if (cached) return cached;

  if (!orgKeyEnc || !orgKeyEnc.startsWith('4.')) return null;
  let wrapped: Uint8Array;
  try {
    wrapped = parseRsaEncString(orgKeyEnc);
  } catch {
    return null;
  }

  const subtle = requireWebCrypto().subtle;
  const candidates: Array<'SHA-1' | 'SHA-256'> = ['SHA-1', 'SHA-256'];
  for (const hash of candidates) {
    try {
      const privateKey = await importPrivateKeyWithHash(pkcs8, hash);
      const raw = new Uint8Array(
        await subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, toBufferSource(wrapped))
      );
      if (raw.length < 64) continue;
      const encBytes = raw.slice(0, 32);
      const macBytes = raw.slice(32, 64);
      const result: UnwrappedOrgKey = {
        parts: {
          encBytes,
          macBytes,
          encB64: bytesToBase64(encBytes),
          macB64: bytesToBase64(macBytes),
        },
        legacySha256Wrap: hash === 'SHA-256',
        raw,
      };
      unwrappedOrgKeyCache.set(cacheKey, result);
      return result;
    } catch {
      // try the next hash
    }
  }
  return null;
}

export async function unwrapOrganizationKey(
  organizationId: string,
  orgKeyEnc: string | null | undefined,
  pkcs8: Uint8Array
): Promise<OrgKeyParts | null> {
  const detailed = await unwrapOrganizationKeyDetailed(organizationId, orgKeyEnc, pkcs8);
  return detailed ? detailed.parts : null;
}

// Generate the 64-byte organization symmetric key.
export function generateOrganizationKeyBytes(): Uint8Array {
  return requireWebCrypto().getRandomValues(new Uint8Array(64));
}

export function orgKeyBytesToParts(raw: Uint8Array): OrgKeyParts {
  if (raw.length < 64) throw new Error('Organization key must be 64 bytes');
  const encBytes = raw.slice(0, 32);
  const macBytes = raw.slice(32, 64);
  return {
    encBytes,
    macBytes,
    encB64: bytesToBase64(encBytes),
    macB64: bytesToBase64(macBytes),
  };
}

// Generate the organization RSA keypair. The private key is exported as PKCS8
// and encrypted with the org key (EncString type 2); the public key is plain
// base64 SPKI, exactly like users.public_key.
export async function generateOrganizationKeyPair(
  orgKey: OrgKeyParts
): Promise<{ publicKeyB64: string; encryptedPrivateKey: string }> {
  const subtle = requireWebCrypto().subtle;
  const pair = await subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt']
  );
  const spki = new Uint8Array(await subtle.exportKey('spki', pair.publicKey));
  const pkcs8 = new Uint8Array(await subtle.exportKey('pkcs8', pair.privateKey));
  const encryptedPrivateKey = await encryptBw(pkcs8, orgKey.encBytes, orgKey.macBytes);
  return { publicKeyB64: bytesToBase64(spki), encryptedPrivateKey };
}

// Wrap the org key for a member: RSA-OAEP encrypt with the member's public
// key (base64 SPKI), producing the "4.<b64>" EncString stored on confirm.
// Uses SHA-1 to match official Bitwarden clients (see the OAEP note above).
export async function wrapOrganizationKeyForUser(
  orgKeyRaw: Uint8Array,
  memberPublicKeyB64: string
): Promise<string> {
  const subtle = requireWebCrypto().subtle;
  const spki = base64ToBytes(String(memberPublicKeyB64 || '').trim());
  const publicKey = await subtle.importKey(
    'spki',
    toBufferSource(spki),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const wrapped = new Uint8Array(
    await subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, toBufferSource(orgKeyRaw))
  );
  return `4.${bytesToBase64(wrapped)}`;
}

export async function encryptWithOrgKey(
  value: string,
  orgKey: OrgKeyParts
): Promise<string> {
  return encryptBw(new TextEncoder().encode(value), orgKey.encBytes, orgKey.macBytes);
}

export function clearUnwrappedOrgKeyCache(): void {
  unwrappedOrgKeyCache.clear();
}
