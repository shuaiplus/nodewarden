import { base64ToBytes, concatBytes, decryptBw, decryptStr, encryptBw, encryptBwRsa, requireWebCrypto, toBufferSource } from './crypto';
import type { SessionState } from './types';

export interface OrgKeyPair {
  encKey: Uint8Array;
  macKey: Uint8Array;
  wrapped: string;
}

export async function createOrgKey(session: SessionState): Promise<OrgKeyPair> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const raw = requireWebCrypto().getRandomValues(new Uint8Array(64));
  const encKey = raw.slice(0, 32);
  const macKey = raw.slice(32);
  const wrapped = await encryptBw(raw, base64ToBytes(session.symEncKey), base64ToBytes(session.symMacKey));
  return { encKey, macKey, wrapped };
}

export async function unwrapOrgKey(session: SessionState, wrapped: string, encryptedPrivateKey?: string | null): Promise<{ encKey: Uint8Array; macKey: Uint8Array }> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const encKey = base64ToBytes(session.symEncKey);
  const macKey = base64ToBytes(session.symMacKey);
  let raw: Uint8Array;
  if (/^[34]\./.test(wrapped)) {
    if (!encryptedPrivateKey) throw new Error('Account private key unavailable');
    const algorithm = { name: 'RSA-OAEP', hash: wrapped.startsWith('3.') ? 'SHA-256' : 'SHA-1' };
    const privateKeyBytes = await decryptBw(encryptedPrivateKey, encKey, macKey);
    const subtle = requireWebCrypto().subtle;
    const privateKey = await subtle.importKey('pkcs8', toBufferSource(privateKeyBytes), algorithm, false, ['decrypt']);
    raw = new Uint8Array(await subtle.decrypt(algorithm, privateKey, toBufferSource(base64ToBytes(wrapped.slice(2)))));
  } else {
    raw = await decryptBw(wrapped, encKey, macKey);
  }
  if (raw.length !== 64) throw new Error('Invalid organization key');
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32) };
}

// Upstream DefaultOrganizationUserService.buildConfirmRequest: the org key goes to the member wrapped
// with their public key (encapsulateKeyUnsigned); the confirming admin's own vault key would leave
// the member unable to decrypt it.
export async function wrapOrgKeyForMember(session: SessionState, wrappedOrgKey: string, memberPublicKey: string, encryptedPrivateKey?: string | null): Promise<string> {
  const { encKey, macKey } = await unwrapOrgKey(session, wrappedOrgKey, encryptedPrivateKey);
  return encryptBwRsa(concatBytes(encKey, macKey), memberPublicKey);
}

// Secrets Manager names, keys, values and notes are EncStrings under the org key: upstream requires
// [EncryptedString] on each, and official web and bws decrypt them with that key. Taking an unwrapped
// key keeps key-unwrapping failures separate from individual field-decryption failures.
export function encryptWithOrgKey(orgKey: Pick<OrgKeyPair, 'encKey' | 'macKey'>, value: string): Promise<string> {
  return encryptBw(new TextEncoder().encode(value), orgKey.encKey, orgKey.macKey);
}

export function decryptWithOrgKey(orgKey: Pick<OrgKeyPair, 'encKey' | 'macKey'>, value: string): Promise<string> {
  return decryptStr(value, orgKey.encKey, orgKey.macKey);
}
