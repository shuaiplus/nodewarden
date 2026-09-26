import { base64ToBytes, bytesToBase64, concatBytes, decryptBw, encryptBw, encryptBwRsa, requireWebCrypto } from './crypto';
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

export async function unwrapOrgKey(session: SessionState, wrapped: string): Promise<{ encKey: Uint8Array; macKey: Uint8Array }> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const raw = await decryptBw(wrapped, base64ToBytes(session.symEncKey), base64ToBytes(session.symMacKey));
  return { encKey: raw.slice(0, 32), macKey: raw.slice(32) };
}

// Upstream DefaultOrganizationUserService.buildConfirmRequest: the org key goes to the member wrapped
// with their public key (encapsulateKeyUnsigned); the confirming admin's own vault key would leave
// the member unable to decrypt it.
export async function wrapOrgKeyForMember(session: SessionState, wrappedOrgKey: string, memberPublicKey: string): Promise<string> {
  const { encKey, macKey } = await unwrapOrgKey(session, wrappedOrgKey);
  return encryptBwRsa(concatBytes(encKey, macKey), memberPublicKey);
}

export function encodeOrgKeyB64(encKey: Uint8Array, macKey: Uint8Array): string {
  const raw = new Uint8Array(64);
  raw.set(encKey, 0);
  raw.set(macKey, 32);
  return bytesToBase64(raw);
}
