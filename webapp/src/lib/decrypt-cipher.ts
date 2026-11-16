import { base64ToBytes, decryptStr, decryptBw } from './crypto';
import { looksLikeCipherString } from './app-support';
import type { Cipher } from './types';
import type { OrgKeyMap } from './vault-decrypt';

async function decryptCipherField(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean,
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, itemEnc, itemMac);
  } catch {
    // Try the legacy user-key path for mixed key/field ciphers.
  }
  if (canFallbackToUserKey) {
    try {
      return await decryptStr(value, userEnc, userMac);
    } catch {
      // Preserve the old raw fallback for fields that are genuinely unreadable.
    }
  }
  return looksLikeCipherString(value) ? '' : value;
}

export async function decryptSingleCipher(
  encrypted: Cipher,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  orgKeys?: OrgKeyMap | null,
): Promise<Cipher> {
  // Organization ciphers decrypt with the org key (or a per-cipher key
  // wrapped by it) instead of the user key.
  let baseEnc = userEnc;
  let baseMac = userMac;
  const orgKey = orgKeys && encrypted.organizationId ? orgKeys[encrypted.organizationId] : null;
  if (orgKey) {
    try {
      baseEnc = base64ToBytes(orgKey.encB64);
      baseMac = base64ToBytes(orgKey.macB64);
    } catch {
      // fall back to user key
    }
  }

  let itemEnc = baseEnc;
  let itemMac = baseMac;
  let usesItemKey = false;
  if (encrypted.key) {
    try {
      const itemKey = await decryptBw(encrypted.key, baseEnc, baseMac);
      if (itemKey.length >= 64) {
        itemEnc = itemKey.slice(0, 32);
        itemMac = itemKey.slice(32, 64);
        usesItemKey = true;
      }
    } catch { /* keep base key */ }
  }

  const canFallbackToUserKey = usesItemKey;

  const decrypted: Cipher = {
    ...encrypted,
    decName: await decryptCipherField(encrypted.name, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
    decNotes: await decryptCipherField(encrypted.notes, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
  };

  if (encrypted.login) {
    decrypted.login = {
      ...encrypted.login,
      decUsername: await decryptCipherField(encrypted.login.username, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decPassword: await decryptCipherField(encrypted.login.password, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decTotp: await decryptCipherField(encrypted.login.totp, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      uris: await Promise.all((encrypted.login.uris || []).map(async (u) => ({
        ...u,
        decUri: await decryptCipherField(u.uri, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      }))),
    };
  }

  if (Array.isArray(encrypted.passwordHistory)) {
    decrypted.passwordHistory = await Promise.all(
      encrypted.passwordHistory.map(async (entry) => ({
        ...entry,
        decPassword: await decryptCipherField(entry?.password, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      }))
    );
  }

  if (encrypted.card) {
    decrypted.card = {
      ...encrypted.card,
      decCardholderName: await decryptCipherField(encrypted.card.cardholderName, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decNumber: await decryptCipherField(encrypted.card.number, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decBrand: await decryptCipherField(encrypted.card.brand, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decExpMonth: await decryptCipherField(encrypted.card.expMonth, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decExpYear: await decryptCipherField(encrypted.card.expYear, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decCode: await decryptCipherField(encrypted.card.code, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
    };
  }

  if (encrypted.identity) {
    decrypted.identity = {
      ...encrypted.identity,
      decTitle: await decryptCipherField(encrypted.identity.title, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decFirstName: await decryptCipherField(encrypted.identity.firstName, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decMiddleName: await decryptCipherField(encrypted.identity.middleName, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decLastName: await decryptCipherField(encrypted.identity.lastName, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decUsername: await decryptCipherField(encrypted.identity.username, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decCompany: await decryptCipherField(encrypted.identity.company, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decSsn: await decryptCipherField(encrypted.identity.ssn, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decPassportNumber: await decryptCipherField(encrypted.identity.passportNumber, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decLicenseNumber: await decryptCipherField(encrypted.identity.licenseNumber, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decEmail: await decryptCipherField(encrypted.identity.email, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decPhone: await decryptCipherField(encrypted.identity.phone, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decAddress1: await decryptCipherField(encrypted.identity.address1, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decAddress2: await decryptCipherField(encrypted.identity.address2, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decAddress3: await decryptCipherField(encrypted.identity.address3, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decCity: await decryptCipherField(encrypted.identity.city, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decState: await decryptCipherField(encrypted.identity.state, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decPostalCode: await decryptCipherField(encrypted.identity.postalCode, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decCountry: await decryptCipherField(encrypted.identity.country, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
    };
  }

  if (encrypted.sshKey) {
    const fingerprint = encrypted.sshKey.keyFingerprint || encrypted.sshKey.fingerprint || '';
    decrypted.sshKey = {
      ...encrypted.sshKey,
      decPrivateKey: await decryptCipherField(encrypted.sshKey.privateKey, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      decPublicKey: await decryptCipherField(encrypted.sshKey.publicKey, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      keyFingerprint: fingerprint || null,
      fingerprint: fingerprint || null,
      decFingerprint: await decryptCipherField(fingerprint, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
    };
  }

  if (encrypted.fields) {
    decrypted.fields = await Promise.all(
      encrypted.fields.map(async (field) => ({
        ...field,
        decName: await decryptCipherField(field.name, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
        decValue: await decryptCipherField(field.value, itemEnc, itemMac, baseEnc, baseMac, canFallbackToUserKey),
      }))
    );
  }

  return decrypted;
}
