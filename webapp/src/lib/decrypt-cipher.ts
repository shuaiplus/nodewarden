import { decryptStr, decryptBw } from './crypto';
import { looksLikeCipherString } from './app-support';
import type { Cipher } from './types';

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
): Promise<Cipher> {
  let itemEnc = userEnc;
  let itemMac = userMac;
  let usesItemKey = false;
  if (encrypted.key) {
    try {
      const itemKey = await decryptBw(encrypted.key, userEnc, userMac);
      if (itemKey.length >= 64) {
        itemEnc = itemKey.slice(0, 32);
        itemMac = itemKey.slice(32, 64);
        usesItemKey = true;
      }
    } catch { /* keep user key */ }
  }

  const canFallbackToUserKey = usesItemKey;

  const decrypted: Cipher = {
    ...encrypted,
    decName: await decryptCipherField(encrypted.name, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
    decNotes: await decryptCipherField(encrypted.notes, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
  };

  if (encrypted.login) {
    decrypted.login = {
      ...encrypted.login,
      decUsername: await decryptCipherField(encrypted.login.username, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decPassword: await decryptCipherField(encrypted.login.password, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decTotp: await decryptCipherField(encrypted.login.totp, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      uris: await Promise.all((encrypted.login.uris || []).map(async (u) => ({
        ...u,
        decUri: await decryptCipherField(u.uri, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      }))),
    };
  }

  if (Array.isArray(encrypted.passwordHistory)) {
    decrypted.passwordHistory = await Promise.all(
      encrypted.passwordHistory.map(async (entry) => ({
        ...entry,
        decPassword: await decryptCipherField(entry?.password, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      }))
    );
  }

  if (encrypted.card) {
    decrypted.card = {
      ...encrypted.card,
      decCardholderName: await decryptCipherField(encrypted.card.cardholderName, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decNumber: await decryptCipherField(encrypted.card.number, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decBrand: await decryptCipherField(encrypted.card.brand, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decExpMonth: await decryptCipherField(encrypted.card.expMonth, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decExpYear: await decryptCipherField(encrypted.card.expYear, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decCode: await decryptCipherField(encrypted.card.code, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
    };
  }

  if (encrypted.identity) {
    decrypted.identity = {
      ...encrypted.identity,
      decTitle: await decryptCipherField(encrypted.identity.title, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decFirstName: await decryptCipherField(encrypted.identity.firstName, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decMiddleName: await decryptCipherField(encrypted.identity.middleName, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decLastName: await decryptCipherField(encrypted.identity.lastName, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decUsername: await decryptCipherField(encrypted.identity.username, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decCompany: await decryptCipherField(encrypted.identity.company, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decSsn: await decryptCipherField(encrypted.identity.ssn, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decPassportNumber: await decryptCipherField(encrypted.identity.passportNumber, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decLicenseNumber: await decryptCipherField(encrypted.identity.licenseNumber, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decEmail: await decryptCipherField(encrypted.identity.email, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decPhone: await decryptCipherField(encrypted.identity.phone, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decAddress1: await decryptCipherField(encrypted.identity.address1, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decAddress2: await decryptCipherField(encrypted.identity.address2, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decAddress3: await decryptCipherField(encrypted.identity.address3, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decCity: await decryptCipherField(encrypted.identity.city, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decState: await decryptCipherField(encrypted.identity.state, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decPostalCode: await decryptCipherField(encrypted.identity.postalCode, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decCountry: await decryptCipherField(encrypted.identity.country, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
    };
  }

  if (encrypted.sshKey) {
    const fingerprint = encrypted.sshKey.keyFingerprint || encrypted.sshKey.fingerprint || '';
    decrypted.sshKey = {
      ...encrypted.sshKey,
      decPrivateKey: await decryptCipherField(encrypted.sshKey.privateKey, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      decPublicKey: await decryptCipherField(encrypted.sshKey.publicKey, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      keyFingerprint: fingerprint || null,
      fingerprint: fingerprint || null,
      decFingerprint: await decryptCipherField(fingerprint, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
    };
  }

  if (encrypted.fields) {
    decrypted.fields = await Promise.all(
      encrypted.fields.map(async (field) => ({
        ...field,
        decName: await decryptCipherField(field.name, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
        decValue: await decryptCipherField(field.value, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
      }))
    );
  }

  return decrypted;
}
