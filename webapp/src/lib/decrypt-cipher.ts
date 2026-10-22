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
  onError?: () => void,
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
  if (looksLikeCipherString(value)) {
    onError?.();
    return '';
  }
  return value;
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
  let hasDecryptionFailure = false;
  const onDecryptError = () => { hasDecryptionFailure = true; };
  const decField = (val: string | null | undefined) =>
    decryptCipherField(val, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey, onDecryptError);

  const decrypted: Cipher = {
    ...encrypted,
    decName: await decField(encrypted.name),
    decNotes: await decField(encrypted.notes),
  };

  if (encrypted.login) {
    decrypted.login = {
      ...encrypted.login,
      decUsername: await decField(encrypted.login.username),
      decPassword: await decField(encrypted.login.password),
      decTotp: await decField(encrypted.login.totp),
      uris: await Promise.all((encrypted.login.uris || []).map(async (u) => ({
        ...u,
        decUri: await decField(u.uri),
      }))),
    };
  }

  if (Array.isArray(encrypted.passwordHistory)) {
    decrypted.passwordHistory = await Promise.all(
      encrypted.passwordHistory.map(async (entry) => ({
        ...entry,
        decPassword: await decField(entry?.password),
      }))
    );
  }

  if (encrypted.card) {
    decrypted.card = {
      ...encrypted.card,
      decCardholderName: await decField(encrypted.card.cardholderName),
      decNumber: await decField(encrypted.card.number),
      decBrand: await decField(encrypted.card.brand),
      decExpMonth: await decField(encrypted.card.expMonth),
      decExpYear: await decField(encrypted.card.expYear),
      decCode: await decField(encrypted.card.code),
    };
  }

  if (encrypted.identity) {
    decrypted.identity = {
      ...encrypted.identity,
      decTitle: await decField(encrypted.identity.title),
      decFirstName: await decField(encrypted.identity.firstName),
      decMiddleName: await decField(encrypted.identity.middleName),
      decLastName: await decField(encrypted.identity.lastName),
      decUsername: await decField(encrypted.identity.username),
      decCompany: await decField(encrypted.identity.company),
      decSsn: await decField(encrypted.identity.ssn),
      decPassportNumber: await decField(encrypted.identity.passportNumber),
      decLicenseNumber: await decField(encrypted.identity.licenseNumber),
      decEmail: await decField(encrypted.identity.email),
      decPhone: await decField(encrypted.identity.phone),
      decAddress1: await decField(encrypted.identity.address1),
      decAddress2: await decField(encrypted.identity.address2),
      decAddress3: await decField(encrypted.identity.address3),
      decCity: await decField(encrypted.identity.city),
      decState: await decField(encrypted.identity.state),
      decPostalCode: await decField(encrypted.identity.postalCode),
      decCountry: await decField(encrypted.identity.country),
    };
  }

  if (encrypted.sshKey) {
    const fingerprint = encrypted.sshKey.keyFingerprint || encrypted.sshKey.fingerprint || '';
    decrypted.sshKey = {
      ...encrypted.sshKey,
      decPrivateKey: await decField(encrypted.sshKey.privateKey),
      decPublicKey: await decField(encrypted.sshKey.publicKey),
      keyFingerprint: fingerprint || null,
      fingerprint: fingerprint || null,
      decFingerprint: await decField(fingerprint),
    };
  }

  if (encrypted.fields) {
    decrypted.fields = await Promise.all(
      encrypted.fields.map(async (field) => ({
        ...field,
        decName: await decField(field.name),
        decValue: await decField(field.value),
      }))
    );
  }

  if (hasDecryptionFailure) {
    decrypted.unresolved = true;
  }
  return decrypted;
}
