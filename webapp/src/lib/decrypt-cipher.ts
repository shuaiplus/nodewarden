import { decryptBw, decryptStr } from './crypto';
import { looksLikeCipherString } from './app-support';
import type { Cipher } from './types';

async function decryptCipherField(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean,
  onError?: () => void
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

async function decryptCipherObjectFields<T extends Record<string, unknown>>(
  source: T | null | undefined,
  fields: readonly string[],
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean,
  onError?: () => void
): Promise<T | null | undefined> {
  if (!source || typeof source !== 'object') return source;
  const next: Record<string, unknown> = { ...source };
  for (const field of fields) {
    const decKey = `dec${field.charAt(0).toUpperCase()}${field.slice(1)}`;
    next[decKey] = await decryptCipherField(
      source[field] as string | null | undefined,
      itemEnc,
      itemMac,
      userEnc,
      userMac,
      canFallbackToUserKey,
      onError
    );
  }
  return next as T;
}

export async function decryptSingleCipher(
  cipher: Cipher,
  userEnc: Uint8Array,
  userMac: Uint8Array,
): Promise<Cipher> {
  let itemEnc = userEnc;
  let itemMac = userMac;
  let usesItemKey = false;
  if (cipher.key) {
    try {
      const itemKey = await decryptBw(cipher.key, userEnc, userMac);
      if (itemKey.length >= 64) {
        itemEnc = itemKey.slice(0, 32);
        itemMac = itemKey.slice(32, 64);
        usesItemKey = true;
      }
    } catch {
      // Keep user key fallback.
    }
  }

  const canFallbackToUserKey = usesItemKey;
  let hasDecryptionFailure = false;
  const onDecryptError = () => { hasDecryptionFailure = true; };
  const decField = (val: string | null | undefined) =>
    decryptCipherField(val, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey, onDecryptError);
  const decObjFields = <T extends Record<string, unknown>>(src: T | null | undefined, flds: readonly string[]) =>
    decryptCipherObjectFields(src, flds, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey, onDecryptError);

  const nextCipher: Cipher = {
    ...cipher,
    decName: await decField(cipher.name || ''),
    decNotes: await decField(cipher.notes || ''),
  };

  if (cipher.login) {
    nextCipher.login = {
      ...cipher.login,
      decUsername: await decField(cipher.login.username || ''),
      decPassword: await decField(cipher.login.password || ''),
      decTotp: await decField(cipher.login.totp || ''),
      uris: await Promise.all(
        (cipher.login.uris || []).map(async (uri) => ({
          ...uri,
          decUri: await decField(uri.uri || ''),
        }))
      ),
    };
  }

  if (Array.isArray(cipher.passwordHistory)) {
    nextCipher.passwordHistory = await Promise.all(
      cipher.passwordHistory.map(async (entry) => ({
        ...entry,
        decPassword: await decField(entry?.password || ''),
      }))
    );
  }

  if (cipher.card) {
    nextCipher.card = {
      ...cipher.card,
      decCardholderName: await decField(cipher.card.cardholderName || ''),
      decNumber: await decField(cipher.card.number || ''),
      decBrand: await decField(cipher.card.brand || ''),
      decExpMonth: await decField(cipher.card.expMonth || ''),
      decExpYear: await decField(cipher.card.expYear || ''),
      decCode: await decField(cipher.card.code || ''),
    };
  }

  if (cipher.identity) {
    nextCipher.identity = {
      ...cipher.identity,
      decTitle: await decField(cipher.identity.title || ''),
      decFirstName: await decField(cipher.identity.firstName || ''),
      decMiddleName: await decField(cipher.identity.middleName || ''),
      decLastName: await decField(cipher.identity.lastName || ''),
      decUsername: await decField(cipher.identity.username || ''),
      decCompany: await decField(cipher.identity.company || ''),
      decSsn: await decField(cipher.identity.ssn || ''),
      decPassportNumber: await decField(cipher.identity.passportNumber || ''),
      decLicenseNumber: await decField(cipher.identity.licenseNumber || ''),
      decEmail: await decField(cipher.identity.email || ''),
      decPhone: await decField(cipher.identity.phone || ''),
      decAddress1: await decField(cipher.identity.address1 || ''),
      decAddress2: await decField(cipher.identity.address2 || ''),
      decAddress3: await decField(cipher.identity.address3 || ''),
      decCity: await decField(cipher.identity.city || ''),
      decState: await decField(cipher.identity.state || ''),
      decPostalCode: await decField(cipher.identity.postalCode || ''),
      decCountry: await decField(cipher.identity.country || ''),
    };
  }

  if (cipher.sshKey) {
    const encryptedFingerprint = cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint || '';
    nextCipher.sshKey = {
      ...cipher.sshKey,
      decPrivateKey: await decField(cipher.sshKey.privateKey || ''),
      decPublicKey: await decField(cipher.sshKey.publicKey || ''),
      keyFingerprint: encryptedFingerprint || null,
      fingerprint: encryptedFingerprint || null,
      decFingerprint: await decField(encryptedFingerprint),
    };
  }

  if (cipher.bankAccount) {
    nextCipher.bankAccount = await decObjFields(
      cipher.bankAccount,
      ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone']
    );
  }

  if (cipher.driversLicense) {
    nextCipher.driversLicense = await decObjFields(
      cipher.driversLicense,
      ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass']
    );
  }

  if (cipher.passport) {
    nextCipher.passport = await decObjFields(
      cipher.passport,
      ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry', 'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate']
    );
  }

  if (cipher.fields) {
    nextCipher.fields = await Promise.all(
      cipher.fields.map(async (field) => ({
        ...field,
        decName: await decField(field.name || ''),
        decValue: await decField(field.value || ''),
      }))
    );
  }

  if (Array.isArray(cipher.attachments)) {
    nextCipher.attachments = await Promise.all(cipher.attachments.map(async (attachment) => ({
      ...attachment,
      decFileName: await decryptCipherField(attachment.fileName, itemEnc, itemMac, userEnc, userMac, canFallbackToUserKey),
    })));
  }

  nextCipher.unresolved = hasDecryptionFailure;
  return nextCipher;
}
