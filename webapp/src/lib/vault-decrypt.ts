import { base64ToBytes, decryptBw, decryptStr } from './crypto';
import { deriveSendKeyParts, looksLikeCipherString } from './app-support';
import type { Cipher, Folder, Send } from './types';

export interface DecryptVaultCoreArgs {
  folders: Folder[];
  ciphers: Cipher[];
  symEncKeyB64: string;
  symMacKeyB64: string;
}

export interface DecryptVaultCoreResult {
  folders: Folder[];
  ciphers: Cipher[];
}

export interface DecryptSendsArgs {
  sends: Send[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  origin: string;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function decryptField(
  value: string | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string> {
  if (!value || typeof value !== 'string') return '';
  try {
    return await decryptStr(value, enc, mac);
  } catch {
    return looksLikeCipherString(value) ? '' : value;
  }
}

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

async function decryptFieldWithSource(
  value: string | null | undefined,
  itemEnc: Uint8Array,
  itemMac: Uint8Array,
  userEnc: Uint8Array,
  userMac: Uint8Array,
  canFallbackToUserKey: boolean
): Promise<{ text: string; source: 'item' | 'user' | 'plain' }> {
  const raw = String(value || '').trim();
  if (!raw) return { text: '', source: 'plain' };
  try {
    return { text: await decryptStr(raw, itemEnc, itemMac), source: 'item' };
  } catch {
    // Try legacy user-key fallback below.
  }
  if (canFallbackToUserKey) {
    try {
      return { text: await decryptStr(raw, userEnc, userMac), source: 'user' };
    } catch {
      // Keep plain fallback.
    }
  }
  return { text: looksLikeCipherString(raw) ? '' : raw, source: 'plain' };
}

export async function decryptVaultCore(args: DecryptVaultCoreArgs): Promise<DecryptVaultCoreResult> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      ...folder,
      decName: await decryptField(folder.name, userEnc, userMac),
    }))
  );

  const ciphers = await Promise.all(
    args.ciphers.map(async (cipher) => {
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

      const itemUsesUserKey = sameBytes(itemEnc, userEnc) && sameBytes(itemMac, userMac);
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
        nextCipher.attachments = await Promise.all(
          cipher.attachments.map(async (attachment) => {
            const fileNameResult = await decryptFieldWithSource(
              attachment.fileName || '',
              itemEnc,
              itemMac,
              userEnc,
              userMac,
              !itemUsesUserKey
            );
            return {
              ...attachment,
              decFileName: fileNameResult.text,
            };
          })
        );
      }

      if (hasDecryptionFailure) {
        nextCipher.unresolved = true;
      }
      return nextCipher;
    })
  );

  return { folders, ciphers };
}

export async function decryptSends(args: DecryptSendsArgs): Promise<Send[]> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);
  return Promise.all(
    args.sends.map(async (send) => {
      const nextSend: Send = { ...send };
      try {
        if (send.key) {
          const sendKeyRaw = await decryptBw(send.key, userEnc, userMac);
          const derived = await deriveSendKeyParts(sendKeyRaw);
          nextSend.decName = await decryptField(send.name || '', derived.enc, derived.mac);
          nextSend.decNotes = await decryptField(send.notes || '', derived.enc, derived.mac);
          nextSend.decText = await decryptField(send.text?.text || '', derived.enc, derived.mac);
          if (send.file?.fileName) {
            const decFileName = await decryptField(send.file.fileName, derived.enc, derived.mac);
            nextSend.file = {
              ...(send.file || {}),
              fileName: decFileName || send.file.fileName,
            };
          }
          nextSend.decShareKey = btoa(String.fromCharCode(...sendKeyRaw))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
          nextSend.shareUrl = `${args.origin}/#/send/${send.accessId}/${nextSend.decShareKey}`;
        } else {
          nextSend.decName = '';
          nextSend.decNotes = '';
          nextSend.decText = '';
        }
      } catch {
        nextSend.decName = 'Decrypt failed';
      }
      return nextSend;
    })
  );
}
