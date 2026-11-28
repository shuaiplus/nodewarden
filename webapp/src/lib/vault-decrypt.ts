import { base64ToBytes, decryptBw, decryptStr } from './crypto';
import { deriveSendKeyParts, looksLikeCipherString } from './app-support';
import type { Cipher, Folder, Send, VaultCollection } from './types';
import { decryptSingleCipher } from './decrypt-cipher';

// Per-organization decryption keys: base64 enc/mac halves of the organization
// symmetric key, resolved on the main thread via org-crypto before decryption.
export interface OrgKeyMaterial {
  encB64: string;
  macB64: string;
}

export type OrgKeyMap = Record<string, OrgKeyMaterial>;

export interface DecryptVaultCoreArgs {
  folders: Folder[];
  ciphers: Cipher[];
  /** Organization collections to decrypt alongside the vault (encrypted names). */
  collections?: VaultCollection[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  /** Organization keys by organizationId; required to decrypt org ciphers. */
  orgKeys?: OrgKeyMap | null;
}

export interface DecryptVaultCoreResult {
  folders: Folder[];
  ciphers: Cipher[];
  /** Organization collections with decrypted names. */
  collections: VaultCollection[];
}

export interface DecryptSendsArgs {
  sends: Send[];
  symEncKeyB64: string;
  symMacKeyB64: string;
  origin: string;
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

export async function decryptVaultCore(args: DecryptVaultCoreArgs): Promise<DecryptVaultCoreResult> {
  const userEnc = base64ToBytes(args.symEncKeyB64);
  const userMac = base64ToBytes(args.symMacKeyB64);

  // Pre-decoded org keys: collections decrypt with the raw bytes, ciphers go
  // through decryptSingleCipher with the base64 map.
  const orgKeyBytes = new Map<string, { enc: Uint8Array; mac: Uint8Array }>();
  if (args.orgKeys) {
    for (const [organizationId, material] of Object.entries(args.orgKeys)) {
      orgKeyBytes.set(organizationId, {
        enc: base64ToBytes(material.encB64),
        mac: base64ToBytes(material.macB64),
      });
    }
  }

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      ...folder,
      decName: await decryptField(folder.name, userEnc, userMac),
    }))
  );

  // Org-aware through decryptSingleCipher: personal ciphers use the user key,
  // org ciphers the organization key (or a per-cipher key wrapped by it).
  const ciphers = await Promise.all(
    args.ciphers.map((cipher) => decryptSingleCipher(cipher, userEnc, userMac, args.orgKeys))
  );

  const collections = await Promise.all(
    (args.collections || []).map(async (collection) => {
      const orgKey = orgKeyBytes.get(collection.organizationId);
      let decName = '';
      if (collection.name && orgKey) {
        decName = await decryptField(collection.name, orgKey.enc, orgKey.mac);
      }
      return { ...collection, name: collection.name, decName };
    })
  );

  return { folders, ciphers, collections };
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
