import { useMemo, useState } from 'preact/hooks';
import type { ImportAttachmentFile, ImportResultSummary } from '@/components/ImportPage';
import type { ExportRequest, ZipAttachmentEntry } from '@/lib/export-formats';
import {
  attachNodeWardenEncryptedAttachmentPayload,
  buildAccountEncryptedBitwardenJsonString,
  buildBitwardenCsvString,
  buildBitwardenZipBytes,
  buildExportFileName,
  buildNodeWardenAttachmentRecords,
  buildNodeWardenPlainJsonDocument,
  buildPasswordProtectedBitwardenJsonString,
  buildPlainBitwardenJsonString,
  encryptZipBytesWithPassword,
} from '@/lib/export-formats';
import { base64ToBytes, decryptBw, decryptBwFileData, decryptStr } from '@/lib/crypto';
import { decryptSingleCipher } from '@/lib/decrypt-cipher';
import { t } from '@/lib/i18n';
import {
  buildPublicSendUrl,
  importCipherToDraft,
  looksLikeCipherString,
  summarizeImportResult,
} from '@/lib/app-support';
import { buildSendShareKey, bulkDeleteSends, createSend, deleteSend, updateSend } from '@/lib/api/send';
import {
  archiveCipher,
  buildCipherImportPayload,
  bulkArchiveCiphers,
  bulkDeleteCiphers,
  bulkDeleteFolders,
  bulkMoveCiphers,
  bulkPermanentDeleteCiphers,
  bulkRestoreCiphers,
  bulkUnarchiveCiphers,
  createCipher,
  createFolder,
  deleteCipher,
  deleteCipherAttachment,
  deleteFolder,
  downloadCipherAttachmentDecrypted,
  encryptFolderImportName,
  getAttachmentDownloadInfo,
  getCipherById,
  importCiphers,
  permanentDeleteCipher,
  type CiphersImportPayload,
  type ImportedCipherMapEntry,
  updateCipher,
  updateFolder,
  unarchiveCipher,
  uploadCipherAttachment,
} from '@/lib/api/vault';
import { deriveLoginHash, getPreloginKdfConfig, verifyMasterPassword } from '@/lib/api/auth';
import type { AuthedFetch } from '@/lib/api/shared';
import { downloadBytesAsFile } from '@/lib/download';
import type { Cipher, Folder as VaultFolder, Profile, Send, SendDraft, SessionState, VaultDraft } from '@/lib/types';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface UseVaultSendActionsOptions {
  authedFetch: AuthedFetch;
  importAuthedFetch: AuthedFetch;
  session: SessionState | null;
  profile: Profile | null;
  defaultKdfIterations: number;
  encryptedCiphers: Cipher[] | undefined;
  encryptedFolders: VaultFolder[] | undefined;
  refetchCiphers: () => Promise<{ data?: Cipher[] | undefined } | unknown>;
  refetchFolders: () => Promise<{ data?: VaultFolder[] | undefined } | unknown>;
  refetchSends: () => Promise<unknown>;
  onNotify: Notify;
  patchEncryptedCiphers: (updater: (prev: Cipher[]) => Cipher[]) => void;
  patchEncryptedFolders: (updater: (prev: VaultFolder[]) => VaultFolder[]) => void;
  patchEncryptedSends: (updater: (prev: Send[]) => Send[]) => void;
  patchDecryptedCiphers: (updater: (prev: Cipher[]) => Cipher[]) => void;
  patchDecryptedFolders: (updater: (prev: VaultFolder[]) => VaultFolder[]) => void;
  patchDecryptedSends: (updater: (prev: Send[]) => Send[]) => void;
  refreshVaultRevisionStamp: () => Promise<void>;
}

function extractImportIdMaps(cipherMap: ImportedCipherMapEntry[] | null) {
  const byIndex = new Map<number, string>();
  const bySourceId = new Map<string, string>();
  for (const row of cipherMap || []) {
    const idx = Number(row?.index);
    const id = String(row?.id || '').trim();
    if (!Number.isFinite(idx) || !id) continue;
    byIndex.set(idx, id);
    const sourceId = String(row?.sourceId || '').trim();
    if (sourceId) bySourceId.set(sourceId, id);
  }
  return { byIndex, bySourceId };
}

function createOptimisticCipherId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return `optimistic:${crypto.randomUUID()}`;
  }
  return `optimistic:${Date.now().toString(36)}:${Math.random().toString(36).slice(2, 10)}`;
}

function optimisticCipherFromDraft(draft: VaultDraft, current?: Cipher | null): Cipher {
  const now = new Date().toISOString();
  const type = Number(draft.type || current?.type || 1) || 1;
  const next: Cipher = {
    ...(current || {}),
    id: current?.id || createOptimisticCipherId(),
    type,
    folderId: draft.folderId || null,
    favorite: !!draft.favorite,
    reprompt: draft.reprompt ? 1 : 0,
    name: draft.name || '',
    notes: draft.notes || '',
    decName: draft.name || '',
    decNotes: draft.notes || '',
    creationDate: current?.creationDate || now,
    revisionDate: now,
    deletedDate: current?.deletedDate || null,
    archivedDate: current?.archivedDate || null,
  };

  if (type === 1) {
    next.login = {
      ...(current?.login || {}),
      username: draft.loginUsername || '',
      password: draft.loginPassword || '',
      totp: draft.loginTotp || '',
      decUsername: draft.loginUsername || '',
      decPassword: draft.loginPassword || '',
      decTotp: draft.loginTotp || '',
      uris: draft.loginUris.map((uri) => ({
        ...(uri.extra || {}),
        uri: uri.uri || '',
        decUri: uri.uri || '',
        match: uri.match ?? null,
      })),
      fido2Credentials: draft.loginFido2Credentials.map((credential) => ({ ...credential })),
    };
  } else {
    next.login = null;
  }

  if (type === 3) {
    next.card = {
      ...(current?.card || {}),
      cardholderName: draft.cardholderName || '',
      number: draft.cardNumber || '',
      brand: draft.cardBrand || '',
      expMonth: draft.cardExpMonth || '',
      expYear: draft.cardExpYear || '',
      code: draft.cardCode || '',
      decCardholderName: draft.cardholderName || '',
      decNumber: draft.cardNumber || '',
      decBrand: draft.cardBrand || '',
      decExpMonth: draft.cardExpMonth || '',
      decExpYear: draft.cardExpYear || '',
      decCode: draft.cardCode || '',
    };
  } else {
    next.card = null;
  }

  if (type === 4) {
    next.identity = {
      ...(current?.identity || {}),
      title: draft.identTitle || '',
      firstName: draft.identFirstName || '',
      middleName: draft.identMiddleName || '',
      lastName: draft.identLastName || '',
      username: draft.identUsername || '',
      company: draft.identCompany || '',
      ssn: draft.identSsn || '',
      passportNumber: draft.identPassportNumber || '',
      licenseNumber: draft.identLicenseNumber || '',
      email: draft.identEmail || '',
      phone: draft.identPhone || '',
      address1: draft.identAddress1 || '',
      address2: draft.identAddress2 || '',
      address3: draft.identAddress3 || '',
      city: draft.identCity || '',
      state: draft.identState || '',
      postalCode: draft.identPostalCode || '',
      country: draft.identCountry || '',
      decTitle: draft.identTitle || '',
      decFirstName: draft.identFirstName || '',
      decMiddleName: draft.identMiddleName || '',
      decLastName: draft.identLastName || '',
      decUsername: draft.identUsername || '',
      decCompany: draft.identCompany || '',
      decSsn: draft.identSsn || '',
      decPassportNumber: draft.identPassportNumber || '',
      decLicenseNumber: draft.identLicenseNumber || '',
      decEmail: draft.identEmail || '',
      decPhone: draft.identPhone || '',
      decAddress1: draft.identAddress1 || '',
      decAddress2: draft.identAddress2 || '',
      decAddress3: draft.identAddress3 || '',
      decCity: draft.identCity || '',
      decState: draft.identState || '',
      decPostalCode: draft.identPostalCode || '',
      decCountry: draft.identCountry || '',
    };
  } else {
    next.identity = null;
  }

  if (type === 5) {
    next.sshKey = {
      ...(current?.sshKey || {}),
      privateKey: draft.sshPrivateKey || '',
      publicKey: draft.sshPublicKey || '',
      keyFingerprint: draft.sshFingerprint || '',
      fingerprint: draft.sshFingerprint || '',
      decPrivateKey: draft.sshPrivateKey || '',
      decPublicKey: draft.sshPublicKey || '',
      decFingerprint: draft.sshFingerprint || '',
    };
  } else {
    next.sshKey = null;
  }

  next.fields = draft.customFields.map((field) => ({
    type: field.type,
    name: field.label,
    value: field.value,
    decName: field.label,
    decValue: field.value,
  }));

  return next;
}

function isEncryptedFieldUnresolved(raw: unknown, decrypted: unknown): boolean {
  const encrypted = String(raw || '').trim();
  if (!looksLikeCipherString(encrypted)) return false;
  const plain = String(decrypted || '').trim();
  return !plain || looksLikeCipherString(plain);
}

function hasUnresolvedCipherData(cipher: Cipher): boolean {
  const checks: Array<[unknown, unknown]> = [
    [cipher.name, cipher.decName],
    [cipher.notes, cipher.decNotes],
    [cipher.login?.username, cipher.login?.decUsername],
    [cipher.login?.password, cipher.login?.decPassword],
    [cipher.login?.totp, cipher.login?.decTotp],
    ...(cipher.login?.uris || []).map((uri) => [uri.uri, uri.decUri] as [unknown, unknown]),
    [cipher.card?.cardholderName, cipher.card?.decCardholderName],
    [cipher.card?.number, cipher.card?.decNumber],
    [cipher.card?.brand, cipher.card?.decBrand],
    [cipher.card?.expMonth, cipher.card?.decExpMonth],
    [cipher.card?.expYear, cipher.card?.decExpYear],
    [cipher.card?.code, cipher.card?.decCode],
    [cipher.identity?.title, cipher.identity?.decTitle],
    [cipher.identity?.firstName, cipher.identity?.decFirstName],
    [cipher.identity?.middleName, cipher.identity?.decMiddleName],
    [cipher.identity?.lastName, cipher.identity?.decLastName],
    [cipher.identity?.username, cipher.identity?.decUsername],
    [cipher.identity?.company, cipher.identity?.decCompany],
    [cipher.identity?.ssn, cipher.identity?.decSsn],
    [cipher.identity?.passportNumber, cipher.identity?.decPassportNumber],
    [cipher.identity?.licenseNumber, cipher.identity?.decLicenseNumber],
    [cipher.identity?.email, cipher.identity?.decEmail],
    [cipher.identity?.phone, cipher.identity?.decPhone],
    [cipher.identity?.address1, cipher.identity?.decAddress1],
    [cipher.identity?.address2, cipher.identity?.decAddress2],
    [cipher.identity?.address3, cipher.identity?.decAddress3],
    [cipher.identity?.city, cipher.identity?.decCity],
    [cipher.identity?.state, cipher.identity?.decState],
    [cipher.identity?.postalCode, cipher.identity?.decPostalCode],
    [cipher.identity?.country, cipher.identity?.decCountry],
    [cipher.sshKey?.privateKey, cipher.sshKey?.decPrivateKey],
    [cipher.sshKey?.publicKey, cipher.sshKey?.decPublicKey],
    [cipher.sshKey?.keyFingerprint || cipher.sshKey?.fingerprint, cipher.sshKey?.decFingerprint],
    ...(cipher.fields || []).flatMap((field) => [
      [field.name, field.decName] as [unknown, unknown],
      [field.value, field.decValue] as [unknown, unknown],
    ]),
  ];
  return checks.some(([raw, decrypted]) => isEncryptedFieldUnresolved(raw, decrypted));
}

export default function useVaultSendActions(options: UseVaultSendActionsOptions) {
  const {
    authedFetch,
    importAuthedFetch,
    session,
    profile,
    defaultKdfIterations,
    encryptedCiphers,
    encryptedFolders,
    refetchCiphers,
    refetchFolders,
    refetchSends,
    onNotify,
    patchEncryptedCiphers,
    patchEncryptedFolders,
    patchEncryptedSends,
    patchDecryptedCiphers,
    patchDecryptedFolders,
    patchDecryptedSends,
    refreshVaultRevisionStamp,
  } = options;
  const [downloadingAttachmentKey, setDownloadingAttachmentKey] = useState('');
  const [attachmentDownloadPercent, setAttachmentDownloadPercent] = useState<number | null>(null);
  const [uploadingAttachmentName, setUploadingAttachmentName] = useState('');
  const [attachmentUploadPercent, setAttachmentUploadPercent] = useState<number | null>(null);
  const [uploadingSendFileName, setUploadingSendFileName] = useState('');
  const [sendUploadPercent, setSendUploadPercent] = useState<number | null>(null);

  return useMemo(() => {
    const refetchVault = async () => {
      await Promise.all([refetchCiphers(), refetchFolders(), refetchSends()]);
    };

    const requireOnlineWrite = () => {
      if (session?.accessToken) return;
      throw new Error(t('txt_offline_vault_readonly'));
    };

    async function decryptAndPatch(encrypted: Cipher) {
      if (!session?.symEncKey || !session?.symMacKey) {
        await refetchCiphers();
        return;
      }
      patchEncryptedCiphers((prev) => {
        const idx = prev.findIndex((c) => c.id === encrypted.id);
        if (idx >= 0) {
          const next = [...prev];
          next[idx] = encrypted;
          return next;
        }
        return [encrypted, ...prev];
      });
      const encKey = base64ToBytes(session.symEncKey);
      const macKey = base64ToBytes(session.symMacKey);
      const decrypted = await decryptSingleCipher(encrypted, encKey, macKey);
      patchDecryptedCiphers((prev) => {
        const idx = prev.findIndex((c) => c.id === decrypted.id);
        if (idx >= 0) {
          const next = [...prev];
          next[idx] = decrypted;
          return next;
        }
        return [decrypted, ...prev];
      });
    }

    async function decryptAndReplaceOptimistic(optimisticId: string, encrypted: Cipher) {
      if (!session?.symEncKey || !session?.symMacKey) {
        await refetchCiphers();
        return;
      }
      patchEncryptedCiphers((prev) => [encrypted, ...prev.filter((cipher) => cipher.id !== optimisticId && cipher.id !== encrypted.id)]);
      const encKey = base64ToBytes(session.symEncKey);
      const macKey = base64ToBytes(session.symMacKey);
      const decrypted = await decryptSingleCipher(encrypted, encKey, macKey);
      patchDecryptedCiphers((prev) => {
        const next = prev.filter((cipher) => cipher.id !== optimisticId && cipher.id !== decrypted.id);
        return [decrypted, ...next];
      });
    }

    function removeCipherFromState(id: string) {
      patchEncryptedCiphers((prev) => prev.filter((c) => c.id !== id));
      patchDecryptedCiphers((prev) => prev.filter((c) => c.id !== id));
    }

    function patchCipherBatch(
      ids: string[],
      updater: (cipher: Cipher) => Cipher | null,
      options?: { patchEncrypted?: boolean; patchDecrypted?: boolean }
    ) {
      const idSet = new Set(ids.map((id) => String(id || '').trim()).filter(Boolean));
      if (!idSet.size) return;
      const shouldPatchEncrypted = options?.patchEncrypted !== false;
      const shouldPatchDecrypted = options?.patchDecrypted !== false;
      if (shouldPatchEncrypted) {
        patchEncryptedCiphers((prev) => {
          let changed = false;
          const next: Cipher[] = [];
          for (const cipher of prev) {
            if (!idSet.has(cipher.id)) {
              next.push(cipher);
              continue;
            }
            const updated = updater(cipher);
            changed = true;
            if (updated) next.push(updated);
          }
          return changed ? next : prev;
        });
      }
      if (shouldPatchDecrypted) {
        patchDecryptedCiphers((prev) => {
          let changed = false;
          const next: Cipher[] = [];
          for (const cipher of prev) {
            if (!idSet.has(cipher.id)) {
              next.push(cipher);
              continue;
            }
            const updated = updater(cipher);
            changed = true;
            if (updated) next.push(updated);
          }
          return changed ? next : prev;
        });
      }
    }

    function patchFolderBatch(ids: string[], updater: (folder: VaultFolder) => VaultFolder | null) {
      const idSet = new Set(ids.map((id) => String(id || '').trim()).filter(Boolean));
      if (!idSet.size) return;
      patchEncryptedFolders((prev) => {
        let changed = false;
        const next: VaultFolder[] = [];
        for (const folder of prev) {
          if (!idSet.has(folder.id)) {
            next.push(folder);
            continue;
          }
          const updated = updater(folder);
          changed = true;
          if (updated) next.push(updated);
        }
        return changed ? next : prev;
      });
      patchDecryptedFolders((prev) => {
        let changed = false;
        const next: VaultFolder[] = [];
        for (const folder of prev) {
          if (!idSet.has(folder.id)) {
            next.push(folder);
            continue;
          }
          const updated = updater(folder);
          changed = true;
          if (updated) next.push(updated);
        }
        return changed ? next : prev;
      });
    }

    function upsertEncryptedFolder(folder: VaultFolder) {
      patchEncryptedFolders((prev) => {
        const index = prev.findIndex((item) => item.id === folder.id);
        if (index < 0) return [folder, ...prev];
        const next = [...prev];
        next[index] = folder;
        return next;
      });
    }

    function upsertSend(send: Send) {
      patchEncryptedSends((prev) => {
        const index = prev.findIndex((item) => item.id === send.id);
        if (index < 0) return [send, ...prev];
        const next = [...prev];
        next[index] = send;
        return next;
      });
    }

    function removeSend(id: string) {
      patchEncryptedSends((prev) => prev.filter((send) => send.id !== id));
      patchDecryptedSends((prev) => prev.filter((send) => send.id !== id));
    }

    const uploadImportedAttachments = async (
      attachments: ImportAttachmentFile[],
      idMaps: { byIndex: Map<number, string>; bySourceId: Map<string, string> }
    ): Promise<{ total: number; imported: number; failed: Array<{ fileName: string; reason: string }> }> => {
      if (!attachments.length) {
        return { total: 0, imported: 0, failed: [] };
      }
      if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));

      const initialCiphers = (((await refetchCiphers()) as { data?: Cipher[] | undefined })?.data) || [];
      const cipherById = new Map(initialCiphers.map((cipher) => [String(cipher.id || ''), cipher]));
      const failed: Array<{ fileName: string; reason: string }> = [];
      let imported = 0;

      for (const attachment of attachments) {
        const sourceId = String(attachment.sourceCipherId || '').trim();
        const sourceIndex = Number(attachment.sourceCipherIndex);
        const byId = sourceId ? idMaps.bySourceId.get(sourceId) : null;
        const byIndex = Number.isFinite(sourceIndex) ? idMaps.byIndex.get(sourceIndex) : null;
        const targetCipherId = byId || byIndex || null;
        if (!targetCipherId) {
          failed.push({
            fileName: String(attachment.fileName || '').trim() || 'attachment.bin',
            reason: t('txt_import_attachment_target_not_found'),
          });
          continue;
        }

        const name = String(attachment.fileName || '').trim() || 'attachment.bin';
        const fileBytes = Uint8Array.from(attachment.bytes);
        const file = new File([fileBytes], name, { type: 'application/octet-stream' });
        const cipher = cipherById.get(targetCipherId) || null;
        try {
          setUploadingAttachmentName(name);
          setAttachmentUploadPercent(0);
          await uploadCipherAttachment(importAuthedFetch, session, targetCipherId, file, cipher, setAttachmentUploadPercent);
          imported += 1;
        } catch (error) {
          failed.push({
            fileName: name,
            reason: error instanceof Error ? error.message : t('txt_upload_attachment_failed'),
          });
        } finally {
          setUploadingAttachmentName('');
          setAttachmentUploadPercent(null);
        }
      }

      await refetchCiphers();
      return { total: attachments.length, imported, failed };
    };

    return {
      async refreshVault() {
        await refetchVault();
        onNotify('success', t('txt_vault_synced'));
      },

      async createVaultItem(draft: VaultDraft, attachments: File[] = []) {
        if (!session) return;
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        const optimistic = optimisticCipherFromDraft(draft, null);
        patchDecryptedCiphers((prev) => [optimistic, ...prev.filter((cipher) => cipher.id !== optimistic.id)]);
        try {
          const created = await createCipher(authedFetch, session, draft);
          for (const file of attachments) {
            setUploadingAttachmentName(file.name);
            setAttachmentUploadPercent(0);
            await uploadCipherAttachment(authedFetch, session, created.id, file, undefined, setAttachmentUploadPercent);
          }
          const finalCipher = attachments.length ? await getCipherById(authedFetch, created.id) : created;
          await decryptAndReplaceOptimistic(optimistic.id, finalCipher);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_item_created'));
        } catch (error) {
          patchDecryptedCiphers((prev) => prev.filter((cipher) => cipher.id !== optimistic.id));
          onNotify('error', error instanceof Error ? error.message : t('txt_create_item_failed'));
          throw error;
        } finally {
          setUploadingAttachmentName('');
          setAttachmentUploadPercent(null);
        }
      },

      async updateVaultItem(cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) {
        if (!session) return;
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        if (hasUnresolvedCipherData(cipher)) {
          throw new Error(t('txt_decrypt_failed_2'));
        }
        const addFiles = Array.isArray(options?.addFiles) ? options.addFiles : [];
        const removeAttachmentIds = Array.isArray(options?.removeAttachmentIds) ? options.removeAttachmentIds : [];
        const previousCipher: Cipher = {
          ...cipher,
          login: cipher.login ? { ...cipher.login, uris: cipher.login.uris ? [...cipher.login.uris] : cipher.login.uris } : cipher.login,
          card: cipher.card ? { ...cipher.card } : cipher.card,
          identity: cipher.identity ? { ...cipher.identity } : cipher.identity,
          sshKey: cipher.sshKey ? { ...cipher.sshKey } : cipher.sshKey,
          fields: cipher.fields ? cipher.fields.map((field) => ({ ...field })) : cipher.fields,
          attachments: cipher.attachments ? cipher.attachments.map((attachment) => ({ ...attachment })) : cipher.attachments,
          passwordHistory: cipher.passwordHistory ? cipher.passwordHistory.map((entry) => ({ ...entry })) : cipher.passwordHistory,
        };
        const optimistic = optimisticCipherFromDraft(draft, cipher);
        if (removeAttachmentIds.length || addFiles.length) {
          const removedSet = new Set(removeAttachmentIds.map((id) => String(id || '').trim()).filter(Boolean));
          optimistic.attachments = (cipher.attachments || [])
            .filter((attachment) => !removedSet.has(String(attachment?.id || '').trim()))
            .map((attachment) => ({ ...attachment }));
        }
        patchCipherBatch([cipher.id], () => optimistic, { patchEncrypted: false });
        try {
          const updated = await updateCipher(authedFetch, session, cipher, draft);
          for (const attachmentId of removeAttachmentIds) {
            const id = String(attachmentId || '').trim();
            if (!id) continue;
            await deleteCipherAttachment(authedFetch, cipher.id, id);
          }
          for (const file of addFiles) {
            setUploadingAttachmentName(file.name);
            setAttachmentUploadPercent(0);
            await uploadCipherAttachment(authedFetch, session, cipher.id, file, cipher, setAttachmentUploadPercent);
          }
          const finalCipher = addFiles.length || removeAttachmentIds.length
            ? await getCipherById(authedFetch, cipher.id)
            : updated;
          await decryptAndPatch(finalCipher);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_item_updated'));
        } catch (error) {
          patchCipherBatch([cipher.id], () => previousCipher, { patchEncrypted: false });
          onNotify('error', error instanceof Error ? error.message : t('txt_update_item_failed'));
          throw error;
        } finally {
          setUploadingAttachmentName('');
          setAttachmentUploadPercent(null);
        }
      },

      async downloadVaultAttachment(cipher: Cipher, attachmentId: string) {
        if (!session) return;
        const downloadKey = `${cipher.id}:${attachmentId}`;
        setDownloadingAttachmentKey(downloadKey);
        setAttachmentDownloadPercent(null);
        try {
          const file = await downloadCipherAttachmentDecrypted(authedFetch, session, cipher, attachmentId, setAttachmentDownloadPercent);
          const fileName = String(file.fileName || '').trim() || 'attachment.bin';
          downloadBytesAsFile(file.bytes, fileName, 'application/octet-stream');
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_download_failed'));
          throw error;
        } finally {
          setDownloadingAttachmentKey('');
          setAttachmentDownloadPercent(null);
        }
      },

      async deleteVaultItem(cipher: Cipher) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        const previousCipher = { ...cipher };
        if (cipher.deletedDate || (cipher as { deletedAt?: string | null }).deletedAt) {
          try {
            await permanentDeleteCipher(authedFetch, cipher.id);
            patchCipherBatch([cipher.id], () => null);
            void refreshVaultRevisionStamp();
            onNotify('success', t('txt_item_deleted_permanently'));
          } catch (error) {
            onNotify('error', error instanceof Error ? error.message : t('txt_permanent_delete_item_failed'));
            throw error;
          }
          return;
        }
        const deletedDate = new Date().toISOString();
        patchCipherBatch([cipher.id], (current) => ({ ...current, deletedDate, archivedDate: null, revisionDate: deletedDate }));
        try {
          const deleted = await deleteCipher(authedFetch, cipher.id);
          await decryptAndPatch(deleted);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_item_deleted'));
        } catch (error) {
          patchCipherBatch([cipher.id], () => previousCipher, { patchEncrypted: false });
          onNotify('error', error instanceof Error ? error.message : t('txt_delete_item_failed'));
          throw error;
        }
      },

      async archiveVaultItem(cipher: Cipher) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        const previousCipher = { ...cipher };
        const archivedDate = new Date().toISOString();
        patchCipherBatch([cipher.id], (current) => ({ ...current, archivedDate, deletedDate: null, revisionDate: archivedDate }));
        try {
          const archived = await archiveCipher(authedFetch, cipher.id);
          await decryptAndPatch(archived);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_item_archived'));
        } catch (error) {
          patchCipherBatch([cipher.id], () => previousCipher, { patchEncrypted: false });
          onNotify('error', error instanceof Error ? error.message : t('txt_archive_item_failed'));
          throw error;
        }
      },

      async unarchiveVaultItem(cipher: Cipher) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        const previousCipher = { ...cipher };
        const revisionDate = new Date().toISOString();
        patchCipherBatch([cipher.id], (current) => ({ ...current, archivedDate: null, revisionDate }));
        try {
          const unarchived = await unarchiveCipher(authedFetch, cipher.id);
          await decryptAndPatch(unarchived);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_item_unarchived'));
        } catch (error) {
          patchCipherBatch([cipher.id], () => previousCipher, { patchEncrypted: false });
          onNotify('error', error instanceof Error ? error.message : t('txt_unarchive_item_failed'));
          throw error;
        }
      },

      async bulkDeleteVaultItems(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkDeleteCiphers(authedFetch, ids);
          const deletedDate = new Date().toISOString();
          patchCipherBatch(ids, (cipher) => ({ ...cipher, deletedDate, archivedDate: null }));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_deleted_selected_items'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_delete_failed'));
          throw error;
        }
      },

      async bulkArchiveVaultItems(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkArchiveCiphers(authedFetch, ids);
          const archivedDate = new Date().toISOString();
          patchCipherBatch(ids, (cipher) => ({ ...cipher, archivedDate, deletedDate: null }));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_archived_selected_items'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_archive_failed'));
          throw error;
        }
      },

      async bulkUnarchiveVaultItems(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkUnarchiveCiphers(authedFetch, ids);
          patchCipherBatch(ids, (cipher) => ({ ...cipher, archivedDate: null }));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_unarchived_selected_items'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_unarchive_failed'));
          throw error;
        }
      },

      async bulkMoveVaultItems(ids: string[], folderId: string | null) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkMoveCiphers(authedFetch, ids, folderId);
          patchCipherBatch(ids, (cipher) => ({ ...cipher, folderId }));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_moved_selected_items'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_move_failed'));
          throw error;
        }
      },

      async createFolder(name: string) {
        const folderName = name.trim();
        if (!folderName) {
          onNotify('error', t('txt_folder_name_is_required'));
          return;
        }
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          if (!session) throw new Error(t('txt_vault_key_unavailable'));
          const created = await createFolder(authedFetch, session, folderName);
          upsertEncryptedFolder(created);
          patchDecryptedFolders((prev) => [
            {
              id: created.id,
              name: created.name || folderName,
              decName: folderName,
              revisionDate: created.revisionDate,
              creationDate: created.creationDate,
            },
            ...prev,
          ]);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_folder_created'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_create_folder_failed'));
          throw error;
        }
      },

      async deleteFolder(folderId: string) {
        const id = String(folderId || '').trim();
        if (!id) {
          onNotify('error', t('txt_folder_not_found'));
          return;
        }
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await deleteFolder(authedFetch, id);
          patchFolderBatch([id], () => null);
          patchEncryptedCiphers((prev) => prev.map((cipher) => (cipher.folderId === id ? { ...cipher, folderId: null } : cipher)));
          patchDecryptedCiphers((prev) => prev.map((cipher) => (cipher.folderId === id ? { ...cipher, folderId: null } : cipher)));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_folder_deleted'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_delete_folder_failed'));
          throw error;
        }
      },

      async renameFolder(folderId: string, name: string) {
        const id = String(folderId || '').trim();
        const nextName = String(name || '').trim();
        if (!id) {
          onNotify('error', t('txt_folder_not_found'));
          return;
        }
        if (!nextName) {
          onNotify('error', t('txt_folder_name_is_required'));
          return;
        }
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          if (!session) throw new Error(t('txt_vault_key_unavailable'));
          const updated = await updateFolder(authedFetch, session, id, nextName);
          upsertEncryptedFolder(updated);
          patchDecryptedFolders((prev) => prev.map((folder) => (
            folder.id === id
              ? { ...folder, name: updated.name || folder.name, decName: nextName, revisionDate: updated.revisionDate }
              : folder
          )));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_folder_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_update_folder_failed'));
          throw error;
        }
      },

      async bulkRestoreVaultItems(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkRestoreCiphers(authedFetch, ids);
          patchCipherBatch(ids, (cipher) => ({ ...cipher, deletedDate: null }));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_restored_selected_items'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_restore_failed'));
          throw error;
        }
      },

      async bulkPermanentDeleteVaultItems(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkPermanentDeleteCiphers(authedFetch, ids);
          patchCipherBatch(ids, () => null);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_deleted_selected_items_permanently'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_permanent_delete_failed'));
          throw error;
        }
      },

      async bulkDeleteFolders(folderIds: string[]) {
        const ids = Array.from(new Set(folderIds.map((id) => String(id || '').trim()).filter(Boolean)));
        if (!ids.length) return;
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkDeleteFolders(authedFetch, ids);
          const removedIds = new Set(ids);
          patchEncryptedFolders((prev) => prev.filter((folder) => !removedIds.has(folder.id)));
          patchEncryptedCiphers((prev) => prev.map((cipher) => (cipher.folderId && removedIds.has(cipher.folderId) ? { ...cipher, folderId: null } : cipher)));
          patchDecryptedFolders((prev) => prev.filter((folder) => !removedIds.has(folder.id)));
          patchDecryptedCiphers((prev) => prev.map((cipher) => (cipher.folderId && removedIds.has(cipher.folderId) ? { ...cipher, folderId: null } : cipher)));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_folders_deleted'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_delete_all_folders_failed'));
          throw error;
        }
      },

      async verifyMasterPassword(email: string, password: string) {
        const derived = await deriveLoginHash(email, password, defaultKdfIterations);
        await verifyMasterPassword(authedFetch, derived.hash);
      },

      async createSend(draft: SendDraft, autoCopyLink: boolean) {
        if (!session) return;
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          const fileName = draft.type === 'file' ? String(draft.file?.name || '').trim() : '';
          if (fileName) {
            setUploadingSendFileName(fileName);
            setSendUploadPercent(0);
          }
          const created = await createSend(authedFetch, session, draft, fileName ? setSendUploadPercent : undefined);
          upsertSend(created);
          void refreshVaultRevisionStamp();
          if (autoCopyLink && created.key && session.symEncKey && session.symMacKey) {
            const keyPart = await buildSendShareKey(created.key, session.symEncKey, session.symMacKey);
            const shareUrl = buildPublicSendUrl(window.location.origin, created.accessId, keyPart);
            await navigator.clipboard.writeText(shareUrl);
          }
          onNotify('success', t('txt_send_created'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_create_send_failed'));
          throw error;
        } finally {
          setUploadingSendFileName('');
          setSendUploadPercent(null);
        }
      },

      async updateSend(send: Send, draft: SendDraft, autoCopyLink: boolean) {
        if (!session) return;
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          const updated = await updateSend(authedFetch, session, send, draft);
          upsertSend(updated);
          void refreshVaultRevisionStamp();
          if (autoCopyLink && updated.key && session.symEncKey && session.symMacKey) {
            const keyPart = await buildSendShareKey(updated.key, session.symEncKey, session.symMacKey);
            const shareUrl = buildPublicSendUrl(window.location.origin, updated.accessId, keyPart);
            await navigator.clipboard.writeText(shareUrl);
          }
          onNotify('success', t('txt_send_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_update_send_failed'));
          throw error;
        }
      },

      async deleteSend(send: Send) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await deleteSend(authedFetch, send.id);
          removeSend(send.id);
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_send_deleted'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_delete_send_failed'));
          throw error;
        }
      },

      async bulkDeleteSends(ids: string[]) {
        try {
          requireOnlineWrite();
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_offline_vault_readonly'));
          throw error;
        }
        try {
          await bulkDeleteSends(authedFetch, ids);
          const idSet = new Set(ids.map((id) => String(id || '').trim()).filter(Boolean));
          patchEncryptedSends((prev) => prev.filter((send) => !idSet.has(send.id)));
          patchDecryptedSends((prev) => prev.filter((send) => !idSet.has(send.id)));
          void refreshVaultRevisionStamp();
          onNotify('success', t('txt_deleted_selected_sends'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_bulk_delete_sends_failed'));
          throw error;
        }
      },

      async importVault(
        payload: CiphersImportPayload,
        options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
        attachments: ImportAttachmentFile[] = []
      ): Promise<ImportResultSummary> {
        if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
        requireOnlineWrite();

        const mode = options.folderMode || 'original';
        const targetFolderId = (options.targetFolderId || '').trim() || null;
        const nextPayload: CiphersImportPayload = { ciphers: [], folders: [], folderRelationships: [] };

        if (mode === 'original') {
          const folderIndexByLegacyId = new Map<string, number>();
          const folderIndexByName = new Map<string, number>();
          for (let i = 0; i < payload.folders.length; i++) {
            const folderRaw = (payload.folders[i] || {}) as Record<string, unknown>;
            const name = String(folderRaw.name || '').trim();
            if (!name) continue;
            let folderIndex = folderIndexByName.get(name);
            if (folderIndex == null) {
              folderIndex = nextPayload.folders.length;
              nextPayload.folders.push({ name: await encryptFolderImportName(session, name) });
              folderIndexByName.set(name, folderIndex);
            }
            const legacyId = String(folderRaw.id || '').trim();
            if (legacyId) folderIndexByLegacyId.set(legacyId, folderIndex);
          }

          for (let i = 0; i < payload.ciphers.length; i++) {
            const raw = (payload.ciphers[i] || {}) as Record<string, unknown>;
            let folderIndex: number | undefined;
            for (const relation of payload.folderRelationships || []) {
              const cipherIndex = Number(relation?.key);
              const relFolderIndex = Number(relation?.value);
              if (cipherIndex !== i || !Number.isFinite(relFolderIndex)) continue;
              const importedFolder = payload.folders[relFolderIndex] as Record<string, unknown> | undefined;
              const importedName = String(importedFolder?.name || '').trim();
              if (importedName) folderIndex = folderIndexByName.get(importedName);
              if (folderIndex != null) break;
            }
            if (folderIndex == null) {
              const rawFolderId = String(raw.folderId || '').trim();
              if (rawFolderId) folderIndex = folderIndexByLegacyId.get(rawFolderId);
            }
            if (folderIndex == null) {
              const rawFolderName = String(raw.folder || '').trim();
              if (rawFolderName) folderIndex = folderIndexByName.get(rawFolderName);
            }
            if (folderIndex != null) {
              nextPayload.folderRelationships.push({ key: i, value: folderIndex });
            }
          }
        }

        for (let i = 0; i < payload.ciphers.length; i++) {
          const raw = (payload.ciphers[i] || {}) as Record<string, unknown>;
          const draft = importCipherToDraft(raw, mode === 'target' ? targetFolderId : null);
          const cipherPayload = await buildCipherImportPayload(session, draft);
          const sourceId = String(raw.id || '').trim();
          if (sourceId) cipherPayload.id = sourceId;
          nextPayload.ciphers.push(cipherPayload);
        }

        const importedCipherMap = await importCiphers(importAuthedFetch, nextPayload, {
          returnCipherMap: attachments.length > 0,
        });
        await Promise.all([refetchFolders(), refetchCiphers()]);
        const attachmentSummary = attachments.length
          ? await uploadImportedAttachments(attachments, extractImportIdMaps(importedCipherMap))
          : undefined;
        return summarizeImportResult(payload.ciphers, mode === 'original' ? nextPayload.folders.length : 0, attachmentSummary);
      },

      async importEncryptedRaw(
        payload: CiphersImportPayload,
        options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
        attachments: ImportAttachmentFile[] = []
      ): Promise<ImportResultSummary> {
        const mode = options.folderMode || 'original';
        const targetFolderId = (options.targetFolderId || '').trim() || null;
        const nextPayload: CiphersImportPayload = {
          ciphers: payload.ciphers.map((raw) => ({ ...(raw as Record<string, unknown>) })),
          folders: mode === 'original' ? payload.folders : [],
          folderRelationships: mode === 'original' ? payload.folderRelationships : [],
        };
        if (mode === 'none') {
          for (const raw of nextPayload.ciphers) (raw as Record<string, unknown>).folderId = null;
        } else if (mode === 'target' && targetFolderId) {
          for (const raw of nextPayload.ciphers) (raw as Record<string, unknown>).folderId = targetFolderId;
        }

        const importedCipherMap = await importCiphers(importAuthedFetch, nextPayload, {
          returnCipherMap: attachments.length > 0,
        });
        await Promise.all([refetchCiphers(), refetchFolders()]);
        const attachmentSummary = attachments.length
          ? await uploadImportedAttachments(attachments, extractImportIdMaps(importedCipherMap))
          : undefined;
        return summarizeImportResult(
          nextPayload.ciphers,
          mode === 'original' ? nextPayload.folders.length : 0,
          attachmentSummary
        );
      },

      async exportVault(request: ExportRequest) {
        if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
        const masterPassword = String(request.masterPassword || '').trim();
        if (!masterPassword) throw new Error(t('txt_master_password_is_required'));
        const email = String(profile?.email || session.email || '').trim().toLowerCase();
        if (!email) throw new Error(t('txt_profile_unavailable'));
        const verifyDerived = await deriveLoginHash(email, masterPassword, defaultKdfIterations);
        await verifyMasterPassword(authedFetch, verifyDerived.hash);

        const rawFolders = encryptedFolders || [];
        const rawCiphers = encryptedCiphers || [];
        if (!rawFolders || !rawCiphers) throw new Error(t('txt_vault_not_ready'));

        let plainJsonCache: string | null = null;
        let plainJsonDocCache: Record<string, unknown> | null = null;
        let encryptedJsonCache: string | null = null;
        let nodeWardenAttachmentsCache: ReturnType<typeof buildNodeWardenAttachmentRecords> | null = null;

        const getPlainJson = async () => {
          if (!plainJsonCache) {
            plainJsonCache = await buildPlainBitwardenJsonString({
              folders: rawFolders,
              ciphers: rawCiphers,
              userEncB64: session.symEncKey!,
              userMacB64: session.symMacKey!,
            });
          }
          return plainJsonCache;
        };

        const getPlainJsonDoc = async () => {
          if (!plainJsonDocCache) {
            plainJsonDocCache = JSON.parse(await getPlainJson()) as Record<string, unknown>;
          }
          return plainJsonDocCache;
        };

        const getEncryptedJson = async () => {
          if (!encryptedJsonCache) {
            encryptedJsonCache = await buildAccountEncryptedBitwardenJsonString({
              folders: rawFolders,
              ciphers: rawCiphers,
              userEncB64: session.symEncKey!,
              userMacB64: session.symMacKey!,
            });
          }
          return encryptedJsonCache;
        };

        const zipAttachments = async (): Promise<ZipAttachmentEntry[]> => {
          const userEnc = base64ToBytes(session.symEncKey!);
          const userMac = base64ToBytes(session.symMacKey!);
          const out: ZipAttachmentEntry[] = [];
          const activeCiphers = rawCiphers.filter((cipher) => !cipher.deletedDate && !(cipher as { organizationId?: unknown }).organizationId);

          for (const cipher of activeCiphers) {
            const cipherId = String(cipher.id || '').trim();
            if (!cipherId) continue;
            const attachments = Array.isArray(cipher.attachments) ? cipher.attachments : [];
            if (!attachments.length) continue;

            let itemEnc = userEnc;
            let itemMac = userMac;
            const itemKey = String(cipher.key || '').trim();
            if (itemKey && looksLikeCipherString(itemKey)) {
              try {
                const rawItemKey = await decryptBw(itemKey, userEnc, userMac);
                if (rawItemKey.length >= 64) {
                  itemEnc = rawItemKey.slice(0, 32);
                  itemMac = rawItemKey.slice(32, 64);
                }
              } catch {
                // fallback to user key
              }
            }

            for (const attachment of attachments) {
              const attachmentId = String(attachment?.id || '').trim();
              if (!attachmentId) continue;
              const info = await getAttachmentDownloadInfo(authedFetch, cipherId, attachmentId);
              const fileResp = await fetch(info.url, { cache: 'no-store' });
              if (!fileResp.ok) throw new Error(`Failed to download attachment ${attachmentId}`);
              const encryptedBytes = new Uint8Array(await fileResp.arrayBuffer());

              let fileEnc = itemEnc;
              let fileMac = itemMac;
              const attachmentKeyCipher = String(info.key || attachment?.key || '').trim();
              if (attachmentKeyCipher && looksLikeCipherString(attachmentKeyCipher)) {
                try {
                  const rawAttachmentKey = await decryptBw(attachmentKeyCipher, itemEnc, itemMac);
                  if (rawAttachmentKey.length >= 64) {
                    fileEnc = rawAttachmentKey.slice(0, 32);
                    fileMac = rawAttachmentKey.slice(32, 64);
                  }
                } catch {
                  // fallback to item key
                }
              }

              const plainBytes = await decryptBwFileData(encryptedBytes, fileEnc, fileMac);
              const fileNameRaw = String(info.fileName || attachment?.fileName || '').trim();
              let fileName = fileNameRaw || `attachment-${attachmentId}`;
              if (fileNameRaw && looksLikeCipherString(fileNameRaw)) {
                try {
                  fileName = (await decryptStr(fileNameRaw, itemEnc, itemMac)) || fileName;
                } catch {
                  // fallback to raw encrypted name
                }
              }

              out.push({ cipherId, fileName, bytes: plainBytes });
            }
          }
          return out;
        };

        const getNodeWardenAttachmentRecords = async () => {
          if (nodeWardenAttachmentsCache) return nodeWardenAttachmentsCache;
          const [doc, attachments] = await Promise.all([getPlainJsonDoc(), zipAttachments()]);
          const cipherIndexById = new Map<string, number>();
          const items = Array.isArray(doc.items) ? (doc.items as Array<Record<string, unknown>>) : [];
          for (let i = 0; i < items.length; i++) {
            const id = String(items[i]?.id || '').trim();
            if (id) cipherIndexById.set(id, i);
          }
          nodeWardenAttachmentsCache = buildNodeWardenAttachmentRecords(attachments, cipherIndexById);
          return nodeWardenAttachmentsCache;
        };

        let result: { fileName: string; mimeType: string; bytes: Uint8Array } | null = null;
        const format = request.format;

        if (format === 'bitwarden_json') {
          result = {
            fileName: buildExportFileName(format),
            mimeType: 'application/json',
            bytes: new TextEncoder().encode(await getPlainJson()),
          };
        } else if (format === 'bitwarden_csv') {
          result = {
            fileName: buildExportFileName(format),
            mimeType: 'text/csv;charset=utf-8',
            bytes: new TextEncoder().encode(buildBitwardenCsvString(await getPlainJsonDoc())),
          };
        } else if (format === 'bitwarden_encrypted_json') {
          if (request.encryptedJsonMode === 'password') {
            const plainJson = await getPlainJson();
            const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
            const encrypted = await buildPasswordProtectedBitwardenJsonString({
              plaintextJson: plainJson,
              password: String(request.filePassword || ''),
              kdf,
            });
            result = {
              fileName: buildExportFileName(format),
              mimeType: 'application/json',
              bytes: new TextEncoder().encode(encrypted),
            };
          } else {
            result = {
              fileName: buildExportFileName(format),
              mimeType: 'application/json',
              bytes: new TextEncoder().encode(await getEncryptedJson()),
            };
          }
        } else if (format === 'nodewarden_json') {
          const [plainDoc, attachments] = await Promise.all([getPlainJsonDoc(), getNodeWardenAttachmentRecords()]);
          const nodeWardenDoc = buildNodeWardenPlainJsonDocument(plainDoc, attachments);
          result = {
            fileName: buildExportFileName(format),
            mimeType: 'application/json',
            bytes: new TextEncoder().encode(JSON.stringify(nodeWardenDoc, null, 2)),
          };
        } else if (format === 'nodewarden_encrypted_json') {
          if (request.encryptedJsonMode === 'password') {
            const [plainDoc, attachments] = await Promise.all([getPlainJsonDoc(), getNodeWardenAttachmentRecords()]);
            const nodeWardenDoc = buildNodeWardenPlainJsonDocument(plainDoc, attachments);
            const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
            const encrypted = await buildPasswordProtectedBitwardenJsonString({
              plaintextJson: JSON.stringify(nodeWardenDoc, null, 2),
              password: String(request.filePassword || ''),
              kdf,
            });
            result = {
              fileName: buildExportFileName(format),
              mimeType: 'application/json',
              bytes: new TextEncoder().encode(encrypted),
            };
          } else {
            const [encryptedJson, attachments] = await Promise.all([getEncryptedJson(), getNodeWardenAttachmentRecords()]);
            const withAttachments = await attachNodeWardenEncryptedAttachmentPayload(
              encryptedJson,
              attachments,
              session.symEncKey!,
              session.symMacKey!
            );
            result = {
              fileName: buildExportFileName(format),
              mimeType: 'application/json',
              bytes: new TextEncoder().encode(withAttachments),
            };
          }
        } else if (format === 'bitwarden_json_zip' || format === 'bitwarden_encrypted_json_zip') {
          let dataJson = await getPlainJson();
          if (format === 'bitwarden_encrypted_json_zip') {
            if (request.encryptedJsonMode === 'password') {
              const kdf = await getPreloginKdfConfig(profile?.email || session.email, defaultKdfIterations);
              dataJson = await buildPasswordProtectedBitwardenJsonString({
                plaintextJson: await getPlainJson(),
                password: String(request.filePassword || ''),
                kdf,
              });
            } else {
              dataJson = await getEncryptedJson();
            }
          }
          const attachments = await zipAttachments();
          const zipBytes = buildBitwardenZipBytes(dataJson, attachments);
          const encryptedZip = await encryptZipBytesWithPassword(zipBytes, String(request.zipPassword || ''));
          result = {
            fileName: buildExportFileName(format, encryptedZip.encrypted),
            mimeType: 'application/zip',
            bytes: encryptedZip.bytes,
          };
        }

        if (!result) throw new Error(t('txt_unsupported_export_format'));
        downloadBytesAsFile(result.bytes, result.fileName, result.mimeType);
      },
      downloadingAttachmentKey,
      attachmentDownloadPercent,
      uploadingAttachmentName,
      attachmentUploadPercent,
      uploadingSendFileName,
      sendUploadPercent,
    };
  }, [
    attachmentDownloadPercent,
    attachmentUploadPercent,
    authedFetch,
    defaultKdfIterations,
    downloadingAttachmentKey,
    encryptedCiphers,
    encryptedFolders,
    importAuthedFetch,
    onNotify,
    patchDecryptedCiphers,
    patchDecryptedFolders,
    patchDecryptedSends,
    patchEncryptedCiphers,
    patchEncryptedFolders,
    patchEncryptedSends,
    profile,
    refetchCiphers,
    refetchFolders,
    refetchSends,
    refreshVaultRevisionStamp,
    session,
    sendUploadPercent,
    uploadingAttachmentName,
    uploadingSendFileName,
  ]);
}
