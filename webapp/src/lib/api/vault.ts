import { base64ToBytes, decryptBw, decryptBwFileData, decryptStr, encryptBw, encryptBwFileData, sha256Base64 } from '../crypto';
import type {
  Cipher,
  CipherPasswordHistoryEntry,
  Folder,
  SessionState,
  VaultDraft,
  VaultDraftField,
} from '../types';
import {
  BULK_API_CHUNK_SIZE,
  chunkArray,
  createApiError,
  parseErrorMessage,
  parseJson,
  uploadDirectEncryptedPayload,
  uploadWithProgress,
  type AuthedFetch,
} from './shared';
import { readResponseBytesWithProgress } from '../download';
import { loadVaultCoreSyncSnapshot } from './vault-sync';

type CipherLoginData = NonNullable<Cipher['login']>;
const NODEWARDEN_WEB_REPAIR_HEADER = 'X-NodeWarden-Web';

export async function getFolders(authedFetch: AuthedFetch, cacheKey: string): Promise<Folder[]> {
  const body = await loadVaultCoreSyncSnapshot(authedFetch, cacheKey);
  return body.folders || [];
}

export async function getFolderById(authedFetch: AuthedFetch, folderId: string): Promise<Folder> {
  const id = String(folderId || '').trim();
  if (!id) throw new Error('Folder id is required');
  const resp = await authedFetch(`/api/folders/${encodeURIComponent(id)}`);
  if (resp.status === 404) throw createApiError('Folder not found', 404);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Load folder failed'));
  const body = await parseJson<Folder>(resp);
  if (!body?.id) throw new Error('Load folder failed');
  return body;
}

export async function createFolder(
  authedFetch: AuthedFetch,
  session: SessionState,
  name: string
): Promise<Folder> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  const encryptedName = await encryptBw(new TextEncoder().encode(name), enc, mac);
  const resp = await authedFetch('/api/folders', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: encryptedName }),
  });
  if (!resp.ok) throw new Error('Create folder failed');
  const body = await parseJson<Folder>(resp);
  if (!body?.id) throw new Error('Create folder failed');
  return body;
}

export async function encryptFolderImportName(session: SessionState, name: string): Promise<string> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  return encryptBw(new TextEncoder().encode(name), enc, mac);
}

export async function deleteFolder(authedFetch: AuthedFetch, folderId: string): Promise<void> {
  const id = String(folderId || '').trim();
  if (!id) throw new Error('Folder id is required');
  const resp = await authedFetch(`/api/folders/${encodeURIComponent(id)}`, {
    method: 'DELETE',
  });
  if (!resp.ok) throw new Error('Delete folder failed');
}

export async function bulkDeleteFolders(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/folders/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk delete folders failed');
  }
}

export async function updateFolder(
  authedFetch: AuthedFetch,
  session: SessionState,
  folderId: string,
  name: string
): Promise<Folder> {
  const id = String(folderId || '').trim();
  if (!id) throw new Error('Folder id is required');
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const enc = base64ToBytes(session.symEncKey);
  const mac = base64ToBytes(session.symMacKey);
  const encryptedName = await encryptBw(new TextEncoder().encode(name), enc, mac);
  const resp = await authedFetch(`/api/folders/${encodeURIComponent(id)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: encryptedName }),
  });
  if (!resp.ok) throw new Error('Update folder failed');
  const body = await parseJson<Folder>(resp);
  if (!body?.id) throw new Error('Update folder failed');
  return body;
}

export async function getCiphers(authedFetch: AuthedFetch, cacheKey: string): Promise<Cipher[]> {
  const body = await loadVaultCoreSyncSnapshot(authedFetch, cacheKey);
  return body.ciphers || [];
}

export async function getCipherById(authedFetch: AuthedFetch, cipherId: string): Promise<Cipher> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}`);
  if (resp.status === 404) throw createApiError('Cipher not found', 404);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Load cipher failed'));
  const body = await parseJson<Cipher>(resp);
  if (!body?.id) throw new Error('Load cipher failed');
  return body;
}

export interface CiphersImportPayload {
  ciphers: Array<Record<string, unknown>>;
  folders: Array<{ name: string }>;
  folderRelationships: Array<{ key: number; value: number }>;
}

export interface ImportedCipherMapEntry {
  index: number;
  sourceId: string | null;
  id: string;
}

const IMPORT_ITEM_LIMIT = 5000;

export async function importCiphers(
  authedFetch: AuthedFetch,
  payload: CiphersImportPayload,
  options?: { returnCipherMap?: boolean }
): Promise<ImportedCipherMapEntry[] | null> {
  const returnCipherMap = !!options?.returnCipherMap;
  const url = returnCipherMap ? '/api/ciphers/import?returnCipherMap=1' : '/api/ciphers/import';
  const totalItems = (payload.folders?.length || 0) + (payload.ciphers?.length || 0);
  if (totalItems > IMPORT_ITEM_LIMIT) {
    throw new Error(`Import exceeds maximum of ${IMPORT_ITEM_LIMIT} items`);
  }
  const resp = await authedFetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Import failed'));
  if (!returnCipherMap) return null;

  const body =
    (await parseJson<{
      cipherMap?: Array<{ index?: number; sourceId?: string | null; id?: string }>;
    }>(resp)) || {};
  if (!Array.isArray(body.cipherMap)) return [];

  const responses: ImportedCipherMapEntry[] = [];
  for (const row of body.cipherMap) {
    const index = Number(row?.index);
    const id = String(row?.id || '').trim();
    if (!Number.isFinite(index) || !id) continue;
    const sourceRaw = String(row?.sourceId || '').trim();
    responses.push({
      index,
      id,
      sourceId: sourceRaw || null,
    });
  }
  return responses;
}

export interface AttachmentDownloadInfo {
  id: string;
  url: string;
  fileName: string | null;
  key: string | null;
  size: string | null;
  sizeName: string | null;
}

export async function getAttachmentDownloadInfo(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string
): Promise<AttachmentDownloadInfo> {
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Failed to load attachment'));
  const body =
    (await parseJson<{
      id?: string;
      url?: string;
      fileName?: string | null;
      key?: string | null;
      size?: string | null;
      sizeName?: string | null;
    }>(resp)) || {};
  const id = String(body.id || attachmentId || '').trim();
  const url = String(body.url || '').trim();
  if (!id || !url) throw new Error('Invalid attachment download response');
  return {
    id,
    url,
    fileName: body.fileName ?? null,
    key: body.key ?? null,
    size: body.size ?? null,
    sizeName: body.sizeName ?? null,
  };
}

function looksLikeCipherString(value: unknown): boolean {
  return /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/.test(String(value || '').trim());
}

export async function uploadCipherAttachment(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipherId: string,
  file: File,
  cipherForKey?: Cipher | null,
  onProgress?: (percent: number | null) => void
): Promise<void> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  if (!file) throw new Error('File is required');

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const itemKeys = await getCipherKeys(cipherForKey || null, userEnc, userMac);

  const encryptedFileName = await encryptTextValue(file.name, itemKeys.enc, itemKeys.mac);
  if (!encryptedFileName) throw new Error('Invalid attachment name');

  const attachmentRawKey = crypto.getRandomValues(new Uint8Array(64));
  const attachmentWrappedKey = await encryptBw(attachmentRawKey, itemKeys.enc, itemKeys.mac);
  const fileBytes = new Uint8Array(await file.arrayBuffer());
  const encryptedBytes = await encryptBwFileData(fileBytes, attachmentRawKey.slice(0, 32), attachmentRawKey.slice(32, 64));

  const metaResp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/attachment/v2`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      fileName: encryptedFileName,
      key: attachmentWrappedKey,
      fileSize: encryptedBytes.byteLength,
    }),
  });
  if (!metaResp.ok) throw new Error(await parseErrorMessage(metaResp, 'Create attachment failed'));

  const meta =
    (await parseJson<{
      attachmentId?: string;
      url?: string;
      fileUploadType?: number;
    }>(metaResp)) || {};
  const attachmentId = String(meta.attachmentId || '').trim();
  const uploadUrl = String(meta.url || '').trim();
  if (!attachmentId || !uploadUrl) throw new Error('Create attachment failed');
  if (!session.accessToken) throw new Error('Unauthorized');

  const payload = new ArrayBuffer(encryptedBytes.byteLength);
  new Uint8Array(payload).set(encryptedBytes);
  const uploadResp = await uploadDirectEncryptedPayload({
    accessToken: session.accessToken,
    uploadUrl,
    payload,
    fileUploadType: meta.fileUploadType,
    unsupportedMessage: 'Unsupported attachment upload type',
    onProgress,
  });
  if (!uploadResp.ok) {
    try {
      await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/attachment/${encodeURIComponent(attachmentId)}`, { method: 'DELETE' });
    } catch {
      // ignore rollback failure
    }
    throw new Error(await parseErrorMessage(uploadResp, 'Upload attachment failed'));
  }
}

export async function deleteCipherAttachment(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string
): Promise<void> {
  const cid = String(cipherId || '').trim();
  const aid = String(attachmentId || '').trim();
  if (!cid || !aid) throw new Error('Attachment id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cid)}/attachment/${encodeURIComponent(aid)}`, {
    method: 'DELETE',
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Delete attachment failed'));
}

export async function repairCipherAttachmentMetadata(
  authedFetch: AuthedFetch,
  cipherId: string,
  attachmentId: string,
  metadata: { fileName?: string; key?: string | null }
): Promise<void> {
  const resp = await authedFetch(
    `/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}/metadata`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(metadata),
    }
  );
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Update attachment metadata failed'));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  for (let i = 0; i < a.byteLength; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

async function decryptCipherStringWithKey(
  value: string,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Uint8Array | null> {
  try {
    return await decryptBw(value, enc, mac);
  } catch {
    return null;
  }
}

async function decryptAttachmentFileName(
  rawFileName: string,
  itemKeys: { enc: Uint8Array; mac: Uint8Array },
  userKeys: { enc: Uint8Array; mac: Uint8Array }
): Promise<{ fileName: string; source: 'plain' | 'item' | 'user' }> {
  const fallback = rawFileName || 'attachment.bin';
  if (!rawFileName || !looksLikeCipherString(rawFileName)) return { fileName: fallback, source: 'plain' };

  try {
    const fileName = await decryptStr(rawFileName, itemKeys.enc, itemKeys.mac);
    if (fileName) return { fileName, source: 'item' };
  } catch {
    // 继续尝试旧 user key 文件名。
  }

  if (!sameBytes(itemKeys.enc, userKeys.enc) || !sameBytes(itemKeys.mac, userKeys.mac)) {
    try {
      const fileName = await decryptStr(rawFileName, userKeys.enc, userKeys.mac);
      if (fileName) return { fileName, source: 'user' };
    } catch {
      // 保留原始文件名。
    }
  }

  return { fileName: fallback, source: 'plain' };
}

type AttachmentDecryptMode = 'attachment-item' | 'attachment-user' | 'legacy-item' | 'legacy-user';

interface AttachmentDecryptCandidate {
  mode: AttachmentDecryptMode;
  enc: Uint8Array;
  mac: Uint8Array;
  rawAttachmentKey: Uint8Array | null;
}

async function uploadRepairedAttachmentBlob(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipherId: string,
  attachmentId: string,
  encryptedBytes: Uint8Array
): Promise<void> {
  if (!session.accessToken) throw new Error('Unauthorized');
  const payload = new ArrayBuffer(encryptedBytes.byteLength);
  new Uint8Array(payload).set(encryptedBytes);
  const resp = await uploadWithProgress(`/api/ciphers/${encodeURIComponent(cipherId)}/attachment/${encodeURIComponent(attachmentId)}`, {
    accessToken: session.accessToken,
    method: 'PUT',
    headers: { 'Content-Type': 'application/octet-stream' },
    body: payload,
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Repair attachment upload failed'));
}

export async function downloadCipherAttachmentDecrypted(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipher: Cipher,
  attachmentId: string,
  onProgress?: (percent: number | null) => void
): Promise<{ fileName: string; bytes: Uint8Array }> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const cid = String(cipher?.id || '').trim();
  const aid = String(attachmentId || '').trim();
  if (!cid || !aid) throw new Error('Attachment id is required');

  const info = await getAttachmentDownloadInfo(authedFetch, cid, aid);
  const rawResp = await fetch(info.url, { cache: 'no-store' });
  if (!rawResp.ok) throw new Error('Download attachment failed');
  const encryptedBytes = await readResponseBytesWithProgress(rawResp, (progress) => onProgress?.(progress.percent));

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const itemKeys = await getCipherKeys(cipher, userEnc, userMac);
  const userKeys = { enc: userEnc, mac: userMac };

  const candidates: AttachmentDecryptCandidate[] = [];
  const keyCipher = String(info.key || '').trim();
  if (keyCipher && looksLikeCipherString(keyCipher)) {
    const itemWrappedKey = await decryptCipherStringWithKey(keyCipher, itemKeys.enc, itemKeys.mac);
    if (itemWrappedKey && itemWrappedKey.length >= 64) {
      candidates.push({
        mode: 'attachment-item',
        enc: itemWrappedKey.slice(0, 32),
        mac: itemWrappedKey.slice(32, 64),
        rawAttachmentKey: itemWrappedKey,
      });
    }

    if (!sameBytes(itemKeys.enc, userEnc) || !sameBytes(itemKeys.mac, userMac)) {
      const userWrappedKey = await decryptCipherStringWithKey(keyCipher, userEnc, userMac);
      if (userWrappedKey && userWrappedKey.length >= 64) {
        candidates.push({
          mode: 'attachment-user',
          enc: userWrappedKey.slice(0, 32),
          mac: userWrappedKey.slice(32, 64),
          rawAttachmentKey: userWrappedKey,
        });
      }
    }
  }
  candidates.push({ mode: 'legacy-item', enc: itemKeys.enc, mac: itemKeys.mac, rawAttachmentKey: null });
  if (!sameBytes(itemKeys.enc, userEnc) || !sameBytes(itemKeys.mac, userMac)) {
    candidates.push({ mode: 'legacy-user', enc: userEnc, mac: userMac, rawAttachmentKey: null });
  }

  let plainBytes: Uint8Array | null = null;
  let usedCandidate: AttachmentDecryptCandidate | null = null;
  for (const candidate of candidates) {
    try {
      plainBytes = await decryptBwFileData(encryptedBytes, candidate.enc, candidate.mac);
      usedCandidate = candidate;
      break;
    } catch {
      // 继续尝试下一种旧附件格式。
    }
  }
  if (!plainBytes || !usedCandidate) throw new Error('Attachment decryption failed');

  const fileNameRaw = String(info.fileName || '').trim();
  const nameResult = await decryptAttachmentFileName(fileNameRaw, itemKeys, userKeys);
  const fileName = nameResult.fileName || `attachment-${aid}`;

  try {
    const metadata: { fileName?: string; key?: string | null } = {};
    if (nameResult.source === 'user') {
      metadata.fileName = await encryptTextValue(fileName, itemKeys.enc, itemKeys.mac) || undefined;
    }

    if (usedCandidate.mode === 'attachment-user' && usedCandidate.rawAttachmentKey) {
      metadata.key = await encryptBw(usedCandidate.rawAttachmentKey, itemKeys.enc, itemKeys.mac);
    } else if (usedCandidate.mode === 'legacy-item') {
      metadata.key = null;
    } else if (usedCandidate.mode === 'legacy-user') {
      const repairedBytes = await encryptBwFileData(plainBytes, itemKeys.enc, itemKeys.mac);
      await uploadRepairedAttachmentBlob(authedFetch, session, cid, aid, repairedBytes);
      metadata.key = null;
    }

    if (Object.keys(metadata).length > 0) {
      await repairCipherAttachmentMetadata(authedFetch, cid, aid, metadata);
    }
  } catch {
    // 修复失败不影响本次下载，旧附件内容已经成功解密。
  }

  return { fileName, bytes: plainBytes };
}

function asNullable(v: string): string | null {
  const s = String(v || '').trim();
  return s ? s : null;
}

function parseFieldType(v: number | string): 0 | 1 | 2 | 3 {
  if (typeof v === 'number') {
    if (v === 1 || v === 2 || v === 3) return v;
    return 0;
  }
  const s = String(v).trim().toLowerCase();
  if (s === '1' || s === 'hidden') return 1;
  if (s === '2' || s === 'boolean' || s === 'checkbox') return 2;
  if (s === '3' || s === 'linked' || s === 'link') return 3;
  return 0;
}

async function encryptTextValue(value: string, enc: Uint8Array, mac: Uint8Array): Promise<string | null> {
  const s = String(value || '');
  if (!s.trim()) return null;
  return encryptBw(new TextEncoder().encode(s), enc, mac);
}

function stripDecodedObjectFields(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (/^dec[A-Z]/.test(key)) continue;
    out[key] = item;
  }
  return out;
}

async function encryptObjectFields(
  existing: unknown,
  entries: Array<[string, string]>,
  draft: VaultDraft,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Record<string, unknown>> {
  const out = stripDecodedObjectFields(existing);
  for (const [fieldName, draftKey] of entries) {
    out[fieldName] = await encryptTextValue(String((draft as unknown as Record<string, unknown>)[draftKey] || ''), enc, mac);
  }
  return out;
}

async function encryptPasswordHistory(
  entries: CipherPasswordHistoryEntry[] | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<CipherPasswordHistoryEntry[] | null> {
  if (!Array.isArray(entries) || entries.length === 0) return null;

  const out: CipherPasswordHistoryEntry[] = [];
  for (const entry of entries) {
    const rawPassword = String(entry?.password || '');
    const hasDecryptedPassword = typeof entry?.decPassword === 'string';
    const plainPassword = entry?.decPassword ?? rawPassword;
    const encryptedPassword = hasDecryptedPassword
      ? await encryptTextValue(plainPassword, enc, mac)
      : looksLikeCipherString(rawPassword)
      ? rawPassword
      : await encryptTextValue(plainPassword, enc, mac);
    if (!encryptedPassword) continue;
    out.push({
      password: encryptedPassword,
      lastUsedDate: toIsoDateOrNow(entry?.lastUsedDate),
    });
  }

  return out.length ? out : null;
}

function plainCipherValue(decrypted: unknown, raw: unknown = ''): string {
  if (typeof decrypted === 'string' && !looksLikeCipherString(decrypted)) return decrypted;
  const value = String(raw ?? '');
  return looksLikeCipherString(value) ? '' : value;
}

function draftFromDecryptedCipher(cipher: Cipher): VaultDraft {
  const type = Number(cipher.type || 1) || 1;
  const draft: VaultDraft = {
    type,
    name: plainCipherValue(cipher.decName, cipher.name).trim() || 'Untitled',
    notes: plainCipherValue(cipher.decNotes, cipher.notes),
    favorite: !!cipher.favorite,
    reprompt: Number(cipher.reprompt || 0) === 1,
    folderId: cipher.folderId || '',
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [{ uri: '', match: null, originalUri: '', extra: {} }],
    loginFido2Credentials: [],
    cardholderName: '',
    cardNumber: '',
    cardBrand: '',
    cardExpMonth: '',
    cardExpYear: '',
    cardCode: '',
    identTitle: '',
    identFirstName: '',
    identMiddleName: '',
    identLastName: '',
    identUsername: '',
    identCompany: '',
    identSsn: '',
    identPassportNumber: '',
    identLicenseNumber: '',
    identEmail: '',
    identPhone: '',
    identAddress1: '',
    identAddress2: '',
    identAddress3: '',
    identCity: '',
    identState: '',
    identPostalCode: '',
    identCountry: '',
    sshPrivateKey: '',
    sshPublicKey: '',
    sshFingerprint: '',
    bankName: '',
    bankNameOnAccount: '',
    bankAccountType: '',
    bankAccountNumber: '',
    bankRoutingNumber: '',
    bankBranchNumber: '',
    bankPin: '',
    bankSwiftCode: '',
    bankIban: '',
    bankContactPhone: '',
    licenseFirstName: '',
    licenseMiddleName: '',
    licenseLastName: '',
    licenseDateOfBirth: '',
    licenseNumber: '',
    licenseIssuingCountry: '',
    licenseIssuingState: '',
    licenseIssueDate: '',
    licenseExpirationDate: '',
    licenseIssuingAuthority: '',
    licenseClass: '',
    passportSurname: '',
    passportGivenName: '',
    passportDateOfBirth: '',
    passportSex: '',
    passportBirthPlace: '',
    passportNationality: '',
    passportIssuingCountry: '',
    passportNumber: '',
    passportType: '',
    passportNationalIdentificationNumber: '',
    passportIssuingAuthority: '',
    passportIssueDate: '',
    passportExpirationDate: '',
    customFields: [],
  };

  draft.customFields = (cipher.fields || [])
    .map((field) => ({
      type: parseFieldType(field.type ?? 0),
      label: plainCipherValue(field.decName, field.name).trim(),
      value: plainCipherValue(field.decValue, field.value),
    }))
    .filter((field) => field.label);

  if (type === 1 && cipher.login) {
    draft.loginUsername = plainCipherValue(cipher.login.decUsername, cipher.login.username);
    draft.loginPassword = plainCipherValue(cipher.login.decPassword, cipher.login.password);
    draft.loginTotp = plainCipherValue(cipher.login.decTotp, cipher.login.totp);
    draft.loginFido2Credentials = Array.isArray(cipher.login.fido2Credentials)
      ? cipher.login.fido2Credentials.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
      : [];
    const seenUris = new Set<string>();
    const uris = (cipher.login.uris || [])
      .map((entry) => {
        const uri = plainCipherValue(entry.decUri, entry.uri).trim();
        const extra = { ...(entry as Record<string, unknown>) };
        delete extra.uri;
        delete extra.uriChecksum;
        delete extra.match;
        delete extra.decUri;
        return {
          uri,
          match: typeof entry.match === 'number' && Number.isFinite(entry.match) ? entry.match : null,
          originalUri: '',
          extra,
        };
      })
      .filter((entry) => {
        if (!entry.uri) return false;
        const key = entry.uri.toLowerCase();
        if (seenUris.has(key)) return false;
        seenUris.add(key);
        return true;
      });
    draft.loginUris = uris.length ? uris : draft.loginUris;
  } else if (type === 3 && cipher.card) {
    draft.cardholderName = plainCipherValue(cipher.card.decCardholderName, cipher.card.cardholderName);
    draft.cardNumber = plainCipherValue(cipher.card.decNumber, cipher.card.number);
    draft.cardBrand = plainCipherValue(cipher.card.decBrand, cipher.card.brand);
    draft.cardExpMonth = plainCipherValue(cipher.card.decExpMonth, cipher.card.expMonth);
    draft.cardExpYear = plainCipherValue(cipher.card.decExpYear, cipher.card.expYear);
    draft.cardCode = plainCipherValue(cipher.card.decCode, cipher.card.code);
  } else if (type === 4 && cipher.identity) {
    draft.identTitle = plainCipherValue(cipher.identity.decTitle, cipher.identity.title);
    draft.identFirstName = plainCipherValue(cipher.identity.decFirstName, cipher.identity.firstName);
    draft.identMiddleName = plainCipherValue(cipher.identity.decMiddleName, cipher.identity.middleName);
    draft.identLastName = plainCipherValue(cipher.identity.decLastName, cipher.identity.lastName);
    draft.identUsername = plainCipherValue(cipher.identity.decUsername, cipher.identity.username);
    draft.identCompany = plainCipherValue(cipher.identity.decCompany, cipher.identity.company);
    draft.identSsn = plainCipherValue(cipher.identity.decSsn, cipher.identity.ssn);
    draft.identPassportNumber = plainCipherValue(cipher.identity.decPassportNumber, cipher.identity.passportNumber);
    draft.identLicenseNumber = plainCipherValue(cipher.identity.decLicenseNumber, cipher.identity.licenseNumber);
    draft.identEmail = plainCipherValue(cipher.identity.decEmail, cipher.identity.email);
    draft.identPhone = plainCipherValue(cipher.identity.decPhone, cipher.identity.phone);
    draft.identAddress1 = plainCipherValue(cipher.identity.decAddress1, cipher.identity.address1);
    draft.identAddress2 = plainCipherValue(cipher.identity.decAddress2, cipher.identity.address2);
    draft.identAddress3 = plainCipherValue(cipher.identity.decAddress3, cipher.identity.address3);
    draft.identCity = plainCipherValue(cipher.identity.decCity, cipher.identity.city);
    draft.identState = plainCipherValue(cipher.identity.decState, cipher.identity.state);
    draft.identPostalCode = plainCipherValue(cipher.identity.decPostalCode, cipher.identity.postalCode);
    draft.identCountry = plainCipherValue(cipher.identity.decCountry, cipher.identity.country);
  } else if (type === 5 && cipher.sshKey) {
    draft.sshPrivateKey = plainCipherValue(cipher.sshKey.decPrivateKey, cipher.sshKey.privateKey);
    draft.sshPublicKey = plainCipherValue(cipher.sshKey.decPublicKey, cipher.sshKey.publicKey);
    draft.sshFingerprint = plainCipherValue(
      cipher.sshKey.decFingerprint,
      cipher.sshKey.keyFingerprint || cipher.sshKey.fingerprint
    );
  } else if (type === 6 && cipher.bankAccount) {
    draft.bankName = plainCipherValue(cipher.bankAccount.decBankName, cipher.bankAccount.bankName);
    draft.bankNameOnAccount = plainCipherValue(cipher.bankAccount.decNameOnAccount, cipher.bankAccount.nameOnAccount);
    draft.bankAccountType = plainCipherValue(cipher.bankAccount.decAccountType, cipher.bankAccount.accountType);
    draft.bankAccountNumber = plainCipherValue(cipher.bankAccount.decAccountNumber, cipher.bankAccount.accountNumber);
    draft.bankRoutingNumber = plainCipherValue(cipher.bankAccount.decRoutingNumber, cipher.bankAccount.routingNumber);
    draft.bankBranchNumber = plainCipherValue(cipher.bankAccount.decBranchNumber, cipher.bankAccount.branchNumber);
    draft.bankPin = plainCipherValue(cipher.bankAccount.decPin, cipher.bankAccount.pin);
    draft.bankSwiftCode = plainCipherValue(cipher.bankAccount.decSwiftCode, cipher.bankAccount.swiftCode);
    draft.bankIban = plainCipherValue(cipher.bankAccount.decIban, cipher.bankAccount.iban);
    draft.bankContactPhone = plainCipherValue(cipher.bankAccount.decBankContactPhone, cipher.bankAccount.bankContactPhone);
  } else if (type === 7 && cipher.driversLicense) {
    draft.licenseFirstName = plainCipherValue(cipher.driversLicense.decFirstName, cipher.driversLicense.firstName);
    draft.licenseMiddleName = plainCipherValue(cipher.driversLicense.decMiddleName, cipher.driversLicense.middleName);
    draft.licenseLastName = plainCipherValue(cipher.driversLicense.decLastName, cipher.driversLicense.lastName);
    draft.licenseDateOfBirth = plainCipherValue(cipher.driversLicense.decDateOfBirth, cipher.driversLicense.dateOfBirth);
    draft.licenseNumber = plainCipherValue(cipher.driversLicense.decLicenseNumber, cipher.driversLicense.licenseNumber);
    draft.licenseIssuingCountry = plainCipherValue(cipher.driversLicense.decIssuingCountry, cipher.driversLicense.issuingCountry);
    draft.licenseIssuingState = plainCipherValue(cipher.driversLicense.decIssuingState, cipher.driversLicense.issuingState);
    draft.licenseIssueDate = plainCipherValue(cipher.driversLicense.decIssueDate, cipher.driversLicense.issueDate);
    draft.licenseExpirationDate = plainCipherValue(cipher.driversLicense.decExpirationDate, cipher.driversLicense.expirationDate);
    draft.licenseIssuingAuthority = plainCipherValue(cipher.driversLicense.decIssuingAuthority, cipher.driversLicense.issuingAuthority);
    draft.licenseClass = plainCipherValue(cipher.driversLicense.decLicenseClass, cipher.driversLicense.licenseClass);
  } else if (type === 8 && cipher.passport) {
    draft.passportSurname = plainCipherValue(cipher.passport.decSurname, cipher.passport.surname);
    draft.passportGivenName = plainCipherValue(cipher.passport.decGivenName, cipher.passport.givenName);
    draft.passportDateOfBirth = plainCipherValue(cipher.passport.decDateOfBirth, cipher.passport.dateOfBirth);
    draft.passportSex = plainCipherValue(cipher.passport.decSex, cipher.passport.sex);
    draft.passportBirthPlace = plainCipherValue(cipher.passport.decBirthPlace, cipher.passport.birthPlace);
    draft.passportNationality = plainCipherValue(cipher.passport.decNationality, cipher.passport.nationality);
    draft.passportIssuingCountry = plainCipherValue(cipher.passport.decIssuingCountry, cipher.passport.issuingCountry);
    draft.passportNumber = plainCipherValue(cipher.passport.decPassportNumber, cipher.passport.passportNumber);
    draft.passportType = plainCipherValue(cipher.passport.decPassportType, cipher.passport.passportType);
    draft.passportNationalIdentificationNumber = plainCipherValue(cipher.passport.decNationalIdentificationNumber, cipher.passport.nationalIdentificationNumber);
    draft.passportIssuingAuthority = plainCipherValue(cipher.passport.decIssuingAuthority, cipher.passport.issuingAuthority);
    draft.passportIssueDate = plainCipherValue(cipher.passport.decIssueDate, cipher.passport.issueDate);
    draft.passportExpirationDate = plainCipherValue(cipher.passport.decExpirationDate, cipher.passport.expirationDate);
  }

  return draft;
}

async function buildUpdatedPasswordHistory(
  cipher: Cipher | null,
  draft: VaultDraft,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<CipherPasswordHistoryEntry[] | null> {
  const existingHistory = Array.isArray(cipher?.passwordHistory) ? cipher.passwordHistory : [];
  const currentPassword = String(cipher?.login?.decPassword || '');
  const nextPassword = String(draft.loginPassword || '');
  const passwordChanged = currentPassword !== nextPassword;
  const history = await encryptPasswordHistory(existingHistory, enc, mac);

  if (!passwordChanged || !currentPassword.trim()) {
    return history;
  }

  const encryptedCurrentPassword = await encryptTextValue(currentPassword, enc, mac);
  if (!encryptedCurrentPassword) {
    return history;
  }

  const nextEntries: CipherPasswordHistoryEntry[] = [
    {
      password: encryptedCurrentPassword,
      lastUsedDate: new Date().toISOString(),
    },
    ...(history || []),
  ];
  return nextEntries.slice(0, 5);
}

async function encryptCustomFields(
  fields: VaultDraftField[],
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<{ type: number; name: string | null; value: string | null }>> {
  const out: Array<{ type: number; name: string | null; value: string | null }> = [];
  for (const field of fields || []) {
    const label = String(field.label || '').trim();
    if (!label) continue;
    out.push({
      type: parseFieldType(field.type),
      name: await encryptTextValue(label, enc, mac),
      value: await encryptTextValue(String(field.value || ''), enc, mac),
    });
  }
  return out;
}

async function encryptUris(
  uris: VaultDraft['loginUris'],
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  for (const entry of uris || []) {
    const trimmed = String(entry?.uri || '').trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    const preservedExtra =
      entry?.extra && typeof entry.extra === 'object'
        ? { ...entry.extra }
        : {};
    const canReuseChecksum = String(entry?.originalUri || '').trim() === trimmed;
    if (!canReuseChecksum) {
      delete preservedExtra.uriChecksum;
    }
    const preservedChecksum = typeof preservedExtra.uriChecksum === 'string' && looksLikeCipherString(preservedExtra.uriChecksum)
      ? preservedExtra.uriChecksum
      : null;
    const uriChecksum = preservedChecksum || await encryptTextValue(await sha256Base64(trimmed), enc, mac);
    out.push({
      ...preservedExtra,
      uri: await encryptTextValue(trimmed, enc, mac),
      uriChecksum,
      match: typeof entry?.match === 'number' && Number.isFinite(entry.match) ? entry.match : null,
    });
  }
  return out;
}

function toIsoDateOrNow(value: unknown): string {
  const raw = String(value ?? '').trim();
  if (!raw) return new Date().toISOString();
  const parsed = new Date(raw);
  if (!Number.isFinite(parsed.getTime())) return new Date().toISOString();
  return parsed.toISOString();
}

async function encryptMaybeFidoValue(
  value: unknown,
  enc: Uint8Array,
  mac: Uint8Array,
  fallback = ''
): Promise<string> {
  const normalized = String(value ?? '').trim() || fallback;
  if (looksLikeCipherString(normalized)) return normalized;
  return encryptBw(new TextEncoder().encode(normalized), enc, mac);
}

async function encryptMaybeNullableFidoValue(
  value: unknown,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<string | null> {
  const normalized = String(value ?? '').trim();
  if (!normalized) return null;
  if (looksLikeCipherString(normalized)) return normalized;
  return encryptBw(new TextEncoder().encode(normalized), enc, mac);
}

async function normalizeFido2Credentials(
  credentials: Array<Record<string, unknown>> | null | undefined,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<Array<Record<string, unknown>> | null> {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const out: Array<Record<string, unknown>> = [];
  for (const credential of credentials) {
    if (!credential || typeof credential !== 'object') continue;
    out.push({
      credentialId: await encryptMaybeFidoValue(credential.credentialId, enc, mac),
      keyType: await encryptMaybeFidoValue(credential.keyType, enc, mac, 'public-key'),
      keyAlgorithm: await encryptMaybeFidoValue(credential.keyAlgorithm, enc, mac, 'ECDSA'),
      keyCurve: await encryptMaybeFidoValue(credential.keyCurve, enc, mac, 'P-256'),
      keyValue: await encryptMaybeFidoValue(credential.keyValue, enc, mac),
      rpId: await encryptMaybeFidoValue(credential.rpId, enc, mac),
      rpName: await encryptMaybeNullableFidoValue(credential.rpName, enc, mac),
      userHandle: await encryptMaybeNullableFidoValue(credential.userHandle, enc, mac),
      userName: await encryptMaybeNullableFidoValue(credential.userName, enc, mac),
      userDisplayName: await encryptMaybeNullableFidoValue(credential.userDisplayName, enc, mac),
      counter: await encryptMaybeFidoValue(credential.counter, enc, mac, '0'),
      discoverable: await encryptMaybeFidoValue(credential.discoverable, enc, mac, 'false'),
      creationDate: toIsoDateOrNow(credential.creationDate),
    });
  }
  return out.length ? out : null;
}

async function getCipherKeys(
  cipher: Cipher | null,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<{ enc: Uint8Array; mac: Uint8Array; key: string | null }> {
  if (cipher?.key) {
    try {
      const raw = await decryptBw(cipher.key, userEnc, userMac);
      if (raw.length >= 64) return { enc: raw.slice(0, 32), mac: raw.slice(32, 64), key: cipher.key };
    } catch {
      // use user key
    }
  }
  return { enc: userEnc, mac: userMac, key: null };
}

async function repairCipherLoginUris(
  cipher: Cipher,
  enc: Uint8Array,
  mac: Uint8Array
): Promise<{ login: Cipher['login']; changed: boolean }> {
  if (!cipher.login || !Array.isArray(cipher.login.uris)) {
    return { login: cipher.login ?? null, changed: false };
  }

  let changed = false;
  const uris: Array<Record<string, unknown>> = [];

  for (const entry of cipher.login.uris) {
    if (!entry || typeof entry !== 'object') continue;
    const { decUri: _decUri, ...encryptedEntry } = entry as Record<string, unknown>;
    const rawUri = typeof entry.uri === 'string' ? entry.uri.trim() : '';
    if (!looksLikeCipherString(rawUri)) {
      uris.push({ ...encryptedEntry });
      continue;
    }

    let clearUri = '';
    let rawUriUsesCurrentKey = false;
    try {
      clearUri = (await decryptStr(rawUri, enc, mac)).trim();
      rawUriUsesCurrentKey = !!clearUri;
    } catch {
      const fallbackUri = String(entry.decUri || '').trim();
      if (fallbackUri && !looksLikeCipherString(fallbackUri)) {
        clearUri = fallbackUri;
      }
    }

    if (!clearUri) {
      uris.push({ ...encryptedEntry });
      continue;
    }

    const expectedChecksum = await sha256Base64(clearUri);
    let currentChecksumOk = false;
    const rawChecksum = typeof entry.uriChecksum === 'string' ? entry.uriChecksum.trim() : '';
    if (looksLikeCipherString(rawChecksum)) {
      try {
        currentChecksumOk = (await decryptStr(rawChecksum, enc, mac)) === expectedChecksum;
      } catch {
        currentChecksumOk = false;
      }
    }

    if (currentChecksumOk && rawUriUsesCurrentKey) {
      uris.push({ ...encryptedEntry });
      continue;
    }

    const repairedUri = rawUriUsesCurrentKey ? rawUri : await encryptTextValue(clearUri, enc, mac);
    const repairedChecksum = currentChecksumOk
      ? rawChecksum
      : await encryptTextValue(expectedChecksum, enc, mac);

    uris.push({
      ...encryptedEntry,
      uri: repairedUri || rawUri,
      uriChecksum: repairedChecksum,
      match: typeof entry.match === 'number' && Number.isFinite(entry.match) ? entry.match : null,
    });
    changed = true;
  }

  const {
    decUsername: _decUsername,
    decPassword: _decPassword,
    decTotp: _decTotp,
    ...encryptedLogin
  } = cipher.login as Record<string, unknown>;

  return {
    login: {
      ...encryptedLogin,
      uris: uris as CipherLoginData['uris'],
    } as CipherLoginData,
    changed,
  };
}

export async function repairCipherUriChecksums(
  authedFetch: AuthedFetch,
  session: SessionState,
  ciphers: Cipher[]
): Promise<number> {
  if (!session.symEncKey || !session.symMacKey || !Array.isArray(ciphers) || ciphers.length === 0) {
    return 0;
  }

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  let repaired = 0;

  for (const cipher of ciphers) {
    if (!cipher?.id || cipher.type !== 1 || !cipher.login || !Array.isArray(cipher.login.uris)) continue;
    let keys: { enc: Uint8Array; mac: Uint8Array; key: string | null } = {
      enc: userEnc,
      mac: userMac,
      key: null,
    };
    if (looksLikeCipherString(cipher.key)) {
      let itemKey: Uint8Array;
      try {
        itemKey = await decryptBw(String(cipher.key).trim(), userEnc, userMac);
      } catch {
        continue;
      }
      if (itemKey.length < 64) continue;
      keys = { enc: itemKey.slice(0, 32), mac: itemKey.slice(32, 64), key: String(cipher.key).trim() };
    }
    const repair = await repairCipherLoginUris(cipher, keys.enc, keys.mac);
    if (!repair.changed) continue;

    const payload: Record<string, unknown> = {
      type: cipher.type,
      folderId: cipher.folderId ?? null,
      favorite: !!cipher.favorite,
      reprompt: cipher.reprompt ?? 0,
      name: cipher.name ?? null,
      notes: cipher.notes ?? null,
      login: repair.login,
      fields: Array.isArray(cipher.fields)
        ? cipher.fields.map(({ decName: _decName, decValue: _decValue, ...field }) => field)
        : null,
      lastKnownRevisionDate: cipher.revisionDate ?? null,
      preserveRevisionDate: true,
    };
    if (keys.key) payload.key = keys.key;

    const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipher.id)}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', [NODEWARDEN_WEB_REPAIR_HEADER]: '1' },
      body: JSON.stringify(payload),
    });
    if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Repair URI checksum failed'));
    repaired += 1;
  }

  return repaired;
}

function getCipherKeyMismatchProbes(cipher: Cipher): string[] {
  const candidates = [
    cipher.name,
    cipher.notes,
    cipher.login?.username,
    cipher.login?.password,
    cipher.login?.totp,
    ...(cipher.login?.uris || []).map((uri) => uri.uri),
    cipher.card?.cardholderName,
    cipher.card?.number,
    cipher.identity?.title,
    cipher.identity?.firstName,
    cipher.sshKey?.privateKey,
    cipher.bankAccount?.bankName,
    cipher.bankAccount?.accountNumber,
    cipher.driversLicense?.licenseNumber,
    cipher.passport?.passportNumber,
    ...(cipher.fields || []).flatMap((field) => [field.name, field.value]),
  ];
  const probes: string[] = [];
  const seen = new Set<string>();
  for (const value of candidates) {
    const probe = String(value || '').trim();
    if (!looksLikeCipherString(probe) || seen.has(probe)) continue;
    seen.add(probe);
    probes.push(probe);
  }
  return probes;
}

function isResolvedEncryptedField(raw: unknown, decrypted: unknown): boolean {
  const encrypted = String(raw || '').trim();
  if (!looksLikeCipherString(encrypted)) return true;
  const plain = typeof decrypted === 'string' ? decrypted.trim() : '';
  return !!plain && !looksLikeCipherString(plain);
}

function hasUnresolvedEncryptedFields(cipher: Cipher): boolean {
  const fido2EncryptedFields = (cipher.login?.fido2Credentials || []).flatMap((credential) => [
    credential?.credentialId,
    credential?.keyType,
    credential?.keyAlgorithm,
    credential?.keyCurve,
    credential?.keyValue,
    credential?.rpId,
    credential?.rpName,
    credential?.userHandle,
    credential?.userName,
    credential?.userDisplayName,
    credential?.counter,
    credential?.discoverable,
  ]);

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
    [cipher.bankAccount?.bankName, cipher.bankAccount?.decBankName],
    [cipher.bankAccount?.nameOnAccount, cipher.bankAccount?.decNameOnAccount],
    [cipher.bankAccount?.accountType, cipher.bankAccount?.decAccountType],
    [cipher.bankAccount?.accountNumber, cipher.bankAccount?.decAccountNumber],
    [cipher.bankAccount?.routingNumber, cipher.bankAccount?.decRoutingNumber],
    [cipher.bankAccount?.branchNumber, cipher.bankAccount?.decBranchNumber],
    [cipher.bankAccount?.pin, cipher.bankAccount?.decPin],
    [cipher.bankAccount?.swiftCode, cipher.bankAccount?.decSwiftCode],
    [cipher.bankAccount?.iban, cipher.bankAccount?.decIban],
    [cipher.bankAccount?.bankContactPhone, cipher.bankAccount?.decBankContactPhone],
    [cipher.driversLicense?.firstName, cipher.driversLicense?.decFirstName],
    [cipher.driversLicense?.middleName, cipher.driversLicense?.decMiddleName],
    [cipher.driversLicense?.lastName, cipher.driversLicense?.decLastName],
    [cipher.driversLicense?.dateOfBirth, cipher.driversLicense?.decDateOfBirth],
    [cipher.driversLicense?.licenseNumber, cipher.driversLicense?.decLicenseNumber],
    [cipher.driversLicense?.issuingCountry, cipher.driversLicense?.decIssuingCountry],
    [cipher.driversLicense?.issuingState, cipher.driversLicense?.decIssuingState],
    [cipher.driversLicense?.issueDate, cipher.driversLicense?.decIssueDate],
    [cipher.driversLicense?.expirationDate, cipher.driversLicense?.decExpirationDate],
    [cipher.driversLicense?.issuingAuthority, cipher.driversLicense?.decIssuingAuthority],
    [cipher.driversLicense?.licenseClass, cipher.driversLicense?.decLicenseClass],
    [cipher.passport?.surname, cipher.passport?.decSurname],
    [cipher.passport?.givenName, cipher.passport?.decGivenName],
    [cipher.passport?.dateOfBirth, cipher.passport?.decDateOfBirth],
    [cipher.passport?.sex, cipher.passport?.decSex],
    [cipher.passport?.birthPlace, cipher.passport?.decBirthPlace],
    [cipher.passport?.nationality, cipher.passport?.decNationality],
    [cipher.passport?.issuingCountry, cipher.passport?.decIssuingCountry],
    [cipher.passport?.passportNumber, cipher.passport?.decPassportNumber],
    [cipher.passport?.passportType, cipher.passport?.decPassportType],
    [cipher.passport?.nationalIdentificationNumber, cipher.passport?.decNationalIdentificationNumber],
    [cipher.passport?.issuingAuthority, cipher.passport?.decIssuingAuthority],
    [cipher.passport?.issueDate, cipher.passport?.decIssueDate],
    [cipher.passport?.expirationDate, cipher.passport?.decExpirationDate],
    ...(cipher.fields || []).flatMap((field) => [
      [field.name, field.decName] as [unknown, unknown],
      [field.value, field.decValue] as [unknown, unknown],
    ]),
    ...(cipher.passwordHistory || []).map((entry) => [entry.password, entry.decPassword] as [unknown, unknown]),
    ...fido2EncryptedFields.map((value) => [value, undefined] as [unknown, unknown]),
  ];

  return checks.some(([raw, decrypted]) => !isResolvedEncryptedField(raw, decrypted));
}

async function hasItemKeyFieldMismatch(
  cipher: Cipher,
  userEnc: Uint8Array,
  userMac: Uint8Array
): Promise<boolean> {
  if (!looksLikeCipherString(cipher.key)) return false;
  const probes = getCipherKeyMismatchProbes(cipher);
  if (probes.length === 0) return false;

  let itemKey: Uint8Array;
  try {
    itemKey = await decryptBw(String(cipher.key).trim(), userEnc, userMac);
  } catch {
    return false;
  }
  if (itemKey.length < 64) return false;

  const itemEnc = itemKey.slice(0, 32);
  const itemMac = itemKey.slice(32, 64);
  for (const probe of probes) {
    try {
      await decryptStr(probe, itemEnc, itemMac);
      continue;
    } catch {
      // Try the legacy user-key field path below.
    }

    try {
      await decryptStr(probe, userEnc, userMac);
      return true;
    } catch {
      // Keep scanning in case another field reveals a repairable mismatch.
    }
  }

  return false;
}

export async function repairCipherKeyMismatches(
  authedFetch: AuthedFetch,
  session: SessionState,
  ciphers: Cipher[]
): Promise<number> {
  if (!session.symEncKey || !session.symMacKey || !Array.isArray(ciphers) || ciphers.length === 0) {
    return 0;
  }

  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  let repaired = 0;

  for (const cipher of ciphers) {
    if (!cipher?.id || !looksLikeCipherString(cipher.key)) continue;
    if (!(await hasItemKeyFieldMismatch(cipher, userEnc, userMac))) continue;
    if (hasUnresolvedEncryptedFields(cipher)) continue;
    await updateCipher(
      authedFetch,
      session,
      cipher,
      draftFromDecryptedCipher(cipher),
      { preserveRevisionDate: true },
      { webRepair: true }
    );
    repaired += 1;
  }

  return repaired;
}

async function buildCipherPayload(
  session: SessionState,
  draft: VaultDraft,
  cipher: Cipher | null
): Promise<Record<string, unknown>> {
  if (!session.symEncKey || !session.symMacKey) throw new Error('Vault key unavailable');
  const userEnc = base64ToBytes(session.symEncKey);
  const userMac = base64ToBytes(session.symMacKey);
  const keys = await getCipherKeys(cipher, userEnc, userMac);
  const type = Number(draft.type || cipher?.type || 1);
  const now = new Date().toISOString();

  const payload: Record<string, unknown> = {
    type,
    favorite: !!draft.favorite,
    folderId: asNullable(draft.folderId),
    reprompt: draft.reprompt ? 1 : 0,
    name: await encryptTextValue(draft.name, keys.enc, keys.mac),
    notes: await encryptTextValue(draft.notes, keys.enc, keys.mac),
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    bankAccount: null,
    driversLicense: null,
    passport: null,
    fields: await encryptCustomFields(draft.customFields || [], keys.enc, keys.mac),
    passwordHistory: await encryptPasswordHistory(cipher?.passwordHistory, keys.enc, keys.mac),
  };

  if (cipher?.id) {
    payload.id = cipher.id;
    payload.key = keys.key;
  }

  if (type === 1) {
    const passwordChanged = String(cipher?.login?.decPassword || '') !== String(draft.loginPassword || '');
    const existingFido2 =
      cipher?.login && Array.isArray((cipher.login as any).fido2Credentials)
        ? (cipher.login as any).fido2Credentials
        : draft.loginFido2Credentials;
    const existingLogin =
      cipher?.login && typeof cipher.login === 'object'
        ? { ...(cipher.login as Record<string, unknown>) }
        : {};
    delete existingLogin.decUsername;
    delete existingLogin.decPassword;
    delete existingLogin.decTotp;
    payload.login = {
      ...existingLogin,
      username: await encryptTextValue(draft.loginUsername, keys.enc, keys.mac),
      password: await encryptTextValue(draft.loginPassword, keys.enc, keys.mac),
      totp: await encryptTextValue(draft.loginTotp, keys.enc, keys.mac),
      passwordRevisionDate: passwordChanged ? now : existingLogin.passwordRevisionDate ?? null,
      fido2Credentials: await normalizeFido2Credentials(existingFido2, keys.enc, keys.mac),
      uris: await encryptUris(draft.loginUris || [], keys.enc, keys.mac),
    };
    payload.passwordHistory = await buildUpdatedPasswordHistory(cipher, draft, keys.enc, keys.mac);
  } else if (type === 3) {
    payload.card = {
      cardholderName: await encryptTextValue(draft.cardholderName, keys.enc, keys.mac),
      number: await encryptTextValue(draft.cardNumber, keys.enc, keys.mac),
      brand: await encryptTextValue(draft.cardBrand, keys.enc, keys.mac),
      expMonth: await encryptTextValue(draft.cardExpMonth, keys.enc, keys.mac),
      expYear: await encryptTextValue(draft.cardExpYear, keys.enc, keys.mac),
      code: await encryptTextValue(draft.cardCode, keys.enc, keys.mac),
    };
  } else if (type === 4) {
    payload.identity = {
      title: await encryptTextValue(draft.identTitle, keys.enc, keys.mac),
      firstName: await encryptTextValue(draft.identFirstName, keys.enc, keys.mac),
      middleName: await encryptTextValue(draft.identMiddleName, keys.enc, keys.mac),
      lastName: await encryptTextValue(draft.identLastName, keys.enc, keys.mac),
      username: await encryptTextValue(draft.identUsername, keys.enc, keys.mac),
      company: await encryptTextValue(draft.identCompany, keys.enc, keys.mac),
      ssn: await encryptTextValue(draft.identSsn, keys.enc, keys.mac),
      passportNumber: await encryptTextValue(draft.identPassportNumber, keys.enc, keys.mac),
      licenseNumber: await encryptTextValue(draft.identLicenseNumber, keys.enc, keys.mac),
      email: await encryptTextValue(draft.identEmail, keys.enc, keys.mac),
      phone: await encryptTextValue(draft.identPhone, keys.enc, keys.mac),
      address1: await encryptTextValue(draft.identAddress1, keys.enc, keys.mac),
      address2: await encryptTextValue(draft.identAddress2, keys.enc, keys.mac),
      address3: await encryptTextValue(draft.identAddress3, keys.enc, keys.mac),
      city: await encryptTextValue(draft.identCity, keys.enc, keys.mac),
      state: await encryptTextValue(draft.identState, keys.enc, keys.mac),
      postalCode: await encryptTextValue(draft.identPostalCode, keys.enc, keys.mac),
      country: await encryptTextValue(draft.identCountry, keys.enc, keys.mac),
    };
  } else if (type === 5) {
    const encryptedFingerprint = await encryptTextValue(draft.sshFingerprint, keys.enc, keys.mac);
    payload.sshKey = {
      ...stripDecodedObjectFields(cipher?.sshKey),
      privateKey: await encryptTextValue(draft.sshPrivateKey, keys.enc, keys.mac),
      publicKey: await encryptTextValue(draft.sshPublicKey, keys.enc, keys.mac),
      keyFingerprint: encryptedFingerprint,
      fingerprint: encryptedFingerprint,
    };
  } else if (type === 6) {
    payload.bankAccount = await encryptObjectFields(
      cipher?.bankAccount,
      [
        ['bankName', 'bankName'],
        ['nameOnAccount', 'bankNameOnAccount'],
        ['accountType', 'bankAccountType'],
        ['accountNumber', 'bankAccountNumber'],
        ['routingNumber', 'bankRoutingNumber'],
        ['branchNumber', 'bankBranchNumber'],
        ['pin', 'bankPin'],
        ['swiftCode', 'bankSwiftCode'],
        ['iban', 'bankIban'],
        ['bankContactPhone', 'bankContactPhone'],
      ],
      draft,
      keys.enc,
      keys.mac
    );
  } else if (type === 7) {
    payload.driversLicense = await encryptObjectFields(
      cipher?.driversLicense,
      [
        ['firstName', 'licenseFirstName'],
        ['middleName', 'licenseMiddleName'],
        ['lastName', 'licenseLastName'],
        ['dateOfBirth', 'licenseDateOfBirth'],
        ['licenseNumber', 'licenseNumber'],
        ['issuingCountry', 'licenseIssuingCountry'],
        ['issuingState', 'licenseIssuingState'],
        ['issueDate', 'licenseIssueDate'],
        ['expirationDate', 'licenseExpirationDate'],
        ['issuingAuthority', 'licenseIssuingAuthority'],
        ['licenseClass', 'licenseClass'],
      ],
      draft,
      keys.enc,
      keys.mac
    );
  } else if (type === 8) {
    payload.passport = await encryptObjectFields(
      cipher?.passport,
      [
        ['surname', 'passportSurname'],
        ['givenName', 'passportGivenName'],
        ['dateOfBirth', 'passportDateOfBirth'],
        ['sex', 'passportSex'],
        ['birthPlace', 'passportBirthPlace'],
        ['nationality', 'passportNationality'],
        ['issuingCountry', 'passportIssuingCountry'],
        ['passportNumber', 'passportNumber'],
        ['passportType', 'passportType'],
        ['nationalIdentificationNumber', 'passportNationalIdentificationNumber'],
        ['issuingAuthority', 'passportIssuingAuthority'],
        ['issueDate', 'passportIssueDate'],
        ['expirationDate', 'passportExpirationDate'],
      ],
      draft,
      keys.enc,
      keys.mac
    );
  } else if (type === 2) {
    payload.secureNote = { type: 0 };
  }

  return payload;
}

export async function buildCipherImportPayload(session: SessionState, draft: VaultDraft): Promise<Record<string, unknown>> {
  return buildCipherPayload(session, draft, null);
}

export async function createCipher(
  authedFetch: AuthedFetch,
  session: SessionState,
  draft: VaultDraft
): Promise<Cipher> {
  const payload = await buildCipherPayload(session, draft, null);

  const resp = await authedFetch('/api/ciphers', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Create item failed');
  const body = await parseJson<Cipher>(resp);
  if (!body?.id) throw new Error('Create item failed');
  return body;
}

export async function updateCipher(
  authedFetch: AuthedFetch,
  session: SessionState,
  cipher: Cipher,
  draft: VaultDraft,
  extraPayload?: Record<string, unknown>,
  options?: { webRepair?: boolean }
): Promise<Cipher> {
  const payload = await buildCipherPayload(session, draft, cipher);
  if (extraPayload) {
    Object.assign(payload, extraPayload);
  }

  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipher.id)}`, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      ...(options?.webRepair ? { [NODEWARDEN_WEB_REPAIR_HEADER]: '1' } : {}),
    },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error('Update item failed');
  return (await parseJson<Cipher>(resp))!;
}

export async function deleteCipher(authedFetch: AuthedFetch, cipherId: string): Promise<Cipher> {
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(cipherId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Delete item failed');
  return (await parseJson<Cipher>(resp))!;
}

export async function permanentDeleteCipher(authedFetch: AuthedFetch, cipherId: string): Promise<void> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/delete`, { method: 'DELETE' });
  if (!resp.ok) throw new Error('Permanent delete item failed');
}

export async function archiveCipher(authedFetch: AuthedFetch, cipherId: string): Promise<Cipher> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/archive`, { method: 'PUT' });
  if (!resp.ok) throw new Error('Archive item failed');
  return (await parseJson<Cipher>(resp))!;
}

export async function unarchiveCipher(authedFetch: AuthedFetch, cipherId: string): Promise<Cipher> {
  const id = String(cipherId || '').trim();
  if (!id) throw new Error('Cipher id is required');
  const resp = await authedFetch(`/api/ciphers/${encodeURIComponent(id)}/unarchive`, { method: 'PUT' });
  if (!resp.ok) throw new Error('Unarchive item failed');
  return (await parseJson<Cipher>(resp))!;
}

export async function bulkDeleteCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk delete failed');
  }
}

export async function bulkArchiveCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/archive', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk archive failed');
  }
}

export async function bulkPermanentDeleteCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/delete-permanent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk permanent delete failed');
  }
}

export async function bulkRestoreCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk restore failed');
  }
}

export async function bulkUnarchiveCiphers(authedFetch: AuthedFetch, ids: string[]): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/unarchive', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk }),
    });
    if (!resp.ok) throw new Error('Bulk unarchive failed');
  }
}

export async function bulkMoveCiphers(
  authedFetch: AuthedFetch,
  ids: string[],
  folderId: string | null
): Promise<void> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  for (const chunk of chunkArray(uniqueIds, BULK_API_CHUNK_SIZE)) {
    const resp = await authedFetch('/api/ciphers/move', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ids: chunk, folderId }),
    });
    if (!resp.ok) throw new Error('Bulk move failed');
  }
}
