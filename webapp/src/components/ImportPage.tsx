import { useState } from 'preact/hooks';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { createPortal } from 'preact/compat';
import { strFromU8, unzipSync, type UnzipFileInfo } from 'fflate';
import { BlobReader, Uint8ArrayWriter, ZipReader, configure as configureZipJs } from '@zip.js/zip.js';
import { Download, FileUp } from 'lucide-preact';
import ConfirmDialog, { useDialogLifecycle } from '@/components/ConfirmDialog';
import type { CiphersImportPayload } from '@/lib/api/vault';
import {
  type EncryptedJsonMode,
  EXPORT_FORMATS,
  type ExportFormatId,
  type ExportRequest,
} from '@/lib/export-formats';
import {
  parseImportPayloadBySource,
} from '@/lib/import-formats';
import { getFileAcceptBySource, IMPORT_SOURCES, type ImportSourceId } from '@/lib/import-format-sources';
import {
  type BitwardenJsonInput,
  normalizeBitwardenEncryptedAccountImport,
  normalizeBitwardenImport,
} from '@/lib/import-formats-bitwarden';
import { base64ToBytes, decryptStr, hkdfExpand, pbkdf2 } from '@/lib/crypto';
import { t } from '@/lib/i18n';
import type { Folder } from '@/lib/types';

configureZipJs({ useWebWorkers: false });

export interface ImportAttachmentFile {
  sourceCipherId: string | null;
  sourceCipherIndex: number | null;
  fileName: string;
  bytes: Uint8Array;
}

interface ImportPageProps {
  onImport: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  onImportEncryptedRaw: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  accountKeys?: { encB64: string; macB64: string } | null;
  onNotify: (type: 'success' | 'error', text: string) => void;
  folders: Folder[];
  onExport: (request: ExportRequest) => Promise<void>;
}

export interface ImportResultSummary {
  totalItems: number;
  folderCount: number;
  typeCounts: Array<{ label: string; count: number }>;
  attachmentCount: number;
  importedAttachmentCount: number;
  failedAttachments: Array<{ fileName: string; reason: string }>;
}

interface BitwardenPasswordProtectedInput extends BitwardenJsonInput {
  encrypted: true;
  passwordProtected: true;
  salt?: string;
  kdfIterations?: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  kdfType?: number;
  data?: string;
}

const COMMON_IMPORT_SOURCE_IDS: ImportSourceId[] = [
  'bitwarden_json',
  'bitwarden_csv',
  'bitwarden_zip',
  'nodewarden_json',
  'onepassword_1pux',
  'onepassword_1pif',
  'onepassword_mac_csv',
  'onepassword_win_csv',
  'protonpass_json',
  'chrome',
  'edge',
  'brave',
  'opera',
  'vivaldi',
  'firefox_csv',
  'safari_csv',
  'lastpass',
  'dashlane_csv',
  'dashlane_json',
  'keepass_csv',
  'keepass_xml',
  'keepassx_csv',
];

const MAX_IMPORT_ZIP_BYTES = 256 * 1024 * 1024;
const MAX_IMPORT_ZIP_ENTRY_COUNT = 10_000;
const MAX_IMPORT_TEXT_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_IMPORT_ATTACHMENT_BYTES = 100 * 1024 * 1024;
const MAX_IMPORT_ATTACHMENT_TOTAL_BYTES = 512 * 1024 * 1024;

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function isPasswordProtectedExport(value: unknown): value is BitwardenPasswordProtectedInput {
  return isRecord(value) && value.encrypted === true && value.passwordProtected === true;
}

async function derivePasswordProtectedFileKey(
  parsed: BitwardenPasswordProtectedInput,
  password: string
): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  const salt = String(parsed.salt || '').trim();
  const iterations = Number(parsed.kdfIterations || 0);
  const kdfType = Number(parsed.kdfType);
  if (!salt || !Number.isFinite(iterations) || iterations <= 0) {
    throw new Error(t('txt_import_invalid_password_protected_file'));
  }

  let keyMaterial: Uint8Array;
  if (kdfType === 0) {
    keyMaterial = await pbkdf2(password, salt, iterations, 32);
  } else if (kdfType === 1) {
    const memoryMiB = Number(parsed.kdfMemory || 0);
    const parallelism = Number(parsed.kdfParallelism || 0);
    if (!Number.isFinite(memoryMiB) || memoryMiB <= 0 || !Number.isFinite(parallelism) || parallelism <= 0) {
      throw new Error(t('txt_invalid_argon2id_params'));
    }
    const memoryKiB = Math.floor(memoryMiB * 1024);
    const maxmem = memoryKiB * 1024 + 1024 * 1024;
    keyMaterial = await argon2idAsync(new TextEncoder().encode(password), new TextEncoder().encode(salt), {
      t: Math.floor(iterations),
      m: memoryKiB,
      p: Math.floor(parallelism),
      dkLen: 32,
      maxmem,
      asyncTick: 10,
    });
  } else {
    throw new Error(t('txt_unsupported_kdf_type', { type: String(kdfType) }));
  }

  const enc = await hkdfExpand(keyMaterial, 'enc', 32);
  const mac = await hkdfExpand(keyMaterial, 'mac', 32);
  return { enc, mac };
}

async function decryptPasswordProtectedExport(parsed: BitwardenPasswordProtectedInput, password: string): Promise<unknown> {
  if (!parsed.encKeyValidation_DO_NOT_EDIT || !parsed.data) {
    throw new Error(t('txt_import_invalid_password_protected_file'));
  }
  const pass = String(password || '').trim();
  if (!pass) {
    throw new Error(t('txt_import_file_password_required'));
  }

  const key = await derivePasswordProtectedFileKey(parsed, pass);
  try {
    await decryptStr(parsed.encKeyValidation_DO_NOT_EDIT, key.enc, key.mac);
  } catch {
    throw new Error(t('txt_invalid_file_password'));
  }

  const plainJson = await decryptStr(parsed.data, key.enc, key.mac);
  try {
    return JSON.parse(plainJson);
  } catch {
    throw new Error(t('txt_import_decrypt_failed'));
  }
}

function isZipPayload(bytes: Uint8Array): boolean {
  return bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04;
}

function formatMiB(bytes: number): string {
  return String(Math.floor(bytes / (1024 * 1024)));
}

function zipEntryName(rawName: unknown): string {
  return String(rawName || '').trim().replace(/\\/g, '/');
}

function assertSafeZipEntryName(name: string): void {
  if (!name || name.includes('\0') || name.startsWith('/') || name.includes('//')) {
    throw new Error(t('txt_import_zip_unsafe_file_name'));
  }
  const parts = name.split('/');
  if (parts.some((part) => part === '.' || part === '..')) {
    throw new Error(t('txt_import_zip_unsafe_file_name'));
  }
}

function assertImportZipSize(bytes: number): void {
  if (bytes > MAX_IMPORT_ZIP_BYTES) {
    throw new Error(t('txt_import_zip_too_large', { size: formatMiB(MAX_IMPORT_ZIP_BYTES) }));
  }
}

function assertImportTextFileSize(bytes: number): void {
  if (bytes > MAX_IMPORT_TEXT_ENTRY_BYTES) {
    throw new Error(t('txt_import_file_too_large', { size: formatMiB(MAX_IMPORT_TEXT_ENTRY_BYTES) }));
  }
}

function assertImportEntrySize(size: number, maxBytes: number): void {
  if (size > maxBytes) {
    throw new Error(t('txt_import_zip_entry_too_large', { size: formatMiB(maxBytes) }));
  }
}

function isImportTextZipCandidate(source: ImportSourceId, name: string): boolean {
  const lower = name.toLowerCase();
  if (source === 'onepassword_1pux') {
    return lower.endsWith('/export.data') || lower === 'export.data' || lower.endsWith('/export.json') || lower === 'export.json' || lower.endsWith('.json');
  }
  return lower.endsWith('/protonpass.json') || lower === 'protonpass.json' || lower.endsWith('/export.json') || lower === 'export.json' || lower.endsWith('.json');
}

function createImportTextZipFilter(source: ImportSourceId): (file: UnzipFileInfo) => boolean {
  let entryCount = 0;
  let totalTextBytes = 0;
  return (entry: UnzipFileInfo): boolean => {
    entryCount += 1;
    if (entryCount > MAX_IMPORT_ZIP_ENTRY_COUNT) {
      throw new Error(t('txt_import_zip_too_many_files'));
    }
    const name = zipEntryName(entry.name);
    assertSafeZipEntryName(name);
    if (!isImportTextZipCandidate(source, name)) return false;

    const originalSize = Number(entry.originalSize);
    if (!Number.isFinite(originalSize) || originalSize < 0) {
      throw new Error(t('txt_import_zip_entry_too_large', { size: formatMiB(MAX_IMPORT_TEXT_ENTRY_BYTES) }));
    }
    assertImportEntrySize(originalSize, MAX_IMPORT_TEXT_ENTRY_BYTES);
    totalTextBytes += originalSize;
    if (totalTextBytes > MAX_IMPORT_TEXT_ENTRY_BYTES) {
      throw new Error(t('txt_import_zip_expands_too_large', { size: formatMiB(MAX_IMPORT_TEXT_ENTRY_BYTES) }));
    }
    return true;
  };
}

function readZipText(bytes: Uint8Array, source: ImportSourceId): string {
  assertImportZipSize(bytes.byteLength);
  const unzippedRaw = unzipSync(bytes, { filter: createImportTextZipFilter(source) });
  const unzipped: Record<string, Uint8Array> = {};
  for (const [rawName, entryBytes] of Object.entries(unzippedRaw)) {
    const name = zipEntryName(rawName);
    assertSafeZipEntryName(name);
    assertImportEntrySize(entryBytes.byteLength, MAX_IMPORT_TEXT_ENTRY_BYTES);
    unzipped[name] = entryBytes;
  }
  const fileNames = Object.keys(unzipped);
  if (!fileNames.length) throw new Error(t('txt_import_empty_zip_archive'));

  const preferred = source === 'onepassword_1pux' ? ['export.data', 'export.json'] : ['protonpass.json', 'export.json'];
  for (const p of preferred) {
    const hit = fileNames.find((n) => n.toLowerCase().endsWith(p.toLowerCase()));
    if (hit) return strFromU8(unzipped[hit]);
  }

  const firstJson = fileNames.find((n) => n.toLowerCase().endsWith('.json') || n.toLowerCase().endsWith('.data'));
  if (firstJson) return strFromU8(unzipped[firstJson]);
  throw new Error(t('txt_import_no_json_found_in_zip'));
}

async function readImportText(file: File, source: ImportSourceId): Promise<string> {
  if (source !== 'onepassword_1pux' && source !== 'protonpass_json') {
    assertImportTextFileSize(file.size);
    return file.text();
  }
  assertImportZipSize(file.size);
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (isZipPayload(bytes)) return readZipText(bytes, source);
  assertImportTextFileSize(bytes.byteLength);
  return new TextDecoder().decode(bytes);
}

interface PendingPasswordImportContext {
  parsed: BitwardenPasswordProtectedInput;
  source: 'bitwarden_json' | 'nodewarden_json' | 'bitwarden_zip';
  attachments: ImportAttachmentFile[];
}

class ZipNeedsPasswordError extends Error {}
class ZipInvalidPasswordError extends Error {}

function looksLikeZipPasswordError(error: unknown): boolean {
  const message = error instanceof Error ? String(error.message || '').toLowerCase() : '';
  if (!message) return false;
  return message.includes('password') || message.includes('encrypted');
}

function bitwardenZipAttachmentMatch(name: string): RegExpMatchArray | null {
  return name.match(/^attachments\/([^/]+)\/(.+)$/i);
}

function zipJsEntrySize(entry: unknown): number | null {
  const size = Number((entry as { uncompressedSize?: unknown })?.uncompressedSize);
  return Number.isFinite(size) && size >= 0 ? size : null;
}

function validateBitwardenZipEntries(entries: Awaited<ReturnType<ZipReader<unknown>['getEntries']>>): void {
  if (entries.length > MAX_IMPORT_ZIP_ENTRY_COUNT) {
    throw new Error(t('txt_import_zip_too_many_files'));
  }

  let totalAttachmentBytes = 0;
  for (const entry of entries) {
    if (entry.directory) continue;
    const name = zipEntryName(entry.filename);
    assertSafeZipEntryName(name);
    const lower = name.toLowerCase();
    const size = zipJsEntrySize(entry);
    if (lower === 'data.json' && size != null) {
      assertImportEntrySize(size, MAX_IMPORT_TEXT_ENTRY_BYTES);
    } else if (bitwardenZipAttachmentMatch(name) && size != null) {
      assertImportEntrySize(size, MAX_IMPORT_ATTACHMENT_BYTES);
      totalAttachmentBytes += size;
      if (totalAttachmentBytes > MAX_IMPORT_ATTACHMENT_TOTAL_BYTES) {
        throw new Error(t('txt_import_zip_expands_too_large', { size: formatMiB(MAX_IMPORT_ATTACHMENT_TOTAL_BYTES) }));
      }
    }
  }
}

async function readBitwardenZipPayload(
  file: File,
  passwordRaw: string
): Promise<{ jsonText: string; attachments: ImportAttachmentFile[] }> {
  const password = String(passwordRaw || '').trim();
  assertImportZipSize(file.size);
  const reader = new ZipReader(new BlobReader(file), { useWebWorkers: false });
  try {
    const entries = await reader.getEntries();
    if (!entries.length) throw new Error(t('txt_import_empty_zip_archive'));
    validateBitwardenZipEntries(entries);

    let jsonText = '';
    let totalAttachmentBytes = 0;
    const attachments: ImportAttachmentFile[] = [];
    const options = password ? { password } : undefined;

    for (const entry of entries) {
      if (entry.directory) continue;
      const name = zipEntryName(entry.filename);
      if (!name) continue;
      assertSafeZipEntryName(name);

      const bytes = await entry.getData(new Uint8ArrayWriter(), options);
      const lower = name.toLowerCase();
      if (lower === 'data.json') {
        assertImportEntrySize(bytes.byteLength, MAX_IMPORT_TEXT_ENTRY_BYTES);
        jsonText = new TextDecoder().decode(bytes);
        continue;
      }

      const attachmentMatch = bitwardenZipAttachmentMatch(name);
      if (!attachmentMatch) continue;
      assertImportEntrySize(bytes.byteLength, MAX_IMPORT_ATTACHMENT_BYTES);
      totalAttachmentBytes += bytes.byteLength;
      if (totalAttachmentBytes > MAX_IMPORT_ATTACHMENT_TOTAL_BYTES) {
        throw new Error(t('txt_import_zip_expands_too_large', { size: formatMiB(MAX_IMPORT_ATTACHMENT_TOTAL_BYTES) }));
      }
      const sourceCipherId = String(attachmentMatch[1] || '').trim() || null;
      const fileName = String(attachmentMatch[2] || '').trim() || 'attachment.bin';
      attachments.push({
        sourceCipherId,
        sourceCipherIndex: null,
        fileName,
        bytes,
      });
    }

    if (!jsonText) throw new Error(t('txt_import_data_json_not_found'));
    return { jsonText, attachments };
  } catch (error) {
    if (looksLikeZipPasswordError(error)) {
      if (!password) throw new ZipNeedsPasswordError(t('txt_import_zip_password_required'));
      throw new ZipInvalidPasswordError(t('txt_import_invalid_zip_password'));
    }
    if (!password && error instanceof Error && /invalid|corrupt|unsupported/.test(error.message.toLowerCase())) {
      throw error;
    }
    throw error;
  } finally {
    await reader.close();
  }
}

function parseNodeWardenAttachmentArray(raw: unknown): ImportAttachmentFile[] {
  if (!Array.isArray(raw)) return [];
  const out: ImportAttachmentFile[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const row = entry as Record<string, unknown>;
    const fileName = String(row.fileName || '').trim() || 'attachment.bin';
    const base64 = String(row.data || '').trim();
    if (!base64) continue;
    try {
      const bytes = base64ToBytes(base64);
      const sourceCipherId = String(row.cipherId || '').trim() || null;
      const indexRaw = Number(row.cipherIndex);
      out.push({
        sourceCipherId,
        sourceCipherIndex: Number.isFinite(indexRaw) ? indexRaw : null,
        fileName,
        bytes,
      });
    } catch {
      // skip malformed attachment row
    }
  }
  return out;
}

export default function ImportPage({ onImport, onImportEncryptedRaw, accountKeys, onNotify, folders, onExport }: ImportPageProps) {
  const [source, setSource] = useState<ImportSourceId>('bitwarden_json');
  const [file, setFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isPasswordSubmitting, setIsPasswordSubmitting] = useState(false);
  const [passwordDialogOpen, setPasswordDialogOpen] = useState(false);
  const [importPassword, setImportPassword] = useState('');
  const [pendingPasswordImport, setPendingPasswordImport] = useState<PendingPasswordImportContext | null>(null);
  const [zipPasswordDialogOpen, setZipPasswordDialogOpen] = useState(false);
  const [zipImportPassword, setZipImportPassword] = useState('');
  const [pendingZipFile, setPendingZipFile] = useState<File | null>(null);
  const [isZipPasswordSubmitting, setIsZipPasswordSubmitting] = useState(false);
  const [folderMode, setFolderMode] = useState<'original' | 'none' | 'target'>('original');
  const [targetFolderId, setTargetFolderId] = useState('');
  const [exportFormat, setExportFormat] = useState<ExportFormatId>('bitwarden_json');
  const [encryptedJsonMode, setEncryptedJsonMode] = useState<EncryptedJsonMode>('account');
  const [exportPassword, setExportPassword] = useState('');
  const [zipPassword, setZipPassword] = useState('');
  const [isExporting, setIsExporting] = useState(false);
  const [exportAuthDialogOpen, setExportAuthDialogOpen] = useState(false);
  const [exportAuthPassword, setExportAuthPassword] = useState('');
  const [importSummary, setImportSummary] = useState<ImportResultSummary | null>(null);

  useDialogLifecycle(!!importSummary, importSummary ? () => setImportSummary(null) : null);
  const commonSourceSet = new Set<ImportSourceId>(COMMON_IMPORT_SOURCE_IDS);
  const commonSources = IMPORT_SOURCES.filter((item) => commonSourceSet.has(item.id as ImportSourceId));
  const otherSources = IMPORT_SOURCES.filter((item) => !commonSourceSet.has(item.id as ImportSourceId));

  async function runBitwardenJsonImport(parsed: unknown, attachments: ImportAttachmentFile[] = []): Promise<ImportResultSummary> {
    if (isRecord(parsed) && parsed.encrypted === true) {
      const accountEncrypted = parsed as BitwardenJsonInput;
      if (!accountKeys?.encB64 || !accountKeys?.macB64) {
        throw new Error(t('txt_vault_key_unavailable'));
      }
      const validation = String(accountEncrypted.encKeyValidation_DO_NOT_EDIT || '').trim();
      if (!validation) throw new Error(t('txt_invalid_encrypted_export'));
      const accountEncKey = base64ToBytes(accountKeys.encB64);
      const accountMacKey = base64ToBytes(accountKeys.macB64);
      try {
        await decryptStr(validation, accountEncKey, accountMacKey);
      } catch {
        throw new Error(t('txt_export_belongs_to_another_account'));
      }
      return onImportEncryptedRaw(
        normalizeBitwardenEncryptedAccountImport(accountEncrypted),
        {
          folderMode,
          targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
        },
        attachments
      );
    }
    return onImport(
      normalizeBitwardenImport(parsed),
      {
        folderMode,
        targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
      },
      attachments
    );
  }

  async function extractNodeWardenAttachments(parsed: unknown): Promise<ImportAttachmentFile[]> {
    if (!isRecord(parsed)) return [];
    const direct = parseNodeWardenAttachmentArray(parsed.nodewardenAttachments);
    if (direct.length) return direct;

    const encryptedPayload = String(parsed.nodewardenAttachmentsEnc || '').trim();
    if (!encryptedPayload) return [];
    if (!accountKeys?.encB64 || !accountKeys?.macB64) {
      throw new Error(t('txt_vault_key_unavailable'));
    }
    const accountEnc = base64ToBytes(accountKeys.encB64);
    const accountMac = base64ToBytes(accountKeys.macB64);
    const plain = await decryptStr(encryptedPayload, accountEnc, accountMac);
    const unpacked = JSON.parse(plain) as Record<string, unknown>;
    return parseNodeWardenAttachmentArray(unpacked.nodewardenAttachments);
  }

  async function runNodeWardenJsonImport(parsed: unknown, extraAttachments: ImportAttachmentFile[] = []): Promise<ImportResultSummary> {
    const bundled = await extractNodeWardenAttachments(parsed);
    return runBitwardenJsonImport(parsed, [...bundled, ...extraAttachments]);
  }

  async function processPasswordProtectedImport(ctx: PendingPasswordImportContext): Promise<ImportResultSummary> {
    const parsed = await decryptPasswordProtectedExport(ctx.parsed, importPassword);
    if (ctx.source === 'nodewarden_json') {
      return runNodeWardenJsonImport(parsed, ctx.attachments);
    }
    return runBitwardenJsonImport(parsed, ctx.attachments);
  }

  async function handleSubmit() {
    if (!file) {
      onNotify('error', t('txt_please_select_a_file'));
      return;
    }

    setIsSubmitting(true);
    try {
      if (source === 'bitwarden_zip') {
        try {
          const bundle = await readBitwardenZipPayload(file, '');
          let parsed: unknown;
          try {
            parsed = JSON.parse(bundle.jsonText);
          } catch {
            throw new Error(t('txt_import_invalid_json_file'));
          }
          if (isPasswordProtectedExport(parsed)) {
            setPendingPasswordImport({
              parsed,
              source: 'bitwarden_zip',
              attachments: bundle.attachments,
            });
            setImportPassword('');
            setPasswordDialogOpen(true);
            return;
          }
          const summary = await runBitwardenJsonImport(parsed, bundle.attachments);
          setImportSummary(summary);
          setFile(null);
          return;
        } catch (error) {
          if (error instanceof ZipNeedsPasswordError) {
            setPendingZipFile(file);
            setZipImportPassword('');
            setZipPasswordDialogOpen(true);
            return;
          }
          throw error;
        }
      }

      const text = await readImportText(file, source);
      if (source === 'bitwarden_json' || source === 'nodewarden_json') {
        let parsed: unknown;
        try {
          parsed = JSON.parse(text);
        } catch {
          throw new Error(t('txt_import_invalid_json_file'));
        }
        if (isPasswordProtectedExport(parsed)) {
          setPendingPasswordImport({
            parsed,
            source,
            attachments: [],
          });
          setImportPassword('');
          setPasswordDialogOpen(true);
          return;
        }
        const summary =
          source === 'nodewarden_json'
            ? await runNodeWardenJsonImport(parsed)
            : await runBitwardenJsonImport(parsed);
        setImportSummary(summary);
      } else {
        const summary = await onImport(
          parseImportPayloadBySource(source, text),
          {
            folderMode,
            targetFolderId: folderMode === 'target' ? targetFolderId || null : null,
          },
          []
        );
        setImportSummary(summary);
      }
      setFile(null);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_import_failed');
      onNotify('error', message);
    } finally {
      setIsSubmitting(false);
    }
  }

  async function handlePasswordImportConfirm() {
    if (isPasswordSubmitting) return;
    if (!pendingPasswordImport) return;
    setIsPasswordSubmitting(true);
    try {
      const summary = await processPasswordProtectedImport(pendingPasswordImport);
      setImportSummary(summary);
      setFile(null);
      setImportPassword('');
      setPendingPasswordImport(null);
      setPasswordDialogOpen(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_import_failed');
      onNotify('error', message);
    } finally {
      setIsPasswordSubmitting(false);
    }
  }

  async function handleZipPasswordImportConfirm() {
    if (isZipPasswordSubmitting) return;
    if (!pendingZipFile) return;
    setIsZipPasswordSubmitting(true);
    try {
      const bundle = await readBitwardenZipPayload(pendingZipFile, zipImportPassword);
      let parsed: unknown;
      try {
        parsed = JSON.parse(bundle.jsonText);
      } catch {
        throw new Error(t('txt_import_invalid_json_file'));
      }
      if (isPasswordProtectedExport(parsed)) {
        setPendingPasswordImport({
          parsed,
          source: 'bitwarden_zip',
          attachments: bundle.attachments,
        });
        setImportPassword('');
        setPasswordDialogOpen(true);
      } else {
        const summary = await runBitwardenJsonImport(parsed, bundle.attachments);
        setImportSummary(summary);
        setFile(null);
      }
      setZipPasswordDialogOpen(false);
      setPendingZipFile(null);
      setZipImportPassword('');
    } catch (error) {
      if (error instanceof ZipInvalidPasswordError) {
        onNotify('error', t('txt_import_invalid_zip_password'));
        return;
      }
      const message = error instanceof Error ? error.message : t('txt_import_failed');
      onNotify('error', message);
    } finally {
      setIsZipPasswordSubmitting(false);
    }
  }

  const exportNeedsMode =
    exportFormat === 'bitwarden_encrypted_json' ||
    exportFormat === 'bitwarden_encrypted_json_zip' ||
    exportFormat === 'nodewarden_encrypted_json';
  const exportNeedsFilePassword = exportNeedsMode && encryptedJsonMode === 'password';
  const exportIsZip = exportFormat === 'bitwarden_json_zip' || exportFormat === 'bitwarden_encrypted_json_zip';

  async function runExportWithMasterPassword(masterPassword: string) {
    const filePassword = exportPassword.trim();
    const zipPass = zipPassword.trim();
    if (exportNeedsFilePassword && !filePassword) {
      onNotify('error', t('txt_import_file_password_required'));
      return;
    }

    setIsExporting(true);
    try {
      await onExport({
        format: exportFormat,
        encryptedJsonMode: exportNeedsMode ? encryptedJsonMode : undefined,
        filePassword,
        zipPassword: exportIsZip ? zipPass : '',
        masterPassword,
      });
      onNotify('success', t('txt_export_completed'));
    } catch (error) {
      const message = error instanceof Error ? error.message : t('txt_export_failed');
      onNotify('error', message);
    } finally {
      setIsExporting(false);
    }
  }

  async function handleExportConfirmPassword() {
    if (isExporting) return;
    const masterPassword = String(exportAuthPassword || '').trim();
    if (!masterPassword) {
      onNotify('error', t('txt_master_password_is_required'));
      return;
    }
    await runExportWithMasterPassword(masterPassword);
    if (!isExporting) {
      setExportAuthPassword('');
      setExportAuthDialogOpen(false);
    }
  }

  function handleExport() {
    setExportAuthPassword('');
    setExportAuthDialogOpen(true);
  }

  return (
    <div className="import-export-page">
      <div className="import-export-panels">
      <section className="card import-export-panel">
        <h3>{t('txt_import')}</h3>
        <p className="backup-inline-note">{t('txt_import_vault_data_hint')}</p>
        <div className="field-grid">
          <label className="field field-span-2">
            <span>{t('txt_format')}</span>
            <select className="input" value={source} onChange={(e) => setSource((e.currentTarget as HTMLSelectElement).value as ImportSourceId)}>
              {commonSources.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
              {otherSources.length > 0 && (
                <option disabled value="__separator__">
                  --------------------
                </option>
              )}
              {otherSources.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          <label className="field field-span-2">
            <span>{t('txt_source_file')}</span>
            <input
              className="input"
              type="file"
              accept={getFileAcceptBySource(source)}
              onChange={(e) => {
                const next = (e.currentTarget as HTMLInputElement).files?.[0] || null;
                setFile(next);
              }}
            />
          </label>

          <label className="field field-span-2">
            <span>{t('txt_folder_handling')}</span>
            <select
              className="input"
              value={folderMode}
              onChange={(e) => setFolderMode((e.currentTarget as HTMLSelectElement).value as 'original' | 'none' | 'target')}
            >
              <option value="original">{t('txt_import_folder_mode_original')}</option>
              <option value="none">{t('txt_import_folder_mode_none')}</option>
              <option value="target">{t('txt_import_folder_mode_target')}</option>
            </select>
          </label>

          {folderMode === 'target' && (
            <label className="field field-span-2">
              <span>{t('txt_target_folder')}</span>
              <select className="input" value={targetFolderId} onChange={(e) => setTargetFolderId((e.currentTarget as HTMLSelectElement).value)}>
                <option value="">{t('txt_select_folder_placeholder')}</option>
                {folders
                  .slice()
                  .sort((a, b) => String(a.decName || a.name || '').localeCompare(String(b.decName || b.name || '')))
                  .map((folder) => (
                    <option key={folder.id} value={folder.id}>
                      {folder.decName || folder.name || folder.id}
                    </option>
                  ))}
              </select>
            </label>
          )}
        </div>

        <div className="actions">
          <button
            type="button"
            className="btn btn-primary"
            disabled={isSubmitting || (folderMode === 'target' && !targetFolderId)}
            onClick={() => void handleSubmit()}
          >
            <FileUp size={15} /> {isSubmitting ? t('txt_loading') : t('txt_import')}
          </button>
        </div>
      </section>

      <section className="card import-export-panel">
        <h3>{t('txt_export')}</h3>
        <p className="backup-inline-note">{t('txt_export_vault_data_hint')}</p>
        <div className="field-grid">
          <label className="field field-span-2">
            <span>{t('txt_format')}</span>
            <select
              className="input"
              value={exportFormat}
              onChange={(e) => {
                const next = (e.currentTarget as HTMLSelectElement).value as ExportFormatId;
                setExportFormat(next);
              }}
            >
              {EXPORT_FORMATS.map((item) => (
                <option key={item.id} value={item.id}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>

          {exportNeedsMode && (
            <label className="field field-span-2">
              <span>{t('txt_encrypted_mode')}</span>
              <select
                className="input"
                value={encryptedJsonMode}
                onChange={(e) => setEncryptedJsonMode((e.currentTarget as HTMLSelectElement).value as EncryptedJsonMode)}
              >
                <option value="account">{t('txt_account_verification')}</option>
                <option value="password">{t('txt_password_verification')}</option>
              </select>
            </label>
          )}

          {exportNeedsFilePassword && (
            <label className="field field-span-2">
              <span>{t('txt_file_password')}</span>
              <input
                className="input"
                type="password"
                value={exportPassword}
                onInput={(e) => setExportPassword((e.currentTarget as HTMLInputElement).value)}
              />
            </label>
          )}

          {exportIsZip && (
            <label className="field field-span-2">
              <span>{t('txt_zip_password_optional')}</span>
              <input
                className="input"
                type="password"
                value={zipPassword}
                onInput={(e) => setZipPassword((e.currentTarget as HTMLInputElement).value)}
              />
            </label>
          )}
        </div>

        <div className="actions">
          <button type="button" className="btn btn-primary" disabled={isExporting} onClick={() => void handleExport()}>
            <Download size={15} className="btn-icon" />
            {isExporting ? t('txt_loading') : t('txt_export')}
          </button>
        </div>
      </section>
      </div>

      <ConfirmDialog
        open={exportAuthDialogOpen}
        title={t('txt_export')}
        message={t('txt_enter_master_password_to_view_this_item')}
        confirmText={isExporting ? t('txt_loading') : t('txt_verify')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={isExporting}
        cancelDisabled={isExporting}
        onConfirm={() => void handleExportConfirmPassword()}
        onCancel={() => {
          if (isExporting) return;
          setExportAuthDialogOpen(false);
          setExportAuthPassword('');
        }}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input
            className="input"
            type="password"
            value={exportAuthPassword}
            onInput={(e) => setExportAuthPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={passwordDialogOpen}
        title={t('txt_import_encrypted_file_title')}
        message={t('txt_import_encrypted_file_message')}
        confirmText={isPasswordSubmitting ? t('txt_loading') : t('txt_import')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={isPasswordSubmitting}
        cancelDisabled={isPasswordSubmitting}
        onConfirm={() => void handlePasswordImportConfirm()}
        onCancel={() => {
          if (isPasswordSubmitting) return;
          setPasswordDialogOpen(false);
          setImportPassword('');
          setPendingPasswordImport(null);
        }}
      >
        <label className="field">
          <span>{t('txt_file_password')}</span>
          <input
            className="input"
            type="password"
            value={importPassword}
            onInput={(e) => setImportPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={zipPasswordDialogOpen}
        title={t('txt_import_encrypted_zip_title')}
        message={t('txt_import_encrypted_zip_message')}
        confirmText={isZipPasswordSubmitting ? t('txt_loading') : t('txt_import')}
        cancelText={t('txt_cancel')}
        showIcon={false}
        confirmDisabled={isZipPasswordSubmitting}
        cancelDisabled={isZipPasswordSubmitting}
        onConfirm={() => void handleZipPasswordImportConfirm()}
        onCancel={() => {
          if (isZipPasswordSubmitting) return;
          setZipPasswordDialogOpen(false);
          setZipImportPassword('');
          setPendingZipFile(null);
        }}
      >
        <label className="field">
          <span>{t('txt_zip_password')}</span>
          <input
            className="input"
            type="password"
            value={zipImportPassword}
            onInput={(e) => setZipImportPassword((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>

      {importSummary && typeof document !== 'undefined' ? createPortal((
        <div
          className="dialog-mask"
          onClick={(event) => {
            if (event.target !== event.currentTarget) return;
            setImportSummary(null);
          }}
        >
          <section className="dialog-card import-summary-dialog" role="dialog" aria-modal="true" aria-label={t('txt_import_success')}>
            <button
              type="button"
              className="import-summary-close"
              onClick={() => setImportSummary(null)}
              aria-label={t('txt_close')}
            >
              X
            </button>
            <h3 className="dialog-title">{t('txt_import_success')}</h3>
            <div className="dialog-message">{t('txt_import_success_number_of_items', { count: importSummary.totalItems })}</div>
            {importSummary.attachmentCount > 0 && (
              <div className="dialog-message">
                {t('txt_import_attachment_summary', {
                  imported: String(importSummary.importedAttachmentCount),
                  total: String(importSummary.attachmentCount),
                })}
              </div>
            )}
            {importSummary.failedAttachments.length > 0 && (
              <div className="import-summary-failed-list">
                <div className="import-summary-failed-title">
                  {t('txt_import_failed_attachments_title', { count: String(importSummary.failedAttachments.length) })}
                </div>
                <ul>
                  {importSummary.failedAttachments.map((row, index) => (
                    <li key={`${row.fileName}-${index}`}>
                      <strong>{row.fileName}</strong>
                      {`: ${row.reason}`}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <div className="import-summary-table-wrap">
              <table className="import-summary-table">
                <thead>
                  <tr>
                    <th>{t('txt_type')}</th>
                    <th>{t('txt_total')}</th>
                  </tr>
                </thead>
                <tbody>
                  {importSummary.typeCounts.map((row) => (
                    <tr key={row.label}>
                      <td>{row.label}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                  <tr>
                    <td>{t('txt_folder')}</td>
                    <td>{importSummary.folderCount}</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <button type="button" className="btn btn-primary dialog-btn" onClick={() => setImportSummary(null)}>
              {t('txt_confirm')}
            </button>
          </section>
        </div>
      ), document.body) : null}
    </div>
  );
}
