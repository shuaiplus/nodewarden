import { argon2idAsync } from '@noble/hashes/argon2.js';
import { strToU8, zipSync } from 'fflate';
import { Uint8ArrayReader, Uint8ArrayWriter, ZipReader, ZipWriter, configure as configureZipJs } from '@zip.js/zip.js';
import type { PreloginKdfConfig } from './api/auth';
import { base64ToBytes, bytesToBase64, decryptBw, decryptStr, encryptBw, hkdfExpand, pbkdf2 } from './crypto';
import type { Cipher, Folder } from './types';

configureZipJs({ useWebWorkers: false });

export const EXPORT_FORMATS = [
  { id: 'bitwarden_json', label: 'Bitwarden (vault as json)' },
  { id: 'bitwarden_csv', label: 'Bitwarden (vault as csv)' },
  { id: 'bitwarden_encrypted_json', label: 'Bitwarden (encrypted vault as json)' },
  { id: 'bitwarden_json_zip', label: 'Bitwarden (vault + attachments as zip)' },
  { id: 'bitwarden_encrypted_json_zip', label: 'Bitwarden (encrypted vault + attachments as zip)' },
  { id: 'nodewarden_json', label: 'NodeWarden (vault + attachments as json)' },
  { id: 'nodewarden_encrypted_json', label: 'NodeWarden (encrypted vault + attachments as json)' },
] as const;

export type ExportFormatId = (typeof EXPORT_FORMATS)[number]['id'];
export type EncryptedJsonMode = 'account' | 'password';

export interface ExportRequest {
  format: ExportFormatId;
  encryptedJsonMode?: EncryptedJsonMode;
  filePassword?: string;
  zipPassword?: string;
  masterPassword?: string;
}

export interface ExportDownloadPayload {
  fileName: string;
  mimeType: string;
  bytes: Uint8Array;
}

export interface ZipAttachmentEntry {
  cipherId: string;
  fileName: string;
  bytes: Uint8Array;
}

export interface NodeWardenAttachmentRecord {
  cipherId: string;
  cipherIndex: number | null;
  fileName: string;
  data: string;
}

interface BuildPlainJsonArgs {
  folders: Folder[];
  ciphers: Cipher[];
  userEncB64: string;
  userMacB64: string;
}

interface BuildEncryptedJsonArgs {
  folders: Folder[];
  ciphers: Cipher[];
  userEncB64: string;
  userMacB64: string;
}

interface PasswordProtectedArgs {
  plaintextJson: string;
  password: string;
  kdf: PreloginKdfConfig;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function csvText(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function escapeCsvCell(value: unknown): string {
  const text = csvText(value);
  if (!/[",\r\n]/.test(text)) return text;
  return `"${text.replace(/"/g, '""')}"`;
}

function buildCsvString(rows: string[][]): string {
  return `${rows.map((row) => row.map(escapeCsvCell).join(',')).join('\r\n')}\r\n`;
}

function buildSingleRowCsvString(values: string[]): string {
  return values.map(escapeCsvCell).join(',');
}

function isCipherString(value: string): boolean {
  return /^\d+\.[A-Za-z0-9+/=]+\|[A-Za-z0-9+/=]+(?:\|[A-Za-z0-9+/=]+)?$/.test(String(value || '').trim());
}

function normalizeString(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  return String(value);
}

function normalizeNumber(value: unknown, fallback = 0): number {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return n;
}

function cloneValue<T>(value: T): T {
  if (value === null || value === undefined) return value;
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(value);
    } catch {
      // ignore and fallback
    }
  }
  try {
    return JSON.parse(JSON.stringify(value)) as T;
  } catch {
    return value;
  }
}

function randomGuid(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

async function getCipherKeyParts(cipher: Cipher, userEnc: Uint8Array, userMac: Uint8Array): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  if (cipher.key && typeof cipher.key === 'string') {
    try {
      const raw = await decryptBw(cipher.key, userEnc, userMac);
      if (raw.length >= 64) {
        return { enc: raw.slice(0, 32), mac: raw.slice(32, 64) };
      }
    } catch {
      // Fallback to user key.
    }
  }
  return { enc: userEnc, mac: userMac };
}

async function decryptMaybe(value: unknown, enc: Uint8Array, mac: Uint8Array): Promise<string | null> {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') return String(value);
  const raw = value;
  if (!raw) return '';
  if (!isCipherString(raw)) return raw;
  try {
    return await decryptStr(raw, enc, mac);
  } catch {
    return raw;
  }
}

async function deepDecryptUnknown(value: unknown, enc: Uint8Array, mac: Uint8Array): Promise<unknown> {
  if (value === null || value === undefined) return value;
  if (typeof value === 'string') return decryptMaybe(value, enc, mac);
  if (Array.isArray(value)) {
    return Promise.all(value.map((item) => deepDecryptUnknown(item, enc, mac)));
  }
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = await deepDecryptUnknown(v, enc, mac);
    }
    return out;
  }
  return value;
}

function mapCipherCommonMetadata(cipher: Cipher): Record<string, unknown> {
  const out: Record<string, unknown> = {
    id: cipher.id,
    type: normalizeNumber(cipher.type, 1),
    reprompt: normalizeNumber(cipher.reprompt, 0),
    favorite: !!cipher.favorite,
    folderId: normalizeString(cipher.folderId),
    creationDate: normalizeString(cipher.creationDate),
    revisionDate: normalizeString(cipher.revisionDate),
    collectionIds: null,
  };
  if ((out.creationDate as string | null) === null) delete out.creationDate;
  if ((out.revisionDate as string | null) === null) delete out.revisionDate;
  if ((out.folderId as string | null) === null) delete out.folderId;
  return out;
}

function mapCipherEncrypted(cipher: Cipher): Record<string, unknown> {
  const out = mapCipherCommonMetadata(cipher);
  out.name = cipher.name ?? null;
  out.notes = cipher.notes ?? null;
  out.key = cipher.key ?? null;
  out.fields = Array.isArray(cipher.fields)
    ? cipher.fields.map((field) => ({
        name: field?.name ?? null,
        value: field?.value ?? null,
        type: normalizeNumber(field?.type, 0),
        linkedId: field?.linkedId ?? null,
      }))
    : [];

  const login = cipher.login;
  out.login = login
    ? {
        ...(cloneWithoutDecodedFields(login) || {}),
        username: login.username ?? null,
        password: login.password ?? null,
        totp: login.totp ?? null,
        uris: Array.isArray(login.uris)
          ? login.uris.map((uri) => ({
              ...(cloneWithoutDecodedFields(uri) || {}),
              uri: uri?.uri ?? null,
              uriChecksum: uri?.uriChecksum ?? null,
              match: (uri as { match?: unknown })?.match ?? null,
            }))
          : [],
        fido2Credentials: Array.isArray(login.fido2Credentials) ? cloneValue(login.fido2Credentials) : [],
      }
    : null;

  out.card = cipher.card
    ? {
        cardholderName: cipher.card.cardholderName ?? null,
        brand: cipher.card.brand ?? null,
        number: cipher.card.number ?? null,
        expMonth: cipher.card.expMonth ?? null,
        expYear: cipher.card.expYear ?? null,
        code: cipher.card.code ?? null,
      }
    : null;

  out.identity = cipher.identity
    ? {
        title: cipher.identity.title ?? null,
        firstName: cipher.identity.firstName ?? null,
        middleName: cipher.identity.middleName ?? null,
        lastName: cipher.identity.lastName ?? null,
        username: cipher.identity.username ?? null,
        company: cipher.identity.company ?? null,
        ssn: cipher.identity.ssn ?? null,
        passportNumber: cipher.identity.passportNumber ?? null,
        licenseNumber: cipher.identity.licenseNumber ?? null,
        email: cipher.identity.email ?? null,
        phone: cipher.identity.phone ?? null,
        address1: cipher.identity.address1 ?? null,
        address2: cipher.identity.address2 ?? null,
        address3: cipher.identity.address3 ?? null,
        city: cipher.identity.city ?? null,
        state: cipher.identity.state ?? null,
        postalCode: cipher.identity.postalCode ?? null,
        country: cipher.identity.country ?? null,
      }
    : null;

  out.secureNote = cipher.secureNote
    ? {
        type: normalizeNumber((cipher.secureNote as { type?: unknown }).type, 0),
      }
    : null;

  out.passwordHistory = Array.isArray(cipher.passwordHistory)
    ? cipher.passwordHistory.map((entry) => ({
        password: (entry as { password?: unknown }).password ?? null,
        lastUsedDate: (entry as { lastUsedDate?: unknown }).lastUsedDate ?? null,
      }))
    : [];

  out.sshKey = cipher.sshKey
    ? {
        ...(cloneWithoutDecodedFields(cipher.sshKey) || {}),
        privateKey: cipher.sshKey.privateKey ?? null,
        publicKey: cipher.sshKey.publicKey ?? null,
        keyFingerprint: cipher.sshKey.keyFingerprint ?? cipher.sshKey.fingerprint ?? null,
        // Keep legacy alias for compatibility with older importers.
        fingerprint: cipher.sshKey.keyFingerprint ?? cipher.sshKey.fingerprint ?? null,
      }
    : null;
  out.bankAccount = cloneWithoutDecodedFields(cipher.bankAccount) ?? null;
  out.driversLicense = cloneWithoutDecodedFields(cipher.driversLicense) ?? null;
  out.passport = cloneWithoutDecodedFields(cipher.passport) ?? null;

  return out;
}

async function mapCipherPlain(cipher: Cipher, userEnc: Uint8Array, userMac: Uint8Array): Promise<Record<string, unknown>> {
  const keyParts = await getCipherKeyParts(cipher, userEnc, userMac);
  const out = mapCipherCommonMetadata(cipher);

  out.name = await decryptMaybe(cipher.name ?? null, keyParts.enc, keyParts.mac);
  out.notes = await decryptMaybe(cipher.notes ?? null, keyParts.enc, keyParts.mac);
  out.fields = Array.isArray(cipher.fields)
    ? await Promise.all(
        cipher.fields.map(async (field) => ({
          name: await decryptMaybe(field?.name ?? null, keyParts.enc, keyParts.mac),
          value: await decryptMaybe(field?.value ?? null, keyParts.enc, keyParts.mac),
          type: normalizeNumber(field?.type, 0),
          linkedId: field?.linkedId ?? null,
        }))
      )
    : [];

  if (cipher.login) {
    out.login = {
      username: await decryptMaybe(cipher.login.username ?? null, keyParts.enc, keyParts.mac),
      password: await decryptMaybe(cipher.login.password ?? null, keyParts.enc, keyParts.mac),
      totp: await decryptMaybe(cipher.login.totp ?? null, keyParts.enc, keyParts.mac),
      uris: Array.isArray(cipher.login.uris)
        ? await Promise.all(
            cipher.login.uris.map(async (uri) => ({
              uri: await decryptMaybe(uri?.uri ?? null, keyParts.enc, keyParts.mac),
              match: (uri as { match?: unknown })?.match ?? null,
            }))
          )
        : [],
      fido2Credentials: Array.isArray(cipher.login.fido2Credentials)
        ? await Promise.all(
            cipher.login.fido2Credentials.map((credential) => deepDecryptUnknown(credential, keyParts.enc, keyParts.mac))
          )
        : [],
    };
  } else {
    out.login = null;
  }

  out.card = cipher.card ? await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.card), keyParts.enc, keyParts.mac) : null;
  out.identity = cipher.identity ? await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.identity), keyParts.enc, keyParts.mac) : null;
  if (cipher.sshKey) {
    const fingerprint = await decryptMaybe(
      cipher.sshKey.keyFingerprint ?? cipher.sshKey.fingerprint ?? null,
      keyParts.enc,
      keyParts.mac
    );
    out.sshKey = {
      ...((await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.sshKey), keyParts.enc, keyParts.mac)) as Record<string, unknown>),
      privateKey: await decryptMaybe(cipher.sshKey.privateKey ?? null, keyParts.enc, keyParts.mac),
      publicKey: await decryptMaybe(cipher.sshKey.publicKey ?? null, keyParts.enc, keyParts.mac),
      keyFingerprint: fingerprint,
      // Keep legacy alias for compatibility with older importers.
      fingerprint,
    };
  } else {
    out.sshKey = null;
  }
  out.bankAccount = cipher.bankAccount
    ? await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.bankAccount), keyParts.enc, keyParts.mac)
    : null;
  out.driversLicense = cipher.driversLicense
    ? await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.driversLicense), keyParts.enc, keyParts.mac)
    : null;
  out.passport = cipher.passport
    ? await deepDecryptUnknown(cloneWithoutDecodedFields(cipher.passport), keyParts.enc, keyParts.mac)
    : null;
  out.secureNote = cipher.secureNote
    ? {
        type: normalizeNumber((cipher.secureNote as { type?: unknown }).type, 0),
      }
    : null;

  out.passwordHistory = Array.isArray(cipher.passwordHistory)
    ? await Promise.all(
        cipher.passwordHistory.map(async (entry) => ({
          password: await decryptMaybe((entry as { password?: unknown }).password ?? null, keyParts.enc, keyParts.mac),
          lastUsedDate: normalizeString((entry as { lastUsedDate?: unknown }).lastUsedDate),
        }))
      )
    : [];

  return out;
}

async function decryptFolderName(folder: Folder, userEnc: Uint8Array, userMac: Uint8Array): Promise<string> {
  const value = await decryptMaybe(folder.name ?? '', userEnc, userMac);
  return value || '';
}

function trimNullKeys(value: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value)) {
    if (v !== undefined) out[k] = v;
  }
  return out;
}

function filterExportableCiphers(ciphers: Cipher[]): Cipher[] {
  return ciphers.filter((cipher) => !cipher.deletedDate && !(cipher as { organizationId?: unknown }).organizationId);
}

export async function buildPlainBitwardenJsonDocument(args: BuildPlainJsonArgs): Promise<Record<string, unknown>> {
  const userEnc = base64ToBytes(args.userEncB64);
  const userMac = base64ToBytes(args.userMacB64);

  const folders = await Promise.all(
    args.folders.map(async (folder) => ({
      id: folder.id,
      name: await decryptFolderName(folder, userEnc, userMac),
    }))
  );

  const items = await Promise.all(filterExportableCiphers(args.ciphers).map((cipher) => mapCipherPlain(cipher, userEnc, userMac)));

  return {
    encrypted: false,
    folders,
    items: items.map((item) => trimNullKeys(item)),
  };
}

export async function buildPlainBitwardenJsonString(args: BuildPlainJsonArgs): Promise<string> {
  const doc = await buildPlainBitwardenJsonDocument(args);
  return JSON.stringify(doc, null, 2);
}

const BITWARDEN_CSV_HEADERS = [
  'folder',
  'favorite',
  'type',
  'name',
  'notes',
  'fields',
  'reprompt',
  'login_uri',
  'login_username',
  'login_password',
  'login_totp',
] as const;

function bitwardenCsvType(type: number): 'login' | 'note' {
  return type === 1 ? 'login' : 'note';
}

function sourceTypeLabel(type: number): string {
  if (type === 3) return 'card';
  if (type === 4) return 'identity';
  if (type === 5) return 'sshKey';
  if (type === 6) return 'bankAccount';
  if (type === 7) return 'driversLicense';
  if (type === 8) return 'passport';
  if (type === 2) return 'note';
  return `type ${type}`;
}

function appendFieldLine(lines: string[], name: unknown, value: unknown): void {
  const key = csvText(name).trim();
  const text = csvText(value);
  if (!key || !text) return;
  lines.push(`${key}: ${text}`);
}

function appendRecordFieldLines(lines: string[], prefix: string, value: unknown): void {
  if (!isRecord(value)) return;
  for (const [key, fieldValue] of Object.entries(value)) {
    appendFieldLine(lines, `${prefix}.${key}`, fieldValue);
  }
}

function cloneWithoutDecodedFields(value: unknown): Record<string, unknown> | null {
  if (!isRecord(value)) return null;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (/^dec[A-Z]/.test(key)) continue;
    out[key] = cloneValue(item);
  }
  return out;
}

const BITWARDEN_CSV_OBJECT_FIELDS: Record<string, readonly string[]> = {
  card: ['cardholderName', 'brand', 'number', 'expMonth', 'expYear', 'code'],
  identity: [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'username',
    'company',
    'ssn',
    'passportNumber',
    'licenseNumber',
    'email',
    'phone',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
  ],
  sshKey: ['privateKey', 'publicKey', 'keyFingerprint', 'fingerprint'],
  bankAccount: ['bankName', 'nameOnAccount', 'accountType', 'accountNumber', 'routingNumber', 'branchNumber', 'pin', 'swiftCode', 'iban', 'bankContactPhone'],
  driversLicense: ['firstName', 'middleName', 'lastName', 'dateOfBirth', 'licenseNumber', 'issuingCountry', 'issuingState', 'issueDate', 'expirationDate', 'issuingAuthority', 'licenseClass'],
  passport: ['surname', 'givenName', 'dateOfBirth', 'sex', 'birthPlace', 'nationality', 'issuingCountry', 'passportNumber', 'passportType', 'nationalIdentificationNumber', 'issuingAuthority', 'issueDate', 'expirationDate'],
};

function appendKnownRecordFieldLines(lines: string[], prefix: string, value: unknown): void {
  if (!isRecord(value)) return;
  const keys = BITWARDEN_CSV_OBJECT_FIELDS[prefix];
  if (!keys) {
    appendRecordFieldLines(lines, prefix, value);
    return;
  }
  for (const key of keys) {
    appendFieldLine(lines, `${prefix}.${key}`, value[key]);
  }
}

function buildBitwardenCsvFields(item: Record<string, unknown>, type: number): string {
  const lines: string[] = [];
  const fields = Array.isArray(item.fields) ? item.fields : [];
  for (const field of fields) {
    if (!isRecord(field)) continue;
    appendFieldLine(lines, field.name, field.value);
  }
  if (type !== 1 && type !== 2) {
    const sourceLabel = sourceTypeLabel(type);
    appendFieldLine(lines, 'nodewardenType', sourceLabel);
    appendKnownRecordFieldLines(lines, sourceLabel, item[sourceLabel]);
  }
  return lines.join('\n');
}

function buildFolderNameById(foldersRaw: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const folders = Array.isArray(foldersRaw) ? foldersRaw : [];
  for (const folder of folders) {
    if (!isRecord(folder)) continue;
    const id = csvText(folder.id).trim();
    if (!id) continue;
    out.set(id, csvText(folder.name));
  }
  return out;
}

function buildBitwardenCsvLoginUri(login: Record<string, unknown> | null): string {
  const uris = Array.isArray(login?.uris) ? login.uris : [];
  return buildSingleRowCsvString(uris
    .map((uri) => (isRecord(uri) ? csvText(uri.uri).trim() : ''))
    .filter(Boolean));
}

export function buildBitwardenCsvString(bitwardenJsonDoc: Record<string, unknown>): string {
  const folderNameById = buildFolderNameById(bitwardenJsonDoc.folders);
  const rows: string[][] = [[...BITWARDEN_CSV_HEADERS]];
  const items = Array.isArray(bitwardenJsonDoc.items) ? bitwardenJsonDoc.items : [];
  for (const itemRaw of items) {
    if (!isRecord(itemRaw)) continue;
    const type = normalizeNumber(itemRaw.type, 1);
    const isLogin = type === 1;
    const login = isRecord(itemRaw.login) ? itemRaw.login : null;
    const folderId = csvText(itemRaw.folderId).trim();
    rows.push([
      folderNameById.get(folderId) || '',
      itemRaw.favorite ? '1' : '0',
      bitwardenCsvType(type),
      csvText(itemRaw.name) || '--',
      csvText(itemRaw.notes),
      buildBitwardenCsvFields(itemRaw, type),
      String(normalizeNumber(itemRaw.reprompt, 0)),
      isLogin ? buildBitwardenCsvLoginUri(login) : '',
      isLogin ? csvText(login?.username) : '',
      isLogin ? csvText(login?.password) : '',
      isLogin ? csvText(login?.totp) : '',
    ]);
  }
  return `\uFEFF${buildCsvString(rows)}`;
}

export async function buildAccountEncryptedBitwardenJsonString(args: BuildEncryptedJsonArgs): Promise<string> {
  const userEnc = base64ToBytes(args.userEncB64);
  const userMac = base64ToBytes(args.userMacB64);
  const validation = await encryptBw(new TextEncoder().encode(randomGuid()), userEnc, userMac);

  const folders = args.folders.map((folder) => ({
    id: folder.id,
    name: folder.name,
  }));

  const items = filterExportableCiphers(args.ciphers).map((cipher) => mapCipherEncrypted(cipher));

  const doc = {
    encrypted: true,
    encKeyValidation_DO_NOT_EDIT: validation,
    folders,
    items,
  };
  return JSON.stringify(doc, null, 2);
}

async function derivePasswordProtectedKey(kdf: PreloginKdfConfig, password: string, saltB64: string): Promise<{ enc: Uint8Array; mac: Uint8Array }> {
  const iterations = Math.max(1, normalizeNumber(kdf.kdfIterations, 600000));
  const kdfType = normalizeNumber(kdf.kdfType, 0);
  const saltTextBytes = new TextEncoder().encode(saltB64);

  let keyMaterial: Uint8Array;
  if (kdfType === 1) {
    const memoryMiB = Math.max(16, normalizeNumber(kdf.kdfMemory, 64));
    const parallelism = Math.max(1, normalizeNumber(kdf.kdfParallelism, 4));
    const memoryKiB = Math.floor(memoryMiB * 1024);
    const maxmem = memoryKiB * 1024 + 1024 * 1024;
    keyMaterial = await argon2idAsync(new TextEncoder().encode(password), saltTextBytes, {
      t: Math.floor(iterations),
      m: memoryKiB,
      p: Math.floor(parallelism),
      dkLen: 32,
      maxmem,
      asyncTick: 10,
    });
  } else {
    keyMaterial = await pbkdf2(password, saltTextBytes, iterations, 32);
  }

  const enc = await hkdfExpand(keyMaterial, 'enc', 32);
  const mac = await hkdfExpand(keyMaterial, 'mac', 32);
  return { enc, mac };
}

export async function buildPasswordProtectedBitwardenJsonString(args: PasswordProtectedArgs): Promise<string> {
  const password = String(args.password || '').trim();
  if (!password) throw new Error('File password is required');

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const saltB64 = bytesToBase64(salt);
  const key = await derivePasswordProtectedKey(args.kdf, password, saltB64);

  const validation = await encryptBw(new TextEncoder().encode(randomGuid()), key.enc, key.mac);
  const data = await encryptBw(new TextEncoder().encode(args.plaintextJson), key.enc, key.mac);

  const kdfType = normalizeNumber(args.kdf.kdfType, 0);
  const out: Record<string, unknown> = {
    encrypted: true,
    passwordProtected: true,
    salt: saltB64,
    kdfType,
    kdfIterations: Math.max(1, normalizeNumber(args.kdf.kdfIterations, 600000)),
    encKeyValidation_DO_NOT_EDIT: validation,
    data,
  };
  if (kdfType === 1) {
    out.kdfMemory = Math.max(16, normalizeNumber(args.kdf.kdfMemory, 64));
    out.kdfParallelism = Math.max(1, normalizeNumber(args.kdf.kdfParallelism, 4));
  }

  return JSON.stringify(out, null, 2);
}

function sanitizeFileName(name: string): string {
  const normalized = String(name || '').trim().replace(/[\\/]/g, '_').replace(/[\x00-\x1F\x7F]/g, '');
  if (!normalized) return 'attachment.bin';
  if (normalized.length > 240) {
    const dot = normalized.lastIndexOf('.');
    if (dot > 0 && dot > normalized.length - 16) {
      const ext = normalized.slice(dot);
      return `${normalized.slice(0, 240 - ext.length)}${ext}`;
    }
    return normalized.slice(0, 240);
  }
  return normalized;
}

function uniqueAttachmentFileName(cipherId: string, originalName: string, used: Set<string>): string {
  const safe = sanitizeFileName(originalName);
  const keyBase = `${cipherId}/${safe}`;
  if (!used.has(keyBase)) {
    used.add(keyBase);
    return safe;
  }

  const dot = safe.lastIndexOf('.');
  const base = dot > 0 ? safe.slice(0, dot) : safe;
  const ext = dot > 0 ? safe.slice(dot) : '';
  let idx = 1;
  while (idx < 10000) {
    const candidate = `${base} (${idx})${ext}`;
    const key = `${cipherId}/${candidate}`;
    if (!used.has(key)) {
      used.add(key);
      return candidate;
    }
    idx += 1;
  }
  return `${base}-${Date.now()}${ext}`;
}

export function buildBitwardenZipBytes(dataJson: string, attachments: ZipAttachmentEntry[]): Uint8Array {
  const files: Record<string, Uint8Array> = {
    'data.json': strToU8(dataJson),
  };
  const used = new Set<string>();
  for (const attachment of attachments) {
    const cipherId = String(attachment.cipherId || '').trim();
    if (!cipherId) continue;
    const fileName = uniqueAttachmentFileName(cipherId, attachment.fileName || 'attachment.bin', used);
    files[`attachments/${cipherId}/${fileName}`] = attachment.bytes;
  }
  return zipSync(files, { level: 6 });
}

export async function encryptZipBytesWithPassword(
  zipBytes: Uint8Array,
  passwordRaw: string
): Promise<{ bytes: Uint8Array; encrypted: boolean }> {
  const password = String(passwordRaw || '').trim();
  if (!password) return { bytes: zipBytes, encrypted: false };
  const zipReader = new ZipReader(new Uint8ArrayReader(zipBytes), { useWebWorkers: false });
  const zipWriter = new ZipWriter(new Uint8ArrayWriter(), { useWebWorkers: false });
  try {
    const entries = await zipReader.getEntries();
    for (const entry of entries) {
      const filename = String(entry.filename || '').trim();
      if (!filename) continue;

      if (entry.directory) {
        await zipWriter.add(filename, undefined, {
          directory: true,
          password,
          encryptionStrength: 3,
        });
        continue;
      }

      const data = await entry.getData(new Uint8ArrayWriter());
      await zipWriter.add(filename, new Uint8ArrayReader(data), {
        password,
        encryptionStrength: 3,
        level: 6,
      });
    }

    return {
      bytes: await zipWriter.close(),
      encrypted: true,
    };
  } finally {
    await zipReader.close();
  }
}

function nowStamp(now = new Date()): string {
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  return `${y}${m}${d}_${hh}${mm}${ss}`;
}

export function buildExportFileName(format: ExportFormatId, zipEncrypted = false): string {
  const stamp = nowStamp();
  if (
    format === 'bitwarden_csv' ||
    format === 'bitwarden_json' ||
    format === 'bitwarden_encrypted_json' ||
    format === 'nodewarden_json' ||
    format === 'nodewarden_encrypted_json'
  ) {
    if (format === 'bitwarden_csv') return `bitwarden_export_${stamp}.csv`;
    if (format.startsWith('nodewarden_')) return `nodewarden_export_${stamp}.json`;
    return `bitwarden_export_${stamp}.json`;
  }
  if (format === 'bitwarden_json_zip' || format === 'bitwarden_encrypted_json_zip') {
    if (zipEncrypted) return `bitwarden_export_${stamp}.zip`;
    return `bitwarden_export_${stamp}.zip`;
  }
  return `bitwarden_export_${stamp}.bin`;
}

export function buildNodeWardenAttachmentRecords(
  attachments: ZipAttachmentEntry[],
  cipherIndexById?: Map<string, number>
): NodeWardenAttachmentRecord[] {
  const out: NodeWardenAttachmentRecord[] = [];
  for (const attachment of attachments) {
    const cipherId = String(attachment.cipherId || '').trim();
    if (!cipherId) continue;
    const fileName = sanitizeFileName(String(attachment.fileName || '').trim() || 'attachment.bin');
    out.push({
      cipherId,
      cipherIndex: cipherIndexById?.get(cipherId) ?? null,
      fileName,
      data: bytesToBase64(attachment.bytes),
    });
  }
  return out;
}

export function buildNodeWardenPlainJsonDocument(
  bitwardenJsonDoc: Record<string, unknown>,
  attachments: NodeWardenAttachmentRecord[]
): Record<string, unknown> {
  return {
    ...bitwardenJsonDoc,
    nodewardenFormat: 'nodewarden_json',
    nodewardenVersion: 1,
    nodewardenAttachments: attachments,
  };
}

export async function attachNodeWardenEncryptedAttachmentPayload(
  encryptedBitwardenJson: string,
  attachments: NodeWardenAttachmentRecord[],
  userEncB64: string,
  userMacB64: string
): Promise<string> {
  const parsed = JSON.parse(encryptedBitwardenJson) as Record<string, unknown>;
  const userEnc = base64ToBytes(userEncB64);
  const userMac = base64ToBytes(userMacB64);
  const payload = JSON.stringify({
    nodewardenFormat: 'nodewarden_json',
    nodewardenVersion: 1,
    nodewardenAttachments: attachments,
  });
  parsed.nodewardenFormat = 'nodewarden_json';
  parsed.nodewardenVersion = 1;
  parsed.nodewardenAttachmentsEnc = await encryptBw(new TextEncoder().encode(payload), userEnc, userMac);
  return JSON.stringify(parsed, null, 2);
}
