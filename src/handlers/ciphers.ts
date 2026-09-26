import {
  Env,
  Cipher,
  CipherCard,
  CipherIdentity,
  CipherLogin,
  CipherResponse,
  CipherSecureNote,
  CipherSshKey,
  CipherBankAccount,
  CipherDriversLicense,
  CipherPassport,
  Attachment,
  PasswordHistory,
} from '../types';
import { StorageService } from '../services/storage';
import { bumpOrganizationMembers } from '../utils/org-notify';
import { ORG_SELF_SERVICE_REGISTRATION_CONFIG_KEY, ORG_USER_STATUS, ORG_USER_TYPE } from '../config/org';
import type { CipherAccessInfo } from '../services/storage-collection-repo';
import {
  notifyUserCipherCreate,
  notifyUserCipherDelete,
  notifyUserCipherUpdate,
  notifyUserCiphersSync,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher, deleteAllAttachmentsForCiphers } from './attachments';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { readActingDeviceIdentifier } from '../utils/device';
import { stripPasswordMaterial } from '../utils/hide-password-material';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { readNullableFullUpdateField } from './cipher-full-update';

// CONTRACT:
// Cipher JSON is the highest-risk Bitwarden compatibility surface. Preserve
// unknown/future client fields by default, then override only server-owned
// fields. Any change to cipher response shape must be checked against /api/sync,
// attachments, import/export, and current official clients.
export interface CipherResponseOptions {
  preserveRepairableUris?: boolean;
  validFolderIds?: ReadonlySet<string>;
}

export function shouldPreserveRepairableCipherUris(request: Request): boolean {
  return request.headers.get('X-NodeWarden-Web') === '1';
}

function cipherResponseOptionsForRequest(request: Request): CipherResponseOptions {
  return { preserveRepairableUris: shouldPreserveRepairableCipherUris(request) };
}

interface AccessibleCipherForRequest {
  cipher: Cipher;
  /** null for personally-owned ciphers (owner = full access). */
  access: CipherAccessInfo | null;
}

// Load one cipher for an authenticated operation: personal ownership or
// confirmed organization membership. requireWrite rejects members whose
// accessible collections are all read-only.
async function loadCipherForRequest(
  storage: StorageService,
  userId: string,
  cipherId: string,
  options: { requireWrite?: boolean } = {}
): Promise<AccessibleCipherForRequest | Response> {
  const result = await storage.getAccessibleCipher(cipherId, userId);
  if (!result) return errorResponse('Cipher not found', 404);
  if (options.requireWrite && result.access && !result.access.canEdit) {
    return errorResponse('You do not have permission to modify this cipher', 403);
  }
  // Apply per-member access flags on every cipher before it reaches a
  // response, so all mutation handlers (delete/restore/archive/unarchive/
  // update/partial/share/set-collections) return the same org metadata
  // the sync endpoint produces — not just the read handlers.
  if (result.access) {
    result.cipher.collectionIds = result.access.accessibleCollectionIds;
    result.cipher.edit = result.access.canEdit;
    result.cipher.viewPassword = !result.access.hidePasswords;
  }
  // Overlay the acting user's personal filing for org ciphers (the cipher row
  // itself never stores a folder id). saveCipher guards the column, so this
  // in-memory value can never leak back into storage.
  if (result.cipher.organizationId) {
    result.cipher.folderId = await storage.getCipherUserFolder(userId, cipherId);
  }
  return result;
}

// Post-mutation sync plumbing for a single cipher: personal ciphers bump only
// the owner; organization ciphers fan out to every confirmed member.
async function finishCipherMutation(
  request: Request,
  env: Env,
  storage: StorageService,
  cipher: Cipher,
  actingUserId: string
): Promise<string> {
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
    return cipher.updatedAt;
  }
  const revisionDate = await storage.updateRevisionDate(actingUserId);
  notifyVaultSyncForRequest(request, env, actingUserId, revisionDate);
  return revisionDate;
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function normalizeResponseFolderId(folderId: unknown, validFolderIds?: ReadonlySet<string>): string | null {
  const normalized = normalizeOptionalId(folderId);
  if (!normalized) return null;
  return validFolderIds && !validFolderIds.has(normalized) ? null : normalized;
}

function readBooleanOrFallback(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback;
}

function buildCipherPermissions(passthrough: Record<string, unknown>): { delete: boolean; restore: boolean } {
  const raw = passthrough.permissions;
  const source = raw && typeof raw === 'object' && !Array.isArray(raw)
    ? raw as Record<string, unknown>
    : null;

  return {
    delete: readBooleanOrFallback(source?.delete, true),
    restore: readBooleanOrFallback(source?.restore, true),
  };
}

function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

// Push target for cipher-change notifications: the cipher owner for personal
// ciphers, otherwise the acting user. Organization ciphers additionally fan
// out to all confirmed members via bumpOrganizationMembers().
function cipherNotifyTargetUserId(cipher: Cipher, actingUserId: string): string {
  return cipher.userId ?? actingUserId;
}

function notifyCipherCreateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string,
  actingUserId: string
): void {
  notifyUserCipherCreate(env, {
    userId: cipherNotifyTargetUserId(cipher, actingUserId),
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId(cipher.organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

function notifyCipherUpdateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string,
  actingUserId: string
): void {
  notifyUserCipherUpdate(env, {
    userId: cipherNotifyTargetUserId(cipher, actingUserId),
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId(cipher.organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

function notifyCipherDeleteForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string,
  actingUserId: string
): void {
  notifyUserCipherDelete(env, {
    userId: cipherNotifyTargetUserId(cipher, actingUserId),
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId(cipher.organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

function getAliasedProp(source: any, aliases: string[]): { present: boolean; value: any } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return { present: true, value: source[key] };
    }
  }
  return { present: false, value: undefined };
}

function readCipherProp<T = unknown>(source: any, aliases: string[]): { present: boolean; value: T | undefined } {
  return getAliasedProp(source, aliases) as { present: boolean; value: T | undefined };
}

function normalizeCipherTimestamp(value: unknown): string | null {
  if (value == null || value === '') return null;
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function readCipherArchivedAt(source: any, fallback: string | null = null): string | null {
  const archived = getAliasedProp(source, ['archivedAt', 'ArchivedAt', 'archivedDate', 'ArchivedDate']);
  return archived.present ? normalizeCipherTimestamp(archived.value) : fallback;
}

function readCipherRevisionDate(source: any): string | null {
  const revision = getAliasedProp(source, ['lastKnownRevisionDate', 'LastKnownRevisionDate']);
  return revision.present ? normalizeCipherTimestamp(revision.value) : null;
}

function isStaleCipherUpdate(existingUpdatedAt: string, clientRevisionDate: string | null): boolean {
  if (!clientRevisionDate) return false;
  const existingTs = Date.parse(existingUpdatedAt);
  const clientTs = Date.parse(clientRevisionDate);
  if (Number.isNaN(existingTs) || Number.isNaN(clientTs)) return false;
  return existingTs - clientTs > 1000;
}

function syncCipherComputedAliases(cipher: Cipher): Cipher {
  cipher.archivedDate = cipher.archivedAt ?? null;
  cipher.deletedDate = cipher.deletedAt ?? null;
  return cipher;
}

async function writeCipherAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'cipher',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

export function isValidEncString(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  const dot = trimmed.indexOf('.');
  if (dot <= 0) return false;
  const type = Number(trimmed.slice(0, dot));
  if (!Number.isInteger(type) || type < 0) return false;
  const parts = trimmed.slice(dot + 1).split('|');
  if (parts.some((part) => part.length === 0)) return false;

  // Bitwarden's legacy symmetric EncString variants require IV + data,
  // while the authenticated AES-CBC-HMAC variant requires IV + data + MAC.
  // Type 4 (Rsa2048_OaepSha256_B64) carries a single base64 payload — RSA
  // ciphertext needs no IV — as used for organization key wrapping.
  if (type === 0 || type === 1) return parts.length >= 2;
  if (type === 2) return parts.length === 3;
  if (type === 4) return parts.length >= 1;

  // Keep newer one-part formats, such as COSE Encrypt0, future-compatible.
  return parts.length >= 1;
}

function optionalEncString(value: unknown): string | null {
  if (value == null || value === '') return null;
  return isValidEncString(value) ? value.trim() : null;
}

function optionalEncStringWithin(value: unknown, maxLength: number): string | null {
  const normalized = optionalEncString(value);
  if (!normalized) return null;
  return normalized.length <= maxLength ? normalized : null;
}

function shouldAcceptCipherKey(value: unknown): boolean {
  return value == null || value === '' || isValidEncString(value);
}

function normalizeCipherKeyForStorage(value: unknown): string | null {
  return optionalEncString(value);
}

function sanitizeEncryptedObject<T extends Record<string, any>>(
  source: T | null | undefined,
  encryptedKeys: readonly string[] | Record<string, number>
): T | null {
  if (!source || typeof source !== 'object') return source ?? null;
  const next: Record<string, any> = { ...source };
  const entries = Array.isArray(encryptedKeys)
    ? encryptedKeys.map((key) => [key, 10000] as const)
    : Object.entries(encryptedKeys);
  for (const [key, maxLength] of entries) {
    if (!Object.prototype.hasOwnProperty.call(next, key)) continue;
    next[key] = optionalEncStringWithin(next[key], maxLength);
  }
  return next as T;
}

const BANK_ACCOUNT_ENCRYPTED_KEYS = [
  'bankName',
  'nameOnAccount',
  'accountType',
  'accountNumber',
  'routingNumber',
  'branchNumber',
  'pin',
  'swiftCode',
  'iban',
  'bankContactPhone',
] as const;

const DRIVERS_LICENSE_ENCRYPTED_KEYS = [
  'firstName',
  'middleName',
  'lastName',
  'dateOfBirth',
  'licenseNumber',
  'issuingCountry',
  'issuingState',
  'issueDate',
  'expirationDate',
  'issuingAuthority',
  'licenseClass',
] as const;

const PASSPORT_ENCRYPTED_KEYS = [
  'surname',
  'givenName',
  'dateOfBirth',
  'sex',
  'birthPlace',
  'nationality',
  'issuingCountry',
  'passportNumber',
  'passportType',
  'nationalIdentificationNumber',
  'issuingAuthority',
  'issueDate',
  'expirationDate',
] as const;

function normalizeCipherForStorage(cipher: Cipher): Cipher {
  cipher.login = normalizeCipherLoginForStorage(cipher.login);
  cipher.sshKey = normalizeCipherSshKeyForCompatibility(cipher.sshKey);
  cipher.folderId = normalizeOptionalId(cipher.folderId);
  const hasArchivedAt = Object.prototype.hasOwnProperty.call(cipher as object, 'archivedAt');
  cipher.archivedAt = hasArchivedAt
    ? normalizeCipherTimestamp(cipher.archivedAt) ?? null
    : normalizeCipherTimestamp(cipher.archivedDate) ?? null;
  return syncCipherComputedAliases(cipher);
}

export function normalizeCipherLoginForStorage(login: any): any {
  if (!login || typeof login !== 'object') return login ?? null;
  return {
    ...login,
    fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
  };
}

export function normalizeCipherLoginForCompatibility(
  login: any,
  requiresUriChecksum: boolean = false,
  preserveRepairableUris: boolean = false
): any {
  const normalized = normalizeCipherLoginForStorage(login);
  if (!normalized || typeof normalized !== 'object') return normalized ?? null;
  const next = sanitizeEncryptedObject(normalized, {
    username: 1000,
    password: 5000,
    totp: 1000,
    uri: 10000,
  });
  if (!next) return null;
  next.uris = normalizeCipherLoginUrisForCompatibility(next.uris, {
    requiresUriChecksum,
    preserveRepairableUris,
  });
  next.fido2Credentials = normalizeFido2CredentialsForCompatibility(next.fido2Credentials);
  return next;
}

function normalizeCipherLoginUrisForCompatibility(
  uris: any,
  options: { requiresUriChecksum?: boolean; preserveRepairableUris?: boolean } = {}
): any[] | null {
  if (!Array.isArray(uris) || uris.length === 0) return null;
  const out: any[] = [];

  for (const uri of uris) {
    if (!uri || typeof uri !== 'object') continue;
    const next = sanitizeEncryptedObject(uri, ['uri', 'uriChecksum']);
    if (!next) continue;

    const hasUri = isValidEncString(next.uri);
    const hasChecksum = isValidEncString(next.uriChecksum);
    const hasMatch = next.match != null;

    if (hasUri && String(next.uri).trim().length > 10000) continue;
    if (hasChecksum && String(next.uriChecksum).trim().length > 10000) {
      next.uriChecksum = null;
    }

    if (hasUri && isValidEncString(next.uriChecksum)) {
      out.push(next);
      continue;
    }

    if (hasUri && !hasChecksum) {
      // Official Bitwarden treats UriChecksum as nullable encrypted metadata.
      // Keep the URI intact and let clients that can repair checksums do so.
      out.push({ ...next, uriChecksum: null });
      continue;
    }

    if (hasChecksum || hasMatch) {
      out.push(next);
    }
  }

  return out.length ? out : null;
}

export function validateCipherEncryptedFieldsForCompatibility(cipher: Cipher): string | null {
  if (cipher.name != null && !optionalEncStringWithin(cipher.name, 1000)) return 'Cipher name must be an encrypted string up to 1000 characters.';
  if (cipher.notes != null && !optionalEncStringWithin(cipher.notes, 10000)) return 'Cipher notes must be an encrypted string up to 10000 characters.';

  const login = cipher.login as any;
  if (login && typeof login === 'object') {
    if (login.username != null && !optionalEncStringWithin(login.username, 1000)) return 'Login username must be an encrypted string up to 1000 characters.';
    if (login.password != null && !optionalEncStringWithin(login.password, 5000)) return 'Login password must be an encrypted string up to 5000 characters.';
    if (login.totp != null && !optionalEncStringWithin(login.totp, 1000)) return 'Login TOTP must be an encrypted string up to 1000 characters.';
    if (login.uri != null && !optionalEncStringWithin(login.uri, 10000)) return 'Login URI must be an encrypted string up to 10000 characters.';

    if (Array.isArray(login.uris)) {
      for (const uri of login.uris) {
        if (!uri || typeof uri !== 'object') continue;
        if (uri.uri != null && !optionalEncStringWithin(uri.uri, 10000)) return 'Login URI must be an encrypted string up to 10000 characters.';
        if (uri.uriChecksum != null && !optionalEncStringWithin(uri.uriChecksum, 10000)) return 'Login URI checksum must be an encrypted string up to 10000 characters.';
      }
    }

    // Validate FIDO2 credentials — all encrypted-string fields, both required and optional, must be valid.
    if (Array.isArray(login.fido2Credentials)) {
      const fido2EncryptedKeys = ['credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable', 'userHandle', 'userName', 'rpName', 'userDisplayName'];
      for (const cred of login.fido2Credentials) {
        if (!cred || typeof cred !== 'object') continue;
        for (const key of fido2EncryptedKeys) {
          if (cred[key] != null && !isValidEncString(cred[key])) return `FIDO2 credential ${key} must be an encrypted string.`;
        }
      }
    }
  }

  // Validate SSH key fields — all three must be encrypted strings.
  const sshKey = cipher.sshKey as any;
  if (sshKey && typeof sshKey === 'object') {
    if (sshKey.privateKey != null && !isValidEncString(sshKey.privateKey)) return 'SSH key private key must be an encrypted string.';
    if (sshKey.publicKey != null && !isValidEncString(sshKey.publicKey)) return 'SSH key public key must be an encrypted string.';
    const fingerprint = sshKey.keyFingerprint ?? sshKey.fingerprint;
    if (fingerprint != null && !isValidEncString(fingerprint)) return 'SSH key fingerprint must be an encrypted string.';
  }

  const typedEncryptedObjects: Array<[string, any, readonly string[]]> = [
    ['Bank account', (cipher as any).bankAccount, BANK_ACCOUNT_ENCRYPTED_KEYS],
    ['Drivers license', (cipher as any).driversLicense, DRIVERS_LICENSE_ENCRYPTED_KEYS],
    ['Passport', (cipher as any).passport, PASSPORT_ENCRYPTED_KEYS],
  ];
  for (const [label, source, keys] of typedEncryptedObjects) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      if (source[key] != null && !optionalEncStringWithin(source[key], 10000)) {
        return `${label} ${key} must be an encrypted string.`;
      }
    }
  }

  // Validate password history — each password must be an encrypted string.
  if (Array.isArray(cipher.passwordHistory)) {
    for (const entry of cipher.passwordHistory) {
      if (!entry || typeof entry !== 'object') continue;
      if (entry.password != null && !isValidEncString(entry.password)) return 'Password history entry must be an encrypted string.';
    }
  }

  return null;
}

function normalizeFido2CredentialsForCompatibility(credentials: any): any[] | null {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const requiredEncryptedKeys = [
    'credentialId',
    'keyType',
    'keyAlgorithm',
    'keyCurve',
    'keyValue',
    'rpId',
    'counter',
    'discoverable',
  ];
  const optionalEncryptedKeys = ['userHandle', 'userName', 'rpName', 'userDisplayName'];
  const out: any[] = [];

  for (const credential of credentials) {
    if (!credential || typeof credential !== 'object') continue;
    const next: Record<string, any> = { ...credential };
    let valid = true;
    for (const key of requiredEncryptedKeys) {
      if (!isValidEncString(next[key])) {
        valid = false;
        break;
      }
      next[key] = String(next[key]).trim();
    }
    if (!valid) continue;
    for (const key of optionalEncryptedKeys) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        next[key] = optionalEncString(next[key]);
      }
    }
    out.push(next);
  }

  return out.length ? out : null;
}

// Android 2026.2.0 requires sshKey.keyFingerprint in sync payloads.
// Keep legacy alias "fingerprint" in parallel for older web payloads.
export function normalizeCipherSshKeyForCompatibility(sshKey: any): any {
  if (!sshKey || typeof sshKey !== 'object') return sshKey ?? null;

  const candidate =
    sshKey.keyFingerprint !== undefined && sshKey.keyFingerprint !== null
      ? sshKey.keyFingerprint
      : sshKey.fingerprint;

  const normalizedFingerprint =
    candidate === undefined || candidate === null
      ? ''
      : String(candidate);

  if (
    !isValidEncString(sshKey.privateKey) ||
    !isValidEncString(sshKey.publicKey) ||
    !isValidEncString(normalizedFingerprint)
  ) {
    return null;
  }

  return {
    ...sshKey,
    privateKey: String(sshKey.privateKey).trim(),
    publicKey: String(sshKey.publicKey).trim(),
    keyFingerprint: normalizedFingerprint,
    fingerprint: normalizedFingerprint,
  };
}

function normalizeCipherSecureNoteForCompatibility(secureNote: any): CipherSecureNote | null {
  if (!secureNote || typeof secureNote !== 'object') return null;
  const type = Number(secureNote?.type ?? secureNote?.Type ?? 0);
  return {
    type: Number.isFinite(type) ? type : 0,
  };
}

// Format attachments for API response
export function formatAttachments(attachments: Attachment[]): any[] | null {
  if (attachments.length === 0) return null;
  const formatted = attachments
    .filter((a) => isValidEncString(a.fileName))
    .map(a => ({
      id: a.id,
      fileName: a.fileName.trim(),
      // Bitwarden clients decode attachment size as string in cipher payloads.
      size: String(Number(a.size) || 0),
      sizeName: a.sizeName,
      key: optionalEncString(a.key),
      url: `/api/ciphers/${a.cipherId}/attachment/${a.id}`,  // Android requires non-null url!
      object: 'attachment',
    }));
  return formatted.length ? formatted : null;
}

function formatAttachmentSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface IncomingAttachmentMetadata {
  id: string;
  fileName?: unknown;
  key?: unknown;
  fileSize?: unknown;
  hasFileName: boolean;
  hasKey: boolean;
  hasFileSize: boolean;
}

function readIncomingAttachmentMetadataMap(
  value: unknown,
  options: { legacyFileNameMap?: boolean } = {}
): IncomingAttachmentMetadata[] {
  if (!value || typeof value !== 'object') return [];
  const out: IncomingAttachmentMetadata[] = [];

  if (Array.isArray(value)) {
    for (const item of value) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const id = String(row.id ?? row.Id ?? '').trim();
      if (!id) continue;
      const fileName = getAliasedProp(row, ['fileName', 'FileName']);
      const key = getAliasedProp(row, ['key', 'Key']);
      const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
      out.push({
        id,
        fileName: fileName.value,
        key: key.value,
        fileSize: fileSize.value,
        hasFileName: fileName.present,
        hasKey: key.present,
        hasFileSize: fileSize.present,
      });
    }
    return out;
  }

  for (const [rawId, rawValue] of Object.entries(value as Record<string, unknown>)) {
    const id = String(rawId || '').trim();
    if (!id) continue;

    if (options.legacyFileNameMap && (typeof rawValue === 'string' || rawValue == null)) {
      out.push({
        id,
        fileName: rawValue,
        key: undefined,
        fileSize: undefined,
        hasFileName: rawValue != null,
        hasKey: false,
        hasFileSize: false,
      });
      continue;
    }

    if (!rawValue || typeof rawValue !== 'object') continue;
    const row = rawValue as Record<string, unknown>;
    const fileName = getAliasedProp(row, ['fileName', 'FileName']);
    const key = getAliasedProp(row, ['key', 'Key']);
    const fileSize = getAliasedProp(row, ['fileSize', 'FileSize', 'size', 'Size']);
    out.push({
      id,
      fileName: fileName.value,
      key: key.value,
      fileSize: fileSize.value,
      hasFileName: fileName.present,
      hasKey: key.present,
      hasFileSize: fileSize.present,
    });
  }

  return out;
}

function readIncomingAttachmentMetadata(source: any): IncomingAttachmentMetadata[] {
  const merged = new Map<string, IncomingAttachmentMetadata>();
  const legacy = getAliasedProp(source, ['attachments', 'Attachments']);
  const current = getAliasedProp(source, ['attachments2', 'Attachments2']);

  if (legacy.present) {
    for (const item of readIncomingAttachmentMetadataMap(legacy.value, { legacyFileNameMap: true })) {
      merged.set(item.id, item);
    }
  }

  if (current.present) {
    for (const item of readIncomingAttachmentMetadataMap(current.value)) {
      const previous = merged.get(item.id);
      merged.set(item.id, {
        id: item.id,
        fileName: item.hasFileName ? item.fileName : previous?.fileName,
        key: item.hasKey ? item.key : previous?.key,
        fileSize: item.hasFileSize ? item.fileSize : previous?.fileSize,
        hasFileName: item.hasFileName || previous?.hasFileName || false,
        hasKey: item.hasKey || previous?.hasKey || false,
        hasFileSize: item.hasFileSize || previous?.hasFileSize || false,
      });
    }
  }

  return [...merged.values()];
}

function hasIncomingAttachmentMetadata(source: any): boolean {
  return readIncomingAttachmentMetadata(source).length > 0;
}

async function syncIncomingAttachmentMetadata(
  storage: StorageService,
  cipherId: string,
  cipherData: any
): Promise<void> {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length) return;

  const currentById = new Map((await storage.getAttachmentsByCipher(cipherId)).map((attachment) => [attachment.id, attachment]));
  for (const item of incoming) {
    const attachment = currentById.get(item.id);
    if (!attachment) continue;

    let changed = false;
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName) && fileName !== attachment.fileName) {
        attachment.fileName = fileName;
        changed = true;
      }
    }

    if (item.hasKey) {
      const key = optionalEncString(item.key);
      if (key !== attachment.key) {
        attachment.key = key;
        changed = true;
      }
    }

    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0 && size !== Number(attachment.size || 0)) {
        attachment.size = size;
        attachment.sizeName = formatAttachmentSize(size);
        changed = true;
      }
    }

    if (changed) {
      await storage.saveAttachment(attachment);
    }
  }
}

export function applyCipherEmbeddedAttachmentMetadata(cipherData: any, attachments: Attachment[]): Attachment[] {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length || !attachments.length) return attachments;

  const incomingById = new Map(incoming.map((item) => [item.id, item]));
  return attachments.map((attachment) => {
    const item = incomingById.get(attachment.id);
    if (!item) return attachment;

    const next: Attachment = { ...attachment };
    if (item.hasFileName) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName)) {
        next.fileName = fileName;
      }
    }
    if (item.hasKey) {
      next.key = optionalEncString(item.key);
    }
    if (item.hasFileSize) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0) {
        next.size = size;
        next.sizeName = formatAttachmentSize(size);
      }
    }
    return next;
  });
}

function normalizeCipherFieldsForCompatibility(fields: any): any[] | null {
  if (!Array.isArray(fields) || fields.length === 0) return null;
  const out = fields
    .map((field: any) => {
      if (!field || typeof field !== 'object') return null;
      return {
        ...field,
        name: optionalEncString(field.name),
        value: optionalEncString(field.value),
        type: Number(field.type) || 0,
        linkedId: field.linkedId ?? null,
      };
    })
    .filter(Boolean);
  return out.length ? out : null;
}

function normalizePasswordHistoryForCompatibility(passwordHistory: any): PasswordHistory[] | null {
  if (!Array.isArray(passwordHistory) || passwordHistory.length === 0) return null;
  const out = passwordHistory
    .filter((entry: any) => entry && typeof entry === 'object' && isValidEncString(entry.password))
    .map((entry: any) => ({
      ...entry,
      password: String(entry.password).trim(),
      lastUsedDate: normalizeCipherTimestamp(entry.lastUsedDate) ?? new Date().toISOString(),
    }));
  return out.length ? out : null;
}

export function isCipherResponseSyncCompatible(cipher: CipherResponse): boolean {
  return isValidEncString(cipher.name);
}

// Convert internal cipher to API response format.
// Uses opaque passthrough: spreads ALL stored fields (including unknown/future ones),
// then overlays server-computed fields. This ensures new Bitwarden client fields
// survive a round-trip without code changes.
export function cipherToResponse(
  cipher: Cipher,
  attachments: Attachment[] = [],
  options: CipherResponseOptions = {}
): CipherResponse {
  // Strip internal-only fields that must not appear in the API response
  const { userId, createdAt, updatedAt, archivedAt, deletedAt, ...passthrough } = cipher;
  const responseCipherKey = optionalEncString(cipher.key);
  const normalizedLogin = normalizeCipherLoginForCompatibility(
    (passthrough as any).login ?? null,
    !!responseCipherKey,
    !!options.preserveRepairableUris
  );
  const normalizedCard = sanitizeEncryptedObject((passthrough as any).card ?? null, {
    cardholderName: 1000,
    brand: 1000,
    number: 1000,
    expMonth: 1000,
    expYear: 1000,
    code: 1000,
  });
  const normalizedIdentity = sanitizeEncryptedObject((passthrough as any).identity ?? null, [
    'title',
    'firstName',
    'middleName',
    'lastName',
    'address1',
    'address2',
    'address3',
    'city',
    'state',
    'postalCode',
    'country',
    'company',
    'email',
    'phone',
    'ssn',
    'username',
    'passportNumber',
    'licenseNumber',
  ]);
  const normalizedSshKey = normalizeCipherSshKeyForCompatibility((passthrough as any).sshKey ?? null);
  const normalizedBankAccount = sanitizeEncryptedObject(
    (passthrough as any).bankAccount ?? null,
    BANK_ACCOUNT_ENCRYPTED_KEYS
  );
  const normalizedDriversLicense = sanitizeEncryptedObject(
    (passthrough as any).driversLicense ?? null,
    DRIVERS_LICENSE_ENCRYPTED_KEYS
  );
  const normalizedPassport = sanitizeEncryptedObject(
    (passthrough as any).passport ?? null,
    PASSPORT_ENCRYPTED_KEYS
  );
  const responseType = Number(cipher.type) || 1;
  const normalizedSecureNote = responseType === 2
    ? normalizeCipherSecureNoteForCompatibility((passthrough as any).secureNote ?? null) ?? { type: 0 }
    : null;
  const responseAttachments = applyCipherEmbeddedAttachmentMetadata(cipher, attachments);
  const responsePermissions = buildCipherPermissions(passthrough);

  // Server-side hide-passwords enforcement: when the owner marked this
  // member's accessible collections as hide-passwords, strip the encrypted
  // material before it leaves the server. The member holds the org key (it
  // is wrapped to their public key), so delivering the ciphertext would let
  // them decrypt everything the owner tried to restrict. The viewPassword
  // flag alone is advisory — clients may ignore it. The strip covers every
  // password-bearing field across all cipher types (see the pure util — it
  // is extracted so the behaviour is testable outside the runtime).
  const responseViewPassword = readBooleanOrFallback((passthrough as any).viewPassword, true);
  const normalizedFields = normalizeCipherFieldsForCompatibility((passthrough as any).fields);
  const normalizedPasswordHistory = normalizePasswordHistoryForCompatibility((passthrough as any).passwordHistory);
  const responseStripped = !responseViewPassword
    ? stripPasswordMaterial({
        login: normalizedLogin as any,
        card: normalizedCard as any,
        identity: normalizedIdentity as any,
        sshKey: normalizedSshKey as any,
        bankAccount: normalizedBankAccount as any,
        driversLicense: normalizedDriversLicense as any,
        passport: normalizedPassport as any,
        fields: normalizedFields as any,
        passwordHistory: normalizedPasswordHistory as any,
      })
    : null;
  const responseLogin = (responseStripped?.login ?? normalizedLogin) as any;
  const responseCard = responseStripped?.card ?? normalizedCard;
  const responseIdentity = responseStripped?.identity ?? normalizedIdentity;
  const responseFields = (responseStripped?.fields ?? normalizedFields) as any;
  const responsePasswordHistory = responseStripped ? null : normalizedPasswordHistory;
  const responseSshKey = responseStripped?.sshKey ?? normalizedSshKey;
  const responseBankAccount = responseType === 6 ? (responseStripped?.bankAccount ?? normalizedBankAccount) : null;
  const responseDriversLicense = responseType === 7 ? (responseStripped?.driversLicense ?? normalizedDriversLicense) : null;
  const responsePassport = responseType === 8 ? (responseStripped?.passport ?? normalizedPassport) : null;

  return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    // Org ciphers report the acting user's personal filing through the
    // standard folderId field (overlaid at load/sync time); the mapping is
    // per-user so every member files shared items into their own folders.
    folderId: normalizeResponseFolderId(cipher.folderId, options.validFolderIds),
    type: responseType,
    organizationId: normalizeOptionalId((passthrough as any).organizationId ?? null),
    organizationUseTotp: !!((passthrough as any).organizationUseTotp ?? false),
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: archivedAt ?? null,
    edit: readBooleanOrFallback((passthrough as any).edit, true),
    viewPassword: responseViewPassword,
    permissions: responsePermissions,
    object: 'cipherDetails',
    collectionIds: Array.isArray((passthrough as any).collectionIds) ? (passthrough as any).collectionIds : [],
    attachments: formatAttachments(responseAttachments),
    name: isValidEncString(cipher.name) ? cipher.name.trim() : cipher.name,
    notes: optionalEncString(cipher.notes),
    login: responseLogin,
    card: responseCard,
    identity: responseIdentity,
    secureNote: normalizedSecureNote,
    fields: responseFields,
    passwordHistory: responsePasswordHistory,
    sshKey: responseSshKey,
    bankAccount: responseBankAccount,
    driversLicense: responseDriversLicense,
    passport: responsePassport,
    key: responseCipherKey,
    data: typeof (passthrough as any).data === 'string' ? (passthrough as any).data : null,
    encryptedFor: (passthrough as any).encryptedFor ?? null,
  };
}

// GET /api/ciphers
export async function handleGetCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const includeDeleted = url.searchParams.get('deleted') === 'true';
  const pagination = parsePagination(url);

  let filteredCiphers: Cipher[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getCiphersPage(
      userId,
      includeDeleted,
      pagination.limit + 1,
      pagination.offset
    );
    const hasNext = pageRows.length > pagination.limit;
    filteredCiphers = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + filteredCiphers.length) : null;
  } else {
    const ciphers = await storage.getAllCiphersIncludingOrgs(userId);
    filteredCiphers = includeDeleted
      ? ciphers
      : ciphers.filter(c => !c.deletedAt);
  }

  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(
    filteredCiphers.map((cipher) => cipher.id)
  );
  const validFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));

  // Build responses only for the current page to keep pagination cheap.
  const responseOptions = { ...cipherResponseOptionsForRequest(request), validFolderIds };
  const cipherResponses: CipherResponse[] = [];
  for (const cipher of filteredCiphers) {
    const attachments = attachmentsByCipher.get(cipher.id) || [];
    cipherResponses.push(cipherToResponse(cipher, attachments, responseOptions));
  }

  return jsonResponse({
    data: cipherResponses,
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/ciphers/:id
export async function handleGetCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id);
  if (loaded instanceof Response) return loaded;
  const { cipher } = loaded;

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  const responseOptions = cipherResponseOptionsForRequest(request);
  return jsonResponse(
    cipherToResponse(cipher, attachments, responseOptions)
  );
}

async function verifyFolderOwnership(storage: StorageService, folderId: string | null | undefined, userId: string): Promise<boolean> {
  if (!folderId) return true;
  const folder = await storage.getFolderForUser(folderId, userId);
  return !!folder;
}

// POST /api/ciphers
export async function handleCreateCipher(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object (from some clients)
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;
  const createFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const createKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const createLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const createCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const createIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const createSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const createSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const createBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const createDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const createPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const createPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);

  if (createKey.present && !shouldAcceptCipherKey(createKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  const now = new Date().toISOString();
  // Opaque passthrough: spread ALL client fields to preserve unknown/future ones,
  // then override only server-controlled fields.
  const cipher: Cipher = {
    ...cipherData,
    // Server-controlled fields (always override client values)
    id: generateUUID(),
    userId: userId,
    type: Number(cipherData.type) || 1,
    favorite: !!cipherData.favorite,
    reprompt: cipherData.reprompt || 0,
    createdAt: now,
    updatedAt: now,
    archivedAt: readCipherArchivedAt(cipherData, null),
    deletedAt: null,
  };
  cipher.folderId = createFolderId.present ? normalizeOptionalId(createFolderId.value) : normalizeOptionalId(cipher.folderId);
  cipher.key = normalizeCipherKeyForStorage(createKey.present ? createKey.value : cipher.key);
  cipher.login = createLogin.present ? (createLogin.value ?? null) : (cipher.login ?? null);
  cipher.card = createCard.present ? (createCard.value ?? null) : (cipher.card ?? null);
  cipher.identity = createIdentity.present ? (createIdentity.value ?? null) : (cipher.identity ?? null);
  cipher.secureNote = createSecureNote.present ? (createSecureNote.value ?? null) : (cipher.secureNote ?? null);
  cipher.sshKey = createSshKey.present ? (createSshKey.value ?? null) : (cipher.sshKey ?? null);
  cipher.bankAccount = createBankAccount.present ? (createBankAccount.value ?? null) : ((cipher as any).bankAccount ?? null);
  cipher.driversLicense = createDriversLicense.present ? (createDriversLicense.value ?? null) : ((cipher as any).driversLicense ?? null);
  cipher.passport = createPassport.present ? (createPassport.value ?? null) : ((cipher as any).passport ?? null);
  cipher.passwordHistory = createPasswordHistory.present ? (createPasswordHistory.value ?? null) : (cipher.passwordHistory ?? null);
  const createFields = getAliasedProp(cipherData, ['fields', 'Fields']);
  cipher.fields = createFields.present ? (createFields.value ?? null) : (cipher.fields ?? null);
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  // Organization ciphers: created directly inside an org by confirmed members.
  const createOrganizationId = normalizeOptionalId(
    getAliasedProp(cipherData, ['organizationId', 'OrganizationId']).value
  );
  if (createOrganizationId) {
    const membership = await storage.getOrganizationUserForUser(createOrganizationId, userId);
    if (!membership || membership.status !== ORG_USER_STATUS.CONFIRMED) {
      return errorResponse('Organization not found', 404);
    }

    const rawCollectionIds = getAliasedProp(cipherData, ['collectionIds', 'CollectionIds']).value;
    const createCollectionIds = Array.isArray(rawCollectionIds)
      ? Array.from(new Set(rawCollectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)))
      : [];

    if (!createCollectionIds.length) {
      return errorResponse('At least one collection is required to create an organization cipher', 400);
    }

    const collections = await storage.getCollectionsByIds(createCollectionIds);
    const validIds = new Set(collections.filter((c) => c.organizationId === createOrganizationId).map((c) => c.id));
    for (const collectionId of createCollectionIds) {
      if (!validIds.has(collectionId)) {
        return errorResponse(`Collection ${collectionId} does not belong to this organization`, 400);
      }
    }

    if (!membership.accessAll) {
      // Members without accessAll must have edit access to every target collection.
      const editableIds = new Set(
        (await storage.listCollectionUsersByOrganizationUser(membership.id))
          .filter((row) => !row.readOnly)
          .map((row) => row.collectionId)
      );
      for (const collectionId of createCollectionIds) {
        if (!editableIds.has(collectionId)) {
          return errorResponse('You do not have permission to add ciphers to these collections', 403);
        }
      }
    }

    // Org-cipher filing: the payload folderId references one of the acting
    // user's own personal folders; it is stored per-user, not on the row.
    let createCipherFolderId: string | null = null;
    if (cipher.folderId) {
      const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
      if (!folderOk) return errorResponse('Folder not found', 404);
      createCipherFolderId = cipher.folderId;
    }

    cipher.userId = null;
    cipher.organizationId = createOrganizationId;
    cipher.folderId = createCipherFolderId;
    cipher.collectionIds = createCollectionIds;
    await storage.saveCipher(cipher);
    if (createCipherFolderId) {
      await storage.setCipherUserFolder(userId, cipher.id, createCipherFolderId);
    }
    await storage.setCipherCollections(cipher.id, createCollectionIds);
    await bumpOrganizationMembers(request, env, storage, createOrganizationId);
    notifyCipherCreateForRequest(request, env, cipher, cipher.updatedAt, userId);
    return jsonResponse(
      cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request)),
      200
    );
  }

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await storage.saveCipher(cipher);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyCipherCreateForRequest(request, env, cipher, revisionDate, userId);
  const responseOptions = cipherResponseOptionsForRequest(request);

  return jsonResponse(
    cipherToResponse(cipher, [], responseOptions),
    200
  );
}

// PUT /api/ciphers/:id
export async function handleUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const existingCipher = loaded.cipher;

  let body: any;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Handle nested cipher object
  // Android client sends PascalCase "Cipher" for organization ciphers
  const cipherData = body.Cipher || body.cipher || body;
  const incomingFolderId = readCipherProp<string | null>(cipherData, ['folderId', 'FolderId']);
  const incomingKey = readCipherProp<string | null>(cipherData, ['key', 'Key']);
  const incomingLogin = readCipherProp<CipherLogin | null>(cipherData, ['login', 'Login']);
  const incomingCard = readCipherProp<CipherCard | null>(cipherData, ['card', 'Card']);
  const incomingIdentity = readCipherProp<CipherIdentity | null>(cipherData, ['identity', 'Identity']);
  const incomingSecureNote = readCipherProp<CipherSecureNote | null>(cipherData, ['secureNote', 'SecureNote']);
  const incomingSshKey = readCipherProp<CipherSshKey | null>(cipherData, ['sshKey', 'SshKey']);
  const incomingBankAccount = readCipherProp<CipherBankAccount | null>(cipherData, ['bankAccount', 'BankAccount']);
  const incomingDriversLicense = readCipherProp<CipherDriversLicense | null>(cipherData, ['driversLicense', 'DriversLicense']);
  const incomingPassport = readCipherProp<CipherPassport | null>(cipherData, ['passport', 'Passport']);
  const incomingPasswordHistory = readCipherProp<PasswordHistory[] | null>(cipherData, ['passwordHistory', 'PasswordHistory']);
  const incomingRevisionDate = readCipherRevisionDate(cipherData);
  const hasAttachmentMigrationMetadata = hasIncomingAttachmentMetadata(cipherData);
  const preserveRevisionDate =
    shouldPreserveRepairableCipherUris(request)
    && (body.preserveRevisionDate === true || cipherData.preserveRevisionDate === true);

  if (incomingKey.present && !shouldAcceptCipherKey(incomingKey.value)) {
    return errorResponse('Cipher key encryption is not supported by this server. Resync the client and try again.', 400);
  }

  if (!hasAttachmentMigrationMetadata && isStaleCipherUpdate(existingCipher.updatedAt, incomingRevisionDate)) {
    return errorResponse('The client copy of this cipher is out of date. Resync the client and try again.', 400);
  }

  const nextType = Number(cipherData.type) || existingCipher.type;

  // Opaque passthrough: merge existing stored data with ALL incoming client fields.
  // Unknown/future fields from the client are preserved; server-controlled fields are protected.
  const { preserveRevisionDate: _preserveRevisionDate, PreserveRevisionDate: _pascalPreserveRevisionDate, ...cipherDataWithoutFlags } = cipherData;
  const cipher: Cipher = {
    ...existingCipher,   // start with all existing stored data (including unknowns)
    ...cipherDataWithoutFlags, // overlay all client data (including new/unknown fields)
    // Server-controlled fields (never from client)
    id: existingCipher.id,
    userId: existingCipher.userId,
    organizationId: existingCipher.organizationId ?? null,
    type: nextType,
    favorite: cipherData.favorite ?? existingCipher.favorite,
    reprompt: cipherData.reprompt ?? existingCipher.reprompt,
    createdAt: existingCipher.createdAt,
    updatedAt: preserveRevisionDate ? existingCipher.updatedAt : new Date().toISOString(),
    archivedAt: readCipherArchivedAt(cipherData, existingCipher.archivedAt ?? null),
    deletedAt: existingCipher.deletedAt,
  };
  if (incomingFolderId.present) {
    cipher.folderId = normalizeOptionalId(incomingFolderId.value);
  }
  // Org ciphers file into the ACTING USER's personal folders via a per-user
  // mapping; the cipher row's folder_id column stays null (saveCipher guards
  // it). An omitted folderId keeps the existing filing.
  cipher.organizationFolderId = null;
  if (existingCipher.organizationId) {
    if (incomingFolderId.present) {
      const requestedFolderId = normalizeOptionalId(incomingFolderId.value);
      if (requestedFolderId) {
        const folderOk = await verifyFolderOwnership(storage, requestedFolderId, userId);
        if (!folderOk) return errorResponse('Folder not found', 404);
        await storage.setCipherUserFolder(userId, cipher.id, requestedFolderId);
        cipher.folderId = requestedFolderId;
      } else {
        await storage.setCipherUserFolder(userId, cipher.id, null);
        cipher.folderId = null;
      }
    } else {
      cipher.folderId = await storage.getCipherUserFolder(userId, cipher.id);
    }
  }
  if (incomingKey.present) {
    const normalizedIncomingKey = normalizeCipherKeyForStorage(incomingKey.value);
    cipher.key = normalizedIncomingKey || normalizeCipherKeyForStorage(existingCipher.key);
  } else {
    cipher.key = normalizeCipherKeyForStorage(existingCipher.key);
  }
  cipher.login = nextType === 1 ? (incomingLogin.present ? (incomingLogin.value ?? null) : (existingCipher.login ?? null)) : null;
  cipher.secureNote = nextType === 2 ? (incomingSecureNote.present ? (incomingSecureNote.value ?? null) : (existingCipher.secureNote ?? null)) : null;
  cipher.card = nextType === 3 ? (incomingCard.present ? (incomingCard.value ?? null) : (existingCipher.card ?? null)) : null;
  cipher.identity = nextType === 4 ? (incomingIdentity.present ? (incomingIdentity.value ?? null) : (existingCipher.identity ?? null)) : null;
  cipher.sshKey = nextType === 5 ? (incomingSshKey.present ? (incomingSshKey.value ?? null) : (existingCipher.sshKey ?? null)) : null;
  cipher.bankAccount = nextType === 6 ? (incomingBankAccount.present ? (incomingBankAccount.value ?? null) : ((existingCipher as any).bankAccount ?? null)) : null;
  cipher.driversLicense = nextType === 7 ? (incomingDriversLicense.present ? (incomingDriversLicense.value ?? null) : ((existingCipher as any).driversLicense ?? null)) : null;
  cipher.passport = nextType === 8 ? (incomingPassport.present ? (incomingPassport.value ?? null) : ((existingCipher as any).passport ?? null)) : null;
  if (incomingPasswordHistory.present) {
    cipher.passwordHistory = incomingPasswordHistory.value ?? null;
  }

  // Nullable fields use replacement semantics on this full-update endpoint.
  // Some clients omit cleared values, so merge fallback must not resurrect them.
  cipher.notes = readNullableFullUpdateField<string>(cipherData, ['notes', 'Notes']);
  cipher.fields = readNullableFullUpdateField<Cipher['fields']>(cipherData, ['fields', 'Fields']);
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(storage, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await syncIncomingAttachmentMetadata(storage, cipher.id, cipherData);
  await storage.saveCipher(cipher);
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  } else {
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyCipherUpdateForRequest(request, env, cipher, revisionDate, userId);
  }
  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  const responseOptions = cipherResponseOptionsForRequest(request);

  return jsonResponse(
    cipherToResponse(cipher, attachments, responseOptions)
  );
}

// DELETE /api/ciphers/:id
export async function handleDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  // Soft delete
  cipher.deletedAt = new Date().toISOString();
  cipher.updatedAt = cipher.deletedAt;
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
  notifyCipherDeleteForRequest(request, env, cipher, revisionDate, userId);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.soft', {
    id: cipher.id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// DELETE /api/ciphers/:id (compat mode)
// Bitwarden clients may call DELETE on a trashed item to purge it permanently.
// For compatibility:
// - If item is active -> soft delete.
// - If item is already soft-deleted -> hard delete.
export async function handleDeleteCipherCompat(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  if (cipher.deletedAt) {
    await deleteAllAttachmentsForCipher(env, id);
    if (cipher.organizationId) {
      await storage.deleteCiphersByIds([id]);
    } else {
      await storage.deleteCipher(id, userId);
    }
    const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
    notifyCipherDeleteForRequest(request, env, cipher, revisionDate, userId);
    await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent', {
      id,
      type: cipher.type,
      folderId: cipher.folderId ?? null,
      compat: true,
    });
    return new Response(null, { status: 204 });
  }

  return handleDeleteCipher(request, env, userId, id);
}

// DELETE /api/ciphers/:id (permanent)
export async function handlePermanentDeleteCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  // Delete all attachments first
  await deleteAllAttachmentsForCipher(env, id);

  if (cipher.organizationId) {
    await storage.deleteCiphersByIds([id]);
  } else {
    await storage.deleteCipher(id, userId);
  }
  const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
  notifyCipherDeleteForRequest(request, env, cipher, revisionDate, userId);
  await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent', {
    id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/:id/restore
export async function handleRestoreCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  cipher.deletedAt = null;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
  if (!cipher.organizationId) {
    notifyCipherUpdateForRequest(request, env, cipher, revisionDate, userId);
  }

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// PUT /api/ciphers/:id/partial - Update only favorite/folderId
export async function handlePartialUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  let body: { folderId?: string | null; favorite?: boolean };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  // Folder moves: both personal and org ciphers file into the acting user's
  // own folders. Personal rows store folder_id directly; org rows use the
  // per-user cipher_user_folders mapping. Favorite state is honored for both.
  if (body.folderId !== undefined) {
    const folderId = normalizeOptionalId(body.folderId);
    if (folderId) {
      const folderOk = await verifyFolderOwnership(storage, folderId, userId);
      if (!folderOk) return errorResponse('Folder not found', 404);
    }
    if (cipher.organizationId) {
      await storage.setCipherUserFolder(userId, cipher.id, folderId);
    }
    cipher.folderId = folderId;
  }
  if (body.favorite !== undefined) {
    cipher.favorite = body.favorite;
  }
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);

  await storage.saveCipher(cipher);
  const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
  if (!cipher.organizationId) {
    notifyCipherUpdateForRequest(request, env, cipher, revisionDate, userId);
  }
  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// POST/PUT /api/ciphers/move - Bulk move to folder
export async function handleBulkMoveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[]; folderId?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const folderId = normalizeOptionalId(body.folderId);

  // Both namespaces file into the acting user's own folders, so one target
  // folder works for mixed selections: personal rows move via the
  // user_id-scoped bulk update; org rows use the per-user mapping. Each
  // cipher is loaded once (authz + write rights).
  if (folderId) {
    const folderOk = await verifyFolderOwnership(storage, folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }
  const personalIds: string[] = [];
  const orgIds: string[] = [];
  const seen = new Set<string>();
  for (const rawId of body.ids) {
    const id = String(rawId || '').trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
    if (loaded instanceof Response) return loaded;
    if (loaded.cipher.organizationId) orgIds.push(id);
    else personalIds.push(id);
  }

  if (personalIds.length) {
    const revisionDate = await storage.bulkMoveCiphers(personalIds, folderId, userId);
    if (revisionDate) {
      notifyVaultSyncForRequest(request, env, userId, revisionDate);
    }
  }

  if (orgIds.length) {
    // Per-user filing: only the acting user's view changes, so only their
    // revision needs a bump.
    await storage.bulkSetCipherUserFolders(userId, orgIds, folderId);
    const revisionDate = await storage.updateRevisionDate(userId);
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
  }

  return new Response(null, { status: 204 });
}

async function buildCipherListResponse(
  request: Request,
  storage: StorageService,
  userId: string,
  ids: string[]
): Promise<Response> {
  const loaded = await storage.listAccessibleCiphersByIds(userId, ids);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(loaded.map((item) => item.cipher.id));
  // Overlay the acting user's per-user filing for org ciphers (matches sync).
  const folderAssignments = new Map(
    (await storage.listCipherUserFolders(userId)).map((row) => [row.cipherId, row.folderId])
  );
  for (const item of loaded) {
    if (item.cipher.organizationId) {
      item.cipher.folderId = folderAssignments.get(item.cipher.id) ?? null;
    }
  }

  return jsonResponse({
    data: loaded.map((item) => {
      // Apply per-member org flags so the list response matches sync.
      if (item.access) {
        item.cipher.collectionIds = item.access.accessibleCollectionIds;
        item.cipher.edit = item.access.canEdit;
        item.cipher.viewPassword = !item.access.hidePasswords;
      }
      return cipherToResponse(
        item.cipher,
        attachmentsByCipher.get(item.cipher.id) || [],
        cipherResponseOptionsForRequest(request)
      );
    }),
    object: 'list',
    continuationToken: null,
  });
}

function parseCipherIdList(body: { ids?: unknown }): string[] | null {
  if (!Array.isArray(body.ids)) return null;
  return Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

// Split bulk ids into personal vault ids and organization ids the user can
// edit. Ids the user cannot access (or cannot edit) are dropped.
async function splitBulkIdsByAccess(
  storage: StorageService,
  userId: string,
  ids: string[]
): Promise<{ personal: string[]; organization: Array<{ id: string; organizationId: string }> }> {
  const loaded = await storage.listAccessibleCiphersByIds(userId, ids);
  const personal: string[] = [];
  const organization: Array<{ id: string; organizationId: string }> = [];
  for (const item of loaded) {
    if (!item.cipher.organizationId) {
      personal.push(item.cipher.id);
    } else if (!item.access || item.access.canEdit) {
      organization.push({ id: item.cipher.id, organizationId: item.cipher.organizationId });
    }
  }
  return { personal, organization };
}

// Enforce per-target-collection editability for move endpoints, mirroring the
// share flow: non-accessAll members may only move ciphers into collections
// they hold a non-readOnly assignment on.
async function verifyTargetCollectionsEditable(
  storage: StorageService,
  userId: string,
  organizationId: string,
  collectionIds: string[]
): Promise<Response | null> {
  const membership = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!membership || membership.status !== ORG_USER_STATUS.CONFIRMED) {
    return errorResponse('Organization not found', 404);
  }
  if (membership.accessAll || membership.type === ORG_USER_TYPE.OWNER) return null;
  const editableIds = new Set(
    (await storage.listCollectionUsersByOrganizationUser(membership.id))
      .filter((row) => !row.readOnly)
      .map((row) => row.collectionId)
  );
  for (const collectionId of collectionIds) {
    if (!editableIds.has(collectionId)) {
      return errorResponse('You do not have permission to move ciphers to these collections', 403);
    }
  }
  return null;
}

async function bumpOrganizationsForBulk(
  request: Request,
  env: Env,
  storage: StorageService,
  organization: Array<{ id: string; organizationId: string }>
): Promise<void> {
  for (const organizationId of Array.from(new Set(organization.map((item) => item.organizationId)))) {
    await bumpOrganizationMembers(request, env, storage, organizationId);
  }
}

// PUT/POST /api/ciphers/:id/archive
export async function handleArchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;
  if (cipher.deletedAt) {
    return errorResponse('Cannot archive a deleted cipher', 400);
  }

  cipher.archivedAt = new Date().toISOString();
  cipher.updatedAt = cipher.archivedAt;
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  const revisionDate = await finishCipherMutation(request, env, storage, cipher, userId);
  if (!cipher.organizationId) {
    notifyCipherUpdateForRequest(request, env, cipher, revisionDate, userId);
  }

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request))
  );
}

// PUT/POST /api/ciphers/:id/unarchive
export async function handleUnarchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;

  cipher.archivedAt = null;
  cipher.updatedAt = new Date().toISOString();
  normalizeCipherForStorage(cipher);
  await storage.saveCipher(cipher);
  await finishCipherMutation(request, env, storage, cipher, userId);

  const attachments = await storage.getAttachmentsByCipher(cipher.id);
  return jsonResponse(
    cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request))
  );
}

// PUT/POST /api/ciphers/archive
export async function handleBulkArchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const { personal, organization } = await splitBulkIdsByAccess(storage, userId, ids);

  const revisionDate = await storage.bulkArchiveCiphers(personal, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }
  if (organization.length) {
    await storage.archiveCiphersByIds(organization.map((item) => item.id));
    await bumpOrganizationsForBulk(request, env, storage, organization);
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// PUT/POST /api/ciphers/unarchive
export async function handleBulkUnarchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = parseCipherIdList(body);
  if (!ids) {
    return errorResponse('ids array is required', 400);
  }

  const { personal, organization } = await splitBulkIdsByAccess(storage, userId, ids);

  const revisionDate = await storage.bulkUnarchiveCiphers(personal, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }
  if (organization.length) {
    await storage.unarchiveCiphersByIds(organization.map((item) => item.id));
    await bumpOrganizationsForBulk(request, env, storage, organization);
  }

  return buildCipherListResponse(request, storage, userId, ids);
}

// POST /api/ciphers/delete - Bulk soft delete
export async function handleBulkDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const { personal, organization } = await splitBulkIdsByAccess(storage, userId, body.ids);

  const revisionDate = await storage.bulkSoftDeleteCiphers(personal, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }
  if (organization.length) {
    await storage.softDeleteCiphersByIds(organization.map((item) => item.id));
    await bumpOrganizationsForBulk(request, env, storage, organization);
  }
  if (revisionDate || organization.length) {
    await writeCipherAudit(storage, request, userId, 'cipher.delete.soft.bulk', {
      count: body.ids.length,
    });
  }

  return new Response(null, { status: 204 });
}

// POST /api/ciphers/restore - Bulk restore
export async function handleBulkRestoreCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const { personal, organization } = await splitBulkIdsByAccess(storage, userId, body.ids);

  const revisionDate = await storage.bulkRestoreCiphers(personal, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }
  if (organization.length) {
    await storage.restoreCiphersByIds(organization.map((item) => item.id));
    await bumpOrganizationsForBulk(request, env, storage, organization);
  }

  return new Response(null, { status: 204 });
}

// POST /api/ciphers/delete-permanent - Bulk permanent delete
export async function handleBulkPermanentDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const ids = Array.from(new Set(body.ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!ids.length) {
    return new Response(null, { status: 204 });
  }

  const { personal, organization } = await splitBulkIdsByAccess(storage, userId, ids);
  if (!personal.length && !organization.length) {
    return new Response(null, { status: 204 });
  }

  await deleteAllAttachmentsForCiphers(env, [...personal, ...organization.map((item) => item.id)]);

  const revisionDate = await storage.bulkDeleteCiphers(personal, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  }
  if (organization.length) {
    await storage.deleteCiphersByIds(organization.map((item) => item.id));
    await bumpOrganizationsForBulk(request, env, storage, organization);
  }
  if (revisionDate || organization.length) {
    await writeCipherAudit(storage, request, userId, 'cipher.delete.permanent.bulk', {
      count: personal.length + organization.length,
      requestedCount: ids.length,
    });
  }

  return new Response(null, { status: 204 });
}

// --- Organization sharing ---

// POST /api/ciphers/:id/share
// Body: { organizationId, collectionIds: [...], cipher: { ...encrypted with the org key... } }
// Moves a personal cipher into an organization: the re-encrypted client payload
// replaces the stored data, ownership transfers to the organization.
export async function handleShareCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { organizationId?: unknown; collectionIds?: unknown; cipher?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const organizationId = normalizeOptionalId(body.organizationId);
  if (!organizationId) {
    return errorResponse('organizationId is required', 400);
  }

  const membership = await storage.getOrganizationUserForUser(organizationId, userId);
  if (!membership || membership.status !== ORG_USER_STATUS.CONFIRMED) {
    return errorResponse('Organization not found', 404);
  }

  const collectionIds = Array.isArray(body.collectionIds)
    ? Array.from(new Set(body.collectionIds.map((collectionId: unknown) => String(collectionId || '').trim()).filter(Boolean)))
    : [];
  if (!collectionIds.length) {
    return errorResponse('At least one collection is required to share a cipher', 400);
  }

  // Target collections must belong to this organization.
  const collections = await storage.getCollectionsByIds(collectionIds);
  const validIds = new Set(collections.filter((collection) => collection.organizationId === organizationId).map((collection) => collection.id));
  for (const collectionId of collectionIds) {
    if (!validIds.has(collectionId)) {
      return errorResponse(`Collection ${collectionId} does not belong to this organization`, 400);
    }
  }
  if (!membership.accessAll) {
    const editableIds = new Set(
      (await storage.listCollectionUsersByOrganizationUser(membership.id))
        .filter((row) => !row.readOnly)
        .map((row) => row.collectionId)
    );
    for (const collectionId of collectionIds) {
      if (!editableIds.has(collectionId)) {
        return errorResponse('You do not have permission to add ciphers to these collections', 403);
      }
    }
  }

  const cipher = await storage.getCipherForUser(id, userId);
  if (!cipher || cipher.userId !== userId) {
    return errorResponse('Cipher not found', 404);
  }

  // The client re-encrypts every field with the organization key; the supplied
  // cipher payload fully replaces the stored personal data.
  const cipherData = (body.cipher && typeof body.cipher === 'object' ? body.cipher : null) as Record<string, any> | null;
  if (!cipherData) {
    return errorResponse('cipher is required', 400);
  }

  const now = new Date().toISOString();
  // Keep-my-filing: the client sends the source item's personal folderId in
  // the payload; the filing carries over as the acting user's per-user
  // mapping (their own folders only).
  const requestedFolderId = normalizeOptionalId(
    getAliasedProp(cipherData, ['folderId', 'FolderId']).value
  );
  if (requestedFolderId) {
    const folderOk = await verifyFolderOwnership(storage, requestedFolderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }
  const shared: Cipher = {
    ...cipher,
    ...cipherData,
    // Server-controlled fields
    id: cipher.id,
    userId: null,
    organizationId,
    folderId: requestedFolderId,
    favorite: !!cipherData.favorite,
    reprompt: Number(cipherData.reprompt) || 0,
    createdAt: cipher.createdAt,
    updatedAt: now,
    deletedAt: null,
  };
  // Personal per-item keys (user-key wrapped) are unreadable after the move;
  // drop any key the client did not re-encrypt with the organization key.
  if (cipherData.key === undefined || cipherData.key === null) {
    shared.key = null;
  }
  normalizeCipherForStorage(shared);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(shared);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  const transferred = await storage.transferCipherToOrganization(shared, userId);
  if (!transferred) {
    return errorResponse('Cipher not found', 404);
  }
  // The shared item keeps its personal folder filing for the sharer (per-user
  // mapping; the cipher row stays unfiled).
  if (requestedFolderId) {
    await storage.setCipherUserFolder(userId, shared.id, requestedFolderId);
  }
  await storage.setCipherCollections(shared.id, collectionIds);
  await bumpOrganizationMembers(request, env, storage, organizationId);

  shared.collectionIds = collectionIds;
  shared.edit = true;
  shared.viewPassword = true;
  notifyCipherUpdateForRequest(request, env, shared, now, userId);
  await writeCipherAudit(storage, request, userId, 'cipher.share', {
    id: shared.id,
    organizationId,
    collectionIds,
  });

  return jsonResponse(
    cipherToResponse(shared, [], cipherResponseOptionsForRequest(request))
  );
}

// PUT/POST /api/ciphers/:id/collections (v2 flexible collections)
// Body: { collectionIds: [...] } — move an org cipher between collections.
export async function handleSetCipherCollections(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const loaded = await loadCipherForRequest(storage, userId, id, { requireWrite: true });
  if (loaded instanceof Response) return loaded;
  const cipher = loaded.cipher;
  if (!cipher.organizationId) {
    return errorResponse('Cipher is not shared with an organization', 400);
  }

  let body: { collectionIds?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const collectionIds = Array.isArray(body.collectionIds)
    ? Array.from(new Set(body.collectionIds.map((collectionId: unknown) => String(collectionId || '').trim()).filter(Boolean)))
    : [];
  // Reject empty targets: stripping all links silently revokes the cipher from
  // every non-accessAll member (access-map tampering, not a legitimate move).
  if (!collectionIds.length) {
    return errorResponse('At least one collection is required', 400);
  }

  const collections = await storage.getCollectionsByIds(collectionIds);
  const validIds = new Set(collections.filter((collection) => collection.organizationId === cipher.organizationId).map((collection) => collection.id));
  for (const collectionId of collectionIds) {
    if (!validIds.has(collectionId)) {
      return errorResponse(`Collection ${collectionId} does not belong to this organization`, 400);
    }
  }
  const permissionError = await verifyTargetCollectionsEditable(storage, userId, cipher.organizationId, collectionIds);
  if (permissionError) return permissionError;

  cipher.updatedAt = new Date().toISOString();
  await storage.saveCipher(cipher);
  await storage.setCipherCollections(cipher.id, collectionIds);
  await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  await writeCipherAudit(storage, request, userId, 'cipher.collections.update', {
    id: cipher.id,
    organizationId: cipher.organizationId,
    collectionIds,
  });

  cipher.collectionIds = collectionIds;

  return jsonResponse(
    cipherToResponse(cipher, [], cipherResponseOptionsForRequest(request))
  );
}

// POST/PUT /api/ciphers/bulk/collections (v2 bulk flexible-collections move)
// Body: { cipherIds: [...], collectionIds: [...] }
export async function handleBulkSetCipherCollections(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { cipherIds?: unknown; collectionIds?: unknown };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const cipherIds = Array.isArray(body.cipherIds)
    ? Array.from(new Set(body.cipherIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)))
    : [];
  const collectionIds = Array.isArray(body.collectionIds)
    ? Array.from(new Set(body.collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)))
    : [];
  if (!cipherIds.length) {
    return errorResponse('cipherIds array is required', 400);
  }
  if (!collectionIds.length) {
    return errorResponse('collectionIds array is required', 400);
  }

  const { organization } = await splitBulkIdsByAccess(storage, userId, cipherIds);
  if (!organization.length) {
    return errorResponse('No organization ciphers found', 404);
  }
  const organizationIds = Array.from(new Set(organization.map((item) => item.organizationId)));
  if (organizationIds.length > 1) {
    return errorResponse('Ciphers from multiple organizations cannot be moved together', 400);
  }
  const organizationId = organizationIds[0];

  const collections = await storage.getCollectionsByIds(collectionIds);
  const validIds = new Set(collections.filter((collection) => collection.organizationId === organizationId).map((collection) => collection.id));
  for (const collectionId of collectionIds) {
    if (!validIds.has(collectionId)) {
      return errorResponse(`Collection ${collectionId} does not belong to this organization`, 400);
    }
  }
  const permissionError = await verifyTargetCollectionsEditable(storage, userId, organizationId, collectionIds);
  if (permissionError) return permissionError;

  const movedIds = organization.map((item) => item.id);
  for (const cipherId of movedIds) {
    await storage.setCipherCollections(cipherId, collectionIds);
  }
  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeCipherAudit(storage, request, userId, 'cipher.collections.update.bulk', {
    organizationId,
    count: movedIds.length,
    collectionIds,
  });

  return new Response(null, { status: 204 });
}
