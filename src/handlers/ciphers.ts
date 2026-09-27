import { z } from 'zod';
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
  AttachmentResponse,
  PasswordHistory,
} from '../types';
import type { CipherField } from '../types';
import { LIMITS } from '../config/limits';
import {
  notifyUserCipherCreate,
  notifyUserCipherDelete,
  notifyUserCipherUpdate,
  notifyUserCiphersSync,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID, isUUID } from '../utils/uuid';
import { deleteAllAttachmentsForCipher, deleteAllAttachmentsForCiphers } from './attachments';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { cipherNotifyPayload, readActingDeviceIdentifier } from '../utils/device';
import { writeDataAudit } from '../services/audit-events';
import { EventType, recordEvents } from '../services/events';
import * as orgRepo from '../services/storage-org-repo';
import {
  checkCollectionAssignment,
  canReadOrganizationCiphers,
  deleteAuthorizedCipher,
  loadAccessibleCipher,
  planCipherCollectionChange,
  type CollectionChangeMode,
} from './cipher-access';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as cipherRepo from '../services/storage-cipher-repo';
import * as folderRepo from '../services/storage-folder-repo';
import * as revisionRepo from '../services/storage-revision-repo';

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

// Stored permission flags default to allowed; anything but a boolean reads as the default.
const storedFlag = z.boolean().catch(true);
const StoredPermissions = z.object({ delete: storedFlag, restore: storedFlag })
  .catch(() => ({ delete: true, restore: true }));

// Every cipher write ends the same way: bump the owner's revision, signal their devices with the
// matching cipher event, and record the organization event when upstream logs one for the write.
async function afterCipherMutation(
  request: Request,
  env: Env,
  userId: string,
  cipher: Cipher,
  notify: typeof notifyUserCipherUpdate,
  eventType?: number
): Promise<void> {
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  notify(env, cipherNotifyPayload(cipher, revisionDate, request));
  if (eventType !== undefined) await recordCipherEvents(env, request, userId, eventType, [cipher]);
}

// Bulk archive, unarchive, soft-delete, restore and purge share everything after the id list: the
// repo write, the sync signals for the owner's devices, the optional audit row and the response.
async function finishBulkCipherState(
  request: Request,
  env: Env,
  userId: string,
  ids: string[],
  bulk: (db: D1Database, ids: string[], userId: string) => Promise<string | null>,
  audit: { action: string; metadata: Record<string, unknown> } | null,
  respond: () => Response | Promise<Response>
): Promise<Response> {
  const revisionDate = await bulk(env.DB, ids, userId);
  if (revisionDate) {
    notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    notifyUserCiphersSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    if (audit) await writeDataAudit(env.DB, request, userId, 'cipher', audit.action, audit.metadata);
  }
  return respond();
}

function cipherJsonResponse(request: Request, cipher: Cipher, attachments: Attachment[] = []): Response {
  return jsonResponse(cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request)));
}

function normalizeCipherTimestamp(value: unknown): string | null {
  if (value == null || value === '') return null;
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

// Any Date-parseable value reads as its ISO form and anything else as null, so a malformed
// timestamp clears instead of failing the write.
const cipherTimestamp = z.unknown().transform(normalizeCipherTimestamp).optional();

// Client-owned values stored as sent: cipherToResponse sanitizes them on the way out and
// validateCipherEncryptedFieldsForCompatibility checks the merged cipher, so they are typed, not checked.
const storedAsSent = <T>() => z.custom<T | null>().optional();

// A cipher body is stored wholesale, so unknown and future client fields pass through untouched.
const CipherData = z.looseObject({
  organizationId: z.unknown().transform(normalizeOptionalId).optional(),
  key: z.unknown()
    .refine(shouldAcceptCipherKey, { error: 'Cipher key encryption is not supported by this server. Resync the client and try again.' })
    .optional(),
  favorite: z.boolean().nullish(),
  reprompt: z.number().nullish(),
  archivedAt: cipherTimestamp,
  archivedDate: cipherTimestamp,
  lastKnownRevisionDate: cipherTimestamp,
  name: storedAsSent<string>(),
  notes: storedAsSent<string>(),
  login: storedAsSent<CipherLogin>(),
  card: storedAsSent<CipherCard>(),
  identity: storedAsSent<CipherIdentity>(),
  secureNote: storedAsSent<CipherSecureNote>(),
  sshKey: storedAsSent<CipherSshKey>(),
  bankAccount: storedAsSent<CipherBankAccount>(),
  driversLicense: storedAsSent<CipherDriversLicense>(),
  passport: storedAsSent<CipherPassport>(),
  fields: storedAsSent<CipherField[]>(),
  passwordHistory: storedAsSent<PasswordHistory[]>(),
});
type CipherData = z.output<typeof CipherData>;

// Android wraps organization ciphers as { cipher, collectionIds }; other clients send the cipher itself.
const CipherBody = CipherData.extend({ cipher: CipherData.nullish() });

// Ids are compared as trimmed strings; blanks and repeats are dropped before any lookup.
function idList(error?: string) {
  return z.array(z.unknown(), { error }).transform((ids) => [...new Set(ids.map((id) => String(id || '').trim()).filter(Boolean))]);
}

export function nonEmptyIdList(error: string) {
  return idList(error).refine((ids) => ids.length > 0, { error });
}

const requiredId = (error: string) => z.unknown().transform(normalizeOptionalId).pipe(z.string({ error }));

const CipherIdsBody = z.object({ ids: idList('ids array is required') });

// Upstream CipherShareRequestModel / CipherBulkShareRequestModel validation messages.
const NO_SHARE_COLLECTION = 'You must select at least one collection.';
const NO_SHARE_CIPHER = 'You must select at least one cipher.';
const SHARE_CIPHER_UNIDENTIFIED = 'All Ciphers must have an Id and OrganizationId.';
const SHARE_ORGANIZATION_REQUIRED = 'Cipher OrganizationId is required.';

const ShareCipherBody = z.object({
  cipher: z.looseObject(
    { ...CipherData.shape, organizationId: requiredId(SHARE_ORGANIZATION_REQUIRED) },
    { error: SHARE_ORGANIZATION_REQUIRED }
  ),
  collectionIds: nonEmptyIdList(NO_SHARE_COLLECTION),
});

// The whole share is one D1 batch, so its size is capped like an import. The piped item checks run
// only once the count checks pass, so an oversized or empty list answers with its count message.
const BulkShareCiphersBody = z.object({
  ciphers: z.array(z.unknown(), { error: NO_SHARE_CIPHER })
    .min(1, { error: NO_SHARE_CIPHER })
    .max(LIMITS.performance.importItemLimit, { error: `Share exceeds maximum of ${LIMITS.performance.importItemLimit} items` })
    .pipe(z.array(z.looseObject(
      { ...CipherData.shape, id: requiredId(SHARE_CIPHER_UNIDENTIFIED), organizationId: requiredId(SHARE_CIPHER_UNIDENTIFIED) },
      { error: SHARE_CIPHER_UNIDENTIFIED }
    )).refine((ciphers) => new Set(ciphers.map((cipher) => cipher.organizationId)).size === 1, {
      error: 'All ciphers must be for the same organization.',
    })),
  collectionIds: nonEmptyIdList(NO_SHARE_COLLECTION),
});

// archivedDate is the response spelling of archivedAt; a sent archivedAt wins even when null.
function readCipherArchivedAt(source: CipherData, fallback: string | null): string | null {
  if (source.archivedAt !== undefined) return source.archivedAt;
  return source.archivedDate !== undefined ? source.archivedDate : fallback;
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

export async function recordCipherEvents(env: Env, request: Request, userId: string, type: number, ciphers: Cipher[]): Promise<void> {
  await recordEvents(env, request, { userId }, [...new Map(ciphers.map(cipher => [cipher.id, cipher])).values()]
    .flatMap(cipher => cipher.organizationId
      ? [{ type, organizationId: cipher.organizationId, resourceType: 'cipher' as const, resourceId: cipher.id }]
      : []));
}

function cipherEventState(cipher: Cipher, attachments: Attachment[]): string {
  const { revisionDate, creationDate, lastKnownRevisionDate, LastKnownRevisionDate, attachments2, Attachments2, ...state } = cipherToResponse(cipher, attachments);
  return JSON.stringify(state, (_key, value) => value && typeof value === 'object' && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right))) : value);
}

function isValidEncString(value: unknown): value is string {
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
  if (type === 0 || type === 1 || type === 4) return parts.length >= 2;
  if (type === 2) return parts.length === 3;

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

function sanitizeEncryptedObject<T extends object>(
  source: T | null | undefined,
  encryptedKeys: readonly string[] | Record<string, number>
): T | null {
  if (!source || typeof source !== 'object') return source ?? null;
  const next = { ...source } as Record<string, unknown>;
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

// Nested client values are stored as sent, so the response path re-reads them: a valid EncString
// reads trimmed, and anything else reads as null or drops its entry.
const encString = z.custom<string>(isValidEncString).transform((value) => value.trim());
const storedValue = <Output>(read: (value: unknown) => Output) => z.unknown().optional().transform(read);
const encStringOrNull = storedValue(optionalEncString);
const uriEncStringOrNull = storedValue((value) => optionalEncStringWithin(value, 10000));

// Each stored entry parses on its own: a rejected entry is dropped, and a kept one keeps its unknown
// client keys, in stored order, around the normalized ones. No surviving entry reads as null.
function parseStoredEntries<Entry extends object>(entries: unknown, schema: z.ZodType<Entry>): Array<Record<string, unknown> & Entry> | null {
  const parsed = (Array.isArray(entries) ? entries : []).flatMap((entry: Record<string, unknown>) => {
    const result = schema.safeParse(entry);
    return result.success ? [{ ...entry, ...result.data }] : [];
  });
  return parsed.length ? parsed : null;
}

// A URI entry survives while it still holds a URI, a checksum or a match rule. Official Bitwarden
// treats uriChecksum as nullable encrypted metadata, so a URI without one keeps its entry with a
// null checksum and clients that can repair checksums do so.
const StoredLoginUri = z.object({
  uri: uriEncStringOrNull.optional(),
  uriChecksum: uriEncStringOrNull.optional(),
  match: z.custom<number | null>().optional(),
})
  .refine(({ uri, uriChecksum, match }) => !!(uri || uriChecksum) || match != null)
  .transform((entry) => (entry.uri ? { ...entry, uriChecksum: entry.uriChecksum ?? null } : entry));

// A passkey needs all of its key material; a malformed optional label reads as null.
const StoredFido2Credential = z.object({
  credentialId: encString,
  keyType: encString,
  keyAlgorithm: encString,
  keyCurve: encString,
  keyValue: encString,
  rpId: encString,
  counter: encString,
  discoverable: encString,
  userHandle: encStringOrNull.optional(),
  userName: encStringOrNull.optional(),
  rpName: encStringOrNull.optional(),
  userDisplayName: encStringOrNull.optional(),
});

const StoredCipherField = z.object({
  name: encStringOrNull,
  value: encStringOrNull,
  type: storedValue((type) => Number(type) || 0),
  linkedId: z.custom<number | null>().default(null),
});

const StoredPasswordHistoryEntry = z.object({
  password: encString,
  lastUsedDate: storedValue((lastUsedDate) => normalizeCipherTimestamp(lastUsedDate) ?? new Date().toISOString()),
});

// A secure note carries only its subtype, spelled Type by older payloads; anything unreadable is a
// generic note.
const StoredSecureNote = z.object({ type: z.unknown().optional(), Type: z.unknown().optional() })
  .transform(({ type, Type }) => ({ type: Number(type ?? Type ?? 0) }))
  .refine(({ type }) => Number.isFinite(type))
  .catch(() => ({ type: 0 }));

// Passkeys are only ever stored as a list, so any other value reads as none.
export function normalizeCipherLoginForStorage(
  login: (Omit<CipherLogin, 'fido2Credentials'> & { fido2Credentials?: unknown }) | null | undefined
): CipherLogin | null {
  if (!login || typeof login !== 'object') return null;
  return { ...login, fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null };
}

export function normalizeCipherLoginForCompatibility(login: CipherLogin | null): CipherLogin | null {
  const next = sanitizeEncryptedObject(normalizeCipherLoginForStorage(login), {
    username: 1000,
    password: 5000,
    totp: 1000,
    uri: 10000,
  });
  return next && {
    ...next,
    uris: parseStoredEntries(next.uris, StoredLoginUri),
    fido2Credentials: parseStoredEntries(next.fido2Credentials, StoredFido2Credential),
  };
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

// Android 2026.2.0 requires sshKey.keyFingerprint in sync payloads.
// Keep legacy alias "fingerprint" in parallel for older web payloads.
export function normalizeCipherSshKeyForCompatibility(sshKey: unknown): CipherSshKey | null {
  if (!sshKey || typeof sshKey !== 'object') return null;
  const stored: Record<string, unknown> = { ...sshKey };
  const fingerprint = String(stored.keyFingerprint ?? stored.fingerprint ?? '');
  if (!isValidEncString(stored.privateKey) || !isValidEncString(stored.publicKey) || !isValidEncString(fingerprint)) {
    return null;
  }
  return { ...stored, privateKey: stored.privateKey.trim(), publicKey: stored.publicKey.trim(), keyFingerprint: fingerprint, fingerprint };
}

// Format attachments for API response
export function formatAttachments(attachments: Attachment[]): AttachmentResponse[] | null {
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

// Only the fields a client sent may overwrite a stored attachment, so absent keys stay absent;
// size is the older spelling of fileSize.
const IncomingAttachmentFields = z.object({
  fileName: z.unknown().optional(),
  key: z.unknown().optional(),
  fileSize: z.unknown().optional(),
  size: z.unknown().optional(),
}).transform(({ size, ...fields }) => ('fileSize' in fields || size === undefined ? fields : { ...fields, fileSize: size }));
type IncomingAttachmentMetadata = z.output<typeof IncomingAttachmentFields> & { id: string };

function incomingAttachmentMetadata(rawId: unknown, row: unknown): IncomingAttachmentMetadata[] {
  const id = String(rawId ?? '').trim();
  const fields = IncomingAttachmentFields.safeParse(row);
  return id && fields.success ? [{ ...fields.data, id }] : [];
}

// Metadata arrives as a list of rows carrying their id or as a map keyed by id; legacy clients map
// ids straight to file names.
function readIncomingAttachmentMetadataMap(value: unknown, legacyFileNameMap = false): IncomingAttachmentMetadata[] {
  if (Array.isArray(value)) return value.flatMap((row) => incomingAttachmentMetadata(row?.id, row));
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([id, row]) => legacyFileNameMap && (typeof row === 'string' || row == null)
    ? incomingAttachmentMetadata(id, row == null ? {} : { fileName: row })
    : incomingAttachmentMetadata(id, row));
}

// attachments2 refines the legacy attachments field by field.
function readIncomingAttachmentMetadata(source: Record<string, unknown>): IncomingAttachmentMetadata[] {
  const merged = new Map(readIncomingAttachmentMetadataMap(source.attachments, true).map((item) => [item.id, item]));
  for (const item of readIncomingAttachmentMetadataMap(source.attachments2)) merged.set(item.id, { ...merged.get(item.id), ...item });
  return [...merged.values()];
}

function hasIncomingAttachmentMetadata(source: Record<string, unknown>): boolean {
  return readIncomingAttachmentMetadata(source).length > 0;
}

// Applies client-sent attachment metadata (re-encrypted keys, renamed files) to the stored rows and
// returns only the rows it changed.
function applyIncomingAttachmentMetadata(current: Attachment[], cipherData: Record<string, unknown>): Attachment[] {
  const currentById = new Map(current.map((attachment) => [attachment.id, attachment]));
  const changedAttachments: Attachment[] = [];
  for (const item of readIncomingAttachmentMetadata(cipherData)) {
    const attachment = currentById.get(item.id);
    if (!attachment) continue;

    let changed = false;
    if ('fileName' in item) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName) && fileName !== attachment.fileName) {
        attachment.fileName = fileName;
        changed = true;
      }
    }

    if ('key' in item) {
      const key = optionalEncString(item.key);
      if (key !== attachment.key) {
        attachment.key = key;
        changed = true;
      }
    }

    if ('fileSize' in item) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0 && size !== Number(attachment.size || 0)) {
        attachment.size = size;
        attachment.sizeName = formatAttachmentSize(size);
        changed = true;
      }
    }

    if (changed) changedAttachments.push(attachment);
  }
  return changedAttachments;
}

async function syncIncomingAttachmentMetadata(
  db: D1Database,
  cipherId: string,
  cipherData: Record<string, unknown>
): Promise<void> {
  if (!hasIncomingAttachmentMetadata(cipherData)) return;
  for (const attachment of applyIncomingAttachmentMetadata(await attachmentRepo.getAttachmentsByCipher(db, cipherId), cipherData)) {
    await attachmentRepo.saveAttachment(db, attachment);
  }
}

export function applyCipherEmbeddedAttachmentMetadata(cipherData: Record<string, unknown>, attachments: Attachment[]): Attachment[] {
  const incoming = readIncomingAttachmentMetadata(cipherData);
  if (!incoming.length || !attachments.length) return attachments;

  const incomingById = new Map(incoming.map((item) => [item.id, item]));
  return attachments.map((attachment) => {
    const item = incomingById.get(attachment.id);
    if (!item) return attachment;

    const next: Attachment = { ...attachment };
    if ('fileName' in item) {
      const fileName = String(item.fileName || '').trim();
      if (isValidEncString(fileName)) {
        next.fileName = fileName;
      }
    }
    if ('key' in item) {
      next.key = optionalEncString(item.key);
    }
    if ('fileSize' in item) {
      const size = Number(item.fileSize);
      if (Number.isFinite(size) && size >= 0) {
        next.size = size;
        next.sizeName = formatAttachmentSize(size);
      }
    }
    return next;
  });
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
  const normalizedLogin = normalizeCipherLoginForCompatibility(passthrough.login ?? null);
  const normalizedCard = sanitizeEncryptedObject(passthrough.card ?? null, {
    cardholderName: 1000,
    brand: 1000,
    number: 1000,
    expMonth: 1000,
    expYear: 1000,
    code: 1000,
  });
  const normalizedIdentity = sanitizeEncryptedObject(passthrough.identity ?? null, [
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
  const normalizedSshKey = normalizeCipherSshKeyForCompatibility(passthrough.sshKey);
  const normalizedBankAccount = sanitizeEncryptedObject(
    passthrough.bankAccount ?? null,
    BANK_ACCOUNT_ENCRYPTED_KEYS
  );
  const normalizedDriversLicense = sanitizeEncryptedObject(
    passthrough.driversLicense ?? null,
    DRIVERS_LICENSE_ENCRYPTED_KEYS
  );
  const normalizedPassport = sanitizeEncryptedObject(
    passthrough.passport ?? null,
    PASSPORT_ENCRYPTED_KEYS
  );
  const responseType = Number(cipher.type) || 1;
  const responseAttachments = applyCipherEmbeddedAttachmentMetadata(cipher, attachments);

  return {
    // Pass through ALL stored cipher fields (known + unknown)
    ...passthrough,
    // Server-computed / enforced fields (always override)
    folderId: normalizeResponseFolderId(cipher.folderId, options.validFolderIds),
    type: responseType,
    organizationId: normalizeOptionalId(passthrough.organizationId),
    organizationUseTotp: !!passthrough.organizationUseTotp,
    creationDate: createdAt,
    revisionDate: updatedAt,
    deletedDate: deletedAt,
    archivedDate: archivedAt ?? null,
    edit: storedFlag.parse(passthrough.edit),
    viewPassword: storedFlag.parse(passthrough.viewPassword),
    permissions: StoredPermissions.parse(passthrough.permissions),
    object: 'cipherDetails',
    collectionIds: Array.isArray(passthrough.collectionIds) ? passthrough.collectionIds : [],
    attachments: formatAttachments(responseAttachments),
    name: isValidEncString(cipher.name) ? cipher.name.trim() : cipher.name,
    notes: optionalEncString(cipher.notes),
    login: normalizedLogin,
    card: normalizedCard,
    identity: normalizedIdentity,
    secureNote: responseType === 2 ? StoredSecureNote.parse(passthrough.secureNote) : null,
    fields: parseStoredEntries(passthrough.fields, StoredCipherField),
    passwordHistory: parseStoredEntries(passthrough.passwordHistory, StoredPasswordHistoryEntry),
    sshKey: normalizedSshKey,
    bankAccount: responseType === 6 ? normalizedBankAccount : null,
    driversLicense: responseType === 7 ? normalizedDriversLicense : null,
    passport: responseType === 8 ? normalizedPassport : null,
    key: responseCipherKey,
    data: typeof passthrough.data === 'string' ? passthrough.data : null,
    encryptedFor: passthrough.encryptedFor ?? null,
  };
}

function organizationCipherResponse(request: Request, cipher: Cipher, attachments: Attachment[]) {
  const { folderId, favorite, edit, viewPassword, permissions, ...response } = cipherToResponse(cipher, attachments, cipherResponseOptionsForRequest(request));
  return { ...response, organizationUseTotp: true, object: 'cipherMiniDetails' };
}

// includeMemberItems concerns organization-owned default collections upstream. NodeWarden has none;
// neither value can include personal vault rows. Reports decrypt and analyze the response in the client.
export async function handleGetOrganizationCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const orgId = new URL(request.url).searchParams.get('organizationId');
  if (!isUUID(orgId)) return errorResponse('OrganizationId must be a valid GUID.', 400);
  const id = orgId.toLowerCase();
  if (!await canReadOrganizationCiphers(env, userId, id, 'all')) return errorResponse('Not found', 404);
  const ciphers = await orgRepo.listOrganizationCiphers(env.DB, id);
  const attachments = await attachmentRepo.getAttachmentsByCipherIds(env.DB, ciphers.map(cipher => cipher.id));
  return jsonResponse({ data: ciphers.map(cipher => organizationCipherResponse(request, cipher, attachments.get(cipher.id) || [])), object: 'list', continuationToken: null });
}

export async function handleGetCipherAdmin(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await cipherRepo.getCipher(env.DB, id);
  if (!cipher?.organizationId || !await canReadOrganizationCiphers(env, userId, cipher.organizationId, 'admin')) return errorResponse('Not found', 404);
  const collectionIds = await orgRepo.listCipherCollectionIds(env.DB, id, cipher.organizationId);
  return jsonResponse(organizationCipherResponse(request, { ...cipher, collectionIds }, await attachmentRepo.getAttachmentsByCipher(env.DB, id)));
}

// GET /api/ciphers
export async function handleGetCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const url = new URL(request.url);
  const includeDeleted = url.searchParams.get('deleted') === 'true';
  const pagination = parsePagination(url);

  let filteredCiphers: Cipher[];
  let continuationToken: string | null = null;
  const orgCiphers = includeDeleted
    ? await orgRepo.listAccessibleOrgCiphers(env.DB, userId)
    : (await orgRepo.listAccessibleOrgCiphers(env.DB, userId)).filter((cipher) => !cipher.deletedAt);
  if (pagination) {
    const pageRows = await cipherRepo.getCiphersPage(env.DB,
      userId,
      includeDeleted,
      pagination.limit + 1,
      pagination.offset
    );
    const hasNext = pageRows.length > pagination.limit;
    filteredCiphers = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + filteredCiphers.length) : null;
  } else {
    const ciphers = await cipherRepo.getAllCiphers(env.DB, userId);
    filteredCiphers = includeDeleted
      ? [...ciphers, ...orgCiphers]
      : [...ciphers.filter(c => !c.deletedAt), ...orgCiphers];
  }

  const attachmentsByCipher = await attachmentRepo.getAttachmentsByCipherIds(env.DB,
    filteredCiphers.map((cipher) => cipher.id)
  );
  const validFolderIds = new Set((await folderRepo.getAllFolders(env.DB, userId)).map((folder) => folder.id));

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
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'read');
  if (!cipher) return errorResponse('Cipher not found', 404);

  return cipherJsonResponse(request, cipher, await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id));
}

async function verifyFolderOwnership(db: D1Database, folderId: string | null | undefined, userId: string): Promise<boolean> {
  if (!folderId) return true;
  const folder = await folderRepo.getFolderForUser(db, folderId, userId);
  return !!folder;
}

// POST /api/ciphers
export async function handleCreateCipher(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherBody);
  if (body instanceof Response) return body;
  const cipherData = body.cipher ?? body;

  const now = new Date().toISOString();
  const organizationId = cipherData.organizationId ?? null;
  const incomingCollectionIds = idList().catch([]).parse(cipherData.collectionIds || body.collectionIds);
  if (organizationId) {
    const assignment = await checkCollectionAssignment(env, userId, organizationId, incomingCollectionIds);
    if (!assignment.ok) return errorResponse(assignment.message, assignment.status);
  }
  // Opaque passthrough: spread ALL client fields to preserve unknown/future ones,
  // then override only server-controlled fields.
  const cipher: Cipher = normalizeCipherForStorage({
    ...cipherData,
    id: generateUUID(),
    userId: userId,
    organizationId,
    type: Number(cipherData.type) || 1,
    folderId: normalizeOptionalId(cipherData.folderId),
    name: cipherData.name ?? null,
    notes: cipherData.notes ?? null,
    favorite: !!cipherData.favorite,
    reprompt: cipherData.reprompt || 0,
    key: optionalEncString(cipherData.key),
    login: cipherData.login ?? null,
    card: cipherData.card ?? null,
    identity: cipherData.identity ?? null,
    secureNote: cipherData.secureNote ?? null,
    sshKey: cipherData.sshKey ?? null,
    bankAccount: cipherData.bankAccount ?? null,
    driversLicense: cipherData.driversLicense ?? null,
    passport: cipherData.passport ?? null,
    fields: cipherData.fields ?? null,
    passwordHistory: cipherData.passwordHistory ?? null,
    createdAt: now,
    updatedAt: now,
    archivedAt: readCipherArchivedAt(cipherData, null),
    deletedAt: null,
  });
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  if (compatibilityError) return errorResponse(compatibilityError, 400);

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(env.DB, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  await cipherRepo.saveCipher(env.DB, cipher);
  if (organizationId && incomingCollectionIds.length) {
    await orgRepo.replaceCipherCollections(env.DB, cipher.id, incomingCollectionIds);
    cipher.collectionIds = incomingCollectionIds;
  }
  if (organizationId) await orgRepo.bumpOrgMemberRevisions(env.DB, organizationId);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherCreate, EventType.CipherCreated);

  return cipherJsonResponse(request, cipher);
}

type CipherMerge = { ok: true; cipher: Cipher } | { ok: false; message: string };

// Full-update semantics shared by PUT /ciphers/{id} and the share endpoints: the client body
// replaces the stored cipher, while unknown fields survive and server-owned ones stay put.
function mergeFullCipherUpdate(existingCipher: Cipher, cipherData: CipherData, preserveRevisionDate: boolean): CipherMerge {
  if (!hasIncomingAttachmentMetadata(cipherData) && isStaleCipherUpdate(existingCipher.updatedAt, cipherData.lastKnownRevisionDate ?? null)) {
    return { ok: false, message: 'The client copy of this cipher is out of date. Resync the client and try again.' };
  }

  const nextType = Number(cipherData.type) || existingCipher.type;

  // Opaque passthrough: merge existing stored data with ALL incoming client fields.
  // Unknown/future fields from the client are preserved; server-controlled fields are protected.
  const { preserveRevisionDate: _preserveRevisionDate, ...cipherDataWithoutFlags } = cipherData;
  const cipher: Cipher = {
    ...existingCipher,   // start with all existing stored data (including unknowns)
    ...cipherDataWithoutFlags, // overlay all client data (including new/unknown fields)
    // Server-controlled fields (never from client)
    id: existingCipher.id,
    userId: existingCipher.userId,
    organizationId: existingCipher.organizationId,
    type: nextType,
    favorite: cipherData.favorite ?? existingCipher.favorite,
    reprompt: cipherData.reprompt ?? existingCipher.reprompt,
    // A cleared key keeps the stored one.
    key: optionalEncString(cipherData.key) ?? optionalEncString(existingCipher.key),
    // Nullable fields use replacement semantics on this full-update endpoint.
    // Some clients omit cleared values, so merge fallback must not resurrect them.
    notes: cipherData.notes ?? null,
    fields: cipherData.fields ?? null,
    createdAt: existingCipher.createdAt,
    updatedAt: preserveRevisionDate ? existingCipher.updatedAt : new Date().toISOString(),
    archivedAt: readCipherArchivedAt(cipherData, existingCipher.archivedAt ?? null),
    deletedAt: existingCipher.deletedAt,
  };
  // Only the sub-object of the resulting type survives; an omitted one keeps the stored value.
  cipher.login = nextType === 1 ? cipher.login ?? null : null;
  cipher.secureNote = nextType === 2 ? cipher.secureNote ?? null : null;
  cipher.card = nextType === 3 ? cipher.card ?? null : null;
  cipher.identity = nextType === 4 ? cipher.identity ?? null : null;
  cipher.sshKey = nextType === 5 ? cipher.sshKey ?? null : null;
  cipher.bankAccount = nextType === 6 ? cipher.bankAccount ?? null : null;
  cipher.driversLicense = nextType === 7 ? cipher.driversLicense ?? null : null;
  cipher.passport = nextType === 8 ? cipher.passport ?? null : null;
  normalizeCipherForStorage(cipher);
  const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
  return compatibilityError ? { ok: false, message: compatibilityError } : { ok: true, cipher };
}

// PUT /api/ciphers/:id
export async function handleUpdateCipher(request: Request, env: Env, userId: string, id: string, asAdmin = false): Promise<Response> {
  const existingCipher = await loadAccessibleCipher(env, env.DB, userId, id, asAdmin ? 'admin-edit' : 'edit');
  if (!existingCipher) return errorResponse('Cipher not found', 404);

  const body = await parseBody(request, CipherBody);
  if (body instanceof Response) return body;
  const cipherData = body.cipher ?? body;
  // Upstream CiphersController.Put: an item changes owner only through share, so a different
  // organizationId means a stale client copy. An omitted one (NodeWarden web repair) keeps the owner.
  if (cipherData.organizationId !== undefined && cipherData.organizationId !== (existingCipher.organizationId ?? null)) {
    return errorResponse('Organization mismatch. Re-sync if you recently moved this item, then try again.', 400);
  }
  const preserveRevisionDate =
    shouldPreserveRepairableCipherUris(request)
    && (body.preserveRevisionDate === true || cipherData.preserveRevisionDate === true);
  const merged = mergeFullCipherUpdate(existingCipher, cipherData, preserveRevisionDate);
  if (!merged.ok) return errorResponse(merged.message, 400);
  const cipher = merged.cipher;
  if (asAdmin) cipher.collectionIds = existingCipher.collectionIds;

  // Prevent referencing a folder owned by another user.
  if (cipher.folderId) {
    const folderOk = await verifyFolderOwnership(env.DB, cipher.folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  const previousState = cipher.organizationId
    ? cipherEventState(existingCipher, await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id)) : null;
  await syncIncomingAttachmentMetadata(env.DB, cipher.id, cipherData);
  await cipherRepo.saveCipher(env.DB, cipher);
  const attachments = await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id);
  const changed = previousState !== null && previousState !== cipherEventState(cipher, attachments);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate, changed ? EventType.CipherUpdated : undefined);

  return asAdmin
    ? jsonResponse({ ...organizationCipherResponse(request, cipher, attachments), object: 'cipherMini' })
    : cipherJsonResponse(request, cipher, attachments);
}

type ShareResult = { ok: true; ciphers: Cipher[]; revisionDate: string } | { ok: false; status: number; message: string };

// Upstream CipherService.ShareAsync / ShareManyAsync. The caller already owns each personal cipher
// and may write the collections; the client re-encrypted the body under the org key, so it replaces
// the stored fields as a full update would. Each row keeps its owner and gains the org, and every
// member's revision moves so their next sync pulls the ciphers in.
async function shareOwnedCiphers(
  request: Request,
  env: Env,
  db: D1Database,
  userId: string,
  organizationId: string,
  shares: Array<{ existing: Cipher; cipherData: CipherData }>,
  collectionIds: string[]
): Promise<ShareResult> {
  const merges = shares.map(({ existing, cipherData }) => mergeFullCipherUpdate(existing, cipherData, false));
  const failed = merges.find((merge) => !merge.ok);
  if (failed && !failed.ok) return { ok: false, status: 400, message: failed.message };
  const sharedCiphers = merges.flatMap((merge) => merge.ok ? [{ ...merge.cipher, organizationId }] : []);

  const folderIds = new Set((await folderRepo.getAllFolders(db, userId)).map((folder) => folder.id));
  if (sharedCiphers.some((cipher) => cipher.folderId && !folderIds.has(cipher.folderId))) {
    return { ok: false, status: 404, message: 'Folder not found' };
  }

  // Re-encrypted attachment keys arrive in attachments2 and move in the same batch as their cipher,
  // so a failed write never leaves org-key attachments on a cipher that is still personal.
  const withAttachmentMetadata = shares.filter(({ cipherData }) => hasIncomingAttachmentMetadata(cipherData));
  const currentAttachments = await attachmentRepo.getAttachmentsByCipherIds(db, withAttachmentMetadata.map(({ existing }) => existing.id));
  const changedAttachments = withAttachmentMetadata.flatMap(({ existing, cipherData }) =>
    applyIncomingAttachmentMetadata(currentAttachments.get(existing.id) || [], cipherData));
  await orgRepo.shareCiphers(env.DB, sharedCiphers, collectionIds, changedAttachments);
  await recordCipherEvents(env, request, userId, EventType.CipherShared, sharedCiphers);
  const revisionDate = await revisionRepo.updateRevisionDate(db, userId);
  await orgRepo.bumpOrgMemberRevisions(env.DB, organizationId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  return { ok: true, ciphers: sharedCiphers.map((cipher) => ({ ...cipher, collectionIds })), revisionDate };
}

// PUT/POST /api/ciphers/:id/share
export async function handleShareCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const body = await parseBody(request, ShareCipherBody);
  if (body instanceof Response) return body;
  const { cipher: cipherData, collectionIds } = body;
  const { organizationId } = cipherData;

  // Only a personal cipher of the caller can move; an org cipher or someone else's is not found.
  const existing = await cipherRepo.getCipherForUser(env.DB, id, userId);
  if (!existing) return errorResponse('Cipher not found', 404);
  const assignment = await checkCollectionAssignment(env, userId, organizationId, collectionIds);
  if (!assignment.ok) return errorResponse(assignment.message, assignment.status);

  const shared = await shareOwnedCiphers(request, env, env.DB, userId, organizationId, [{ existing, cipherData }], collectionIds);
  if (!shared.ok) return errorResponse(shared.message, shared.status);
  const [cipher] = shared.ciphers;
  notifyUserCipherUpdate(env, cipherNotifyPayload(cipher, shared.revisionDate, request));
  return cipherJsonResponse(request, cipher, await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id));
}

// PUT/POST /api/ciphers/share
export async function handleBulkShareCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, BulkShareCiphersBody);
  if (body instanceof Response) return body;
  const { ciphers: requested, collectionIds } = body;

  // Upstream PutShareMany checks membership before ownership.
  const [{ organizationId }] = requested;
  const assignment = await checkCollectionAssignment(env, userId, organizationId, collectionIds);
  if (!assignment.ok) return errorResponse(assignment.message, assignment.status);
  const owned = new Map(
    (await cipherRepo.getCiphersByIds(env.DB, requested.map((item) => item.id), userId)).map((cipher) => [cipher.id, cipher])
  );
  const shares = requested.flatMap((cipherData) => {
    const existing = owned.get(cipherData.id);
    return existing ? [{ existing, cipherData }] : [];
  });
  if (shares.length < requested.length) return errorResponse('Trying to share ciphers that you do not own.', 400);

  const shared = await shareOwnedCiphers(request, env, env.DB, userId, organizationId, shares, collectionIds);
  if (!shared.ok) return errorResponse(shared.message, shared.status);
  const attachmentsByCipher = await attachmentRepo.getAttachmentsByCipherIds(env.DB, shared.ciphers.map((cipher) => cipher.id));
  const responseOptions = cipherResponseOptionsForRequest(request);
  return jsonResponse({
    data: shared.ciphers.map((cipher) => cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], responseOptions)),
    object: 'list',
    continuationToken: null,
  });
}

// PUT/POST /api/ciphers/:id/collections_v2 and /api/ciphers/:id/collections-admin
export async function handleUpdateCipherCollections(
  request: Request,
  env: Env,
  userId: string,
  id: string,
  mode: CollectionChangeMode
): Promise<Response> {
  const body = await parseBody(request, z.object({ collectionIds: idList('The CollectionIds field is required.') }));
  if (body instanceof Response) return body;

  const change = await planCipherCollectionChange(env, env.DB, userId, id, body.collectionIds, mode);
  if (!change.ok) return errorResponse(change.message, change.status);
  await orgRepo.updateCipherCollections(env.DB, change.cipher.id, change.plan);
  await orgRepo.bumpOrgMemberRevisions(env.DB, change.organizationId);
  const cipher = { ...change.cipher, collectionIds: await orgRepo.listCipherCollectionIds(env.DB, change.cipher.id) };
  const changed = change.plan.insert.length > 0 || change.plan.remove.length > 0;
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate, changed ? EventType.CipherUpdatedCollections : undefined);

  const attachments = await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id);
  const responseOptions = cipherResponseOptionsForRequest(request);
  // The admin client fills in edit, viewPassword and favorite itself, so the details shape serves.
  if (mode === 'admin') return jsonResponse({ ...cipherToResponse(cipher, attachments, responseOptions), object: 'cipherMiniDetails' });
  // A member who dropped its last collection holding the item can no longer read it; upstream
  // answers unavailable and the client deletes its local copy.
  const readable = await loadAccessibleCipher(env, env.DB, userId, cipher.id, 'read');
  return jsonResponse({
    object: 'optionalCipherDetails',
    unavailable: !readable,
    cipher: readable ? cipherToResponse(readable, attachments, responseOptions) : null,
  });
}

// DELETE /api/ciphers/:id
export async function handleDeleteCipher(request: Request, env: Env, userId: string, id: string, asAdmin = false): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, asAdmin ? 'admin-edit' : 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const wasDeleted = !!cipher.deletedAt;
  // Soft delete
  cipher.deletedAt = new Date().toISOString();
  cipher.updatedAt = cipher.deletedAt;
  syncCipherComputedAliases(cipher);
  await cipherRepo.saveCipher(env.DB, cipher);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherDelete, wasDeleted ? undefined : EventType.CipherSoftDeleted);
  await writeDataAudit(env.DB, request, userId, 'cipher', 'cipher.delete.soft', {
    id: cipher.id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return asAdmin ? new Response(null, { status: 200 }) : cipherJsonResponse(request, cipher);
}

// DELETE /api/ciphers/:id (compat mode)
// Bitwarden clients may call DELETE on a trashed item to purge it permanently.
// For compatibility:
// - If item is active -> soft delete.
// - If item is already soft-deleted -> hard delete.
export async function handleDeleteCipherCompat(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  if (cipher.deletedAt) {
    await deleteAllAttachmentsForCipher(env, id);
    await deleteAuthorizedCipher(env.DB, cipher, userId);
    await afterCipherMutation(request, env, userId, cipher, notifyUserCipherDelete, EventType.CipherDeleted);
    await writeDataAudit(env.DB, request, userId, 'cipher', 'cipher.delete.permanent', {
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
export async function handlePermanentDeleteCipher(request: Request, env: Env, userId: string, id: string, asAdmin = false): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, asAdmin ? 'admin-edit' : 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  // Delete all attachments first
  await deleteAllAttachmentsForCipher(env, id);

  await deleteAuthorizedCipher(env.DB, cipher, userId);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherDelete, EventType.CipherDeleted);
  await writeDataAudit(env.DB, request, userId, 'cipher', 'cipher.delete.permanent', {
    id,
    type: cipher.type,
    folderId: cipher.folderId ?? null,
  });

  return new Response(null, { status: 204 });
}

// PUT /api/ciphers/:id/restore
export async function handleRestoreCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const wasDeleted = !!cipher.deletedAt;
  cipher.deletedAt = null;
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);
  await cipherRepo.saveCipher(env.DB, cipher);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate, wasDeleted ? EventType.CipherRestored : undefined);

  return cipherJsonResponse(request, cipher);
}

// PUT /api/ciphers/:id/partial - Update only favorite/folderId
export async function handlePartialUpdateCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const body = await parseBody(request, z.object({ folderId: z.unknown().optional(), favorite: z.boolean().optional() }));
  if (body instanceof Response) return body;

  if (body.folderId !== undefined) {
    const folderId = normalizeOptionalId(body.folderId);
    if (folderId) {
      const folderOk = await verifyFolderOwnership(env.DB, folderId, userId);
      if (!folderOk) return errorResponse('Folder not found', 404);
    }
    cipher.folderId = folderId;
  }
  if (body.favorite !== undefined) {
    cipher.favorite = body.favorite;
  }
  cipher.updatedAt = new Date().toISOString();
  syncCipherComputedAliases(cipher);

  await cipherRepo.saveCipher(env.DB, cipher);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate);

  return cipherJsonResponse(request, cipher);
}

// POST/PUT /api/ciphers/move - Bulk move to folder
export async function handleBulkMoveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody.extend({ folderId: z.unknown().optional() }));
  if (body instanceof Response) return body;

  const folderId = normalizeOptionalId(body.folderId);
  if (folderId) {
    const folderOk = await verifyFolderOwnership(env.DB, folderId, userId);
    if (!folderOk) return errorResponse('Folder not found', 404);
  }

  const revisionDate = await cipherRepo.bulkMoveCiphers(env.DB, body.ids, folderId, userId);
  if (revisionDate) notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));

  return new Response(null, { status: 204 });
}

async function buildCipherListResponse(
  request: Request,
  db: D1Database,
  userId: string,
  ids: string[]
): Promise<Response> {
  const ciphers = await cipherRepo.getCiphersByIds(db, ids, userId);
  const attachmentsByCipher = await attachmentRepo.getAttachmentsByCipherIds(db, ciphers.map((cipher) => cipher.id));

  return jsonResponse({
    data: ciphers.map((cipher) =>
      cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], cipherResponseOptionsForRequest(request))
    ),
    object: 'list',
    continuationToken: null,
  });
}

// PUT/POST /api/ciphers/:id/archive
export async function handleArchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);
  if (cipher.deletedAt) {
    return errorResponse('Cannot archive a deleted cipher', 400);
  }

  cipher.archivedAt = new Date().toISOString();
  cipher.updatedAt = cipher.archivedAt;
  normalizeCipherForStorage(cipher);
  await cipherRepo.saveCipher(env.DB, cipher);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate);

  return cipherJsonResponse(request, cipher, await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id));
}

// PUT/POST /api/ciphers/:id/unarchive
export async function handleUnarchiveCipher(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const cipher = await loadAccessibleCipher(env, env.DB, userId, id, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  cipher.archivedAt = null;
  cipher.updatedAt = new Date().toISOString();
  normalizeCipherForStorage(cipher);
  await cipherRepo.saveCipher(env.DB, cipher);
  await afterCipherMutation(request, env, userId, cipher, notifyUserCipherUpdate);

  return cipherJsonResponse(request, cipher, await attachmentRepo.getAttachmentsByCipher(env.DB, cipher.id));
}

// PUT/POST /api/ciphers/archive
export async function handleBulkArchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody);
  if (body instanceof Response) return body;
  const { ids } = body;
  return finishBulkCipherState(request, env, userId, ids, cipherRepo.bulkArchiveCiphers, null,
    () => buildCipherListResponse(request, env.DB, userId, ids));
}

// PUT/POST /api/ciphers/unarchive
export async function handleBulkUnarchiveCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody);
  if (body instanceof Response) return body;
  const { ids } = body;
  return finishBulkCipherState(request, env, userId, ids, cipherRepo.bulkUnarchiveCiphers, null,
    () => buildCipherListResponse(request, env.DB, userId, ids));
}

// POST /api/ciphers/delete - Bulk soft delete
export async function handleBulkDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody);
  if (body instanceof Response) return body;
  return finishBulkCipherState(request, env, userId, body.ids, cipherRepo.bulkSoftDeleteCiphers,
    { action: 'cipher.delete.soft.bulk', metadata: { count: body.ids.length } }, () => new Response(null, { status: 204 }));
}

// POST /api/ciphers/restore - Bulk restore
export async function handleBulkRestoreCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody);
  if (body instanceof Response) return body;
  return finishBulkCipherState(request, env, userId, body.ids, cipherRepo.bulkRestoreCiphers, null,
    () => new Response(null, { status: 204 }));
}

// POST /api/ciphers/delete-permanent - Bulk permanent delete
export async function handleBulkPermanentDeleteCiphers(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, CipherIdsBody);
  if (body instanceof Response) return body;
  const { ids } = body;
  if (!ids.length) {
    return new Response(null, { status: 204 });
  }

  const ownedCiphers = await cipherRepo.getCiphersByIds(env.DB, ids, userId);
  const ownedIds = ownedCiphers.map((cipher) => cipher.id);
  if (!ownedIds.length) {
    return new Response(null, { status: 204 });
  }

  await deleteAllAttachmentsForCiphers(env, ownedIds);
  return finishBulkCipherState(request, env, userId, ownedIds, cipherRepo.bulkDeleteCiphers,
    { action: 'cipher.delete.permanent.bulk', metadata: { count: ownedIds.length, requestedCount: ids.length } },
    () => new Response(null, { status: 204 }));
}
