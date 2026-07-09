import { User, Cipher, Folder, Attachment, Device, Invite, AuditLog, Send, TrustedDeviceTokenSummary, RefreshTokenRecord, CustomEquivalentDomain, AccountPasskeyChallenge, AccountPasskeyChallengeScope, AccountPasskeyCredential, AuthRequestRecord } from '../types';
import { LIMITS } from '../config/limits';
import { ensurePushInstallationCredentials } from './push-relay';
import { ensureStorageSchema } from './storage-schema';
import {
  getConfigValue as getStoredConfigValue,
  isRegistered as getRegisteredFlag,
  setConfigValue as saveConfigValue,
  setRegistered as saveRegisteredFlag,
} from './storage-config-repo';
import {
  createFirstUser as createFirstStoredUser,
  createUser as createStoredUser,
  deleteUserById as deleteStoredUserById,
  getAllUsers as listStoredUsers,
  getUser as findStoredUserByEmail,
  getUserById as findStoredUserById,
  getUserCount as countStoredUsers,
  saveUser as saveStoredUser,
} from './storage-user-repo';
import {
  type AuditLogListOptions,
  createAuditLog as createStoredAuditLog,
  clearAuditLogs as clearStoredAuditLogs,
  assignInviteUsedBy as assignStoredInviteUsedBy,
  createInvite as createStoredInvite,
  deleteInvite as deleteStoredInvite,
  deleteInvalidInvites as deleteStoredInvalidInvites,
  deleteAllInvites as deleteStoredInvites,
  getInvite as findStoredInvite,
  listAuditLogs as listStoredAuditLogs,
  listInvites as listStoredInvites,
  markInviteUsed as markStoredInviteUsed,
  pruneAuditLogs as pruneStoredAuditLogs,
  pruneAuditLogsToMax as pruneStoredAuditLogsToMax,
  revertInviteUsed as revertStoredInviteUsed,
} from './storage-admin-repo';
import {
  bulkDeleteFolders as deleteStoredFolders,
  clearFolderFromCiphers as clearStoredFolderFromCiphers,
  deleteFolder as deleteStoredFolder,
  getAllFolders as listStoredFolders,
  getFolder as findStoredFolder,
  getFolderForUser as findStoredFolderForUser,
  getFoldersPage as listStoredFoldersPage,
  saveFolder as saveStoredFolder,
} from './storage-folder-repo';
import {
  bulkArchiveCiphers as archiveStoredCiphers,
  bulkDeleteCiphers as deleteStoredCiphers,
  bulkMoveCiphers as moveStoredCiphers,
  bulkRestoreCiphers as restoreStoredCiphers,
  bulkSoftDeleteCiphers as softDeleteStoredCiphers,
  bulkUnarchiveCiphers as unarchiveStoredCiphers,
  getAllCiphers as listStoredCiphers,
  getCipher as findStoredCipher,
  getCipherForUser as findStoredCipherForUser,
  getCiphersByIds as listStoredCiphersByIds,
  getCiphersPage as listStoredCiphersPage,
  saveCipher as saveStoredCipher,
  deleteCipher as deleteStoredCipher,
} from './storage-cipher-repo';
import {
  addAttachmentToCipher as attachStoredAttachmentToCipher,
  addAttachmentToCipherForUser as attachStoredAttachmentToCipherForUser,
  bulkDeleteAttachmentsByIds as deleteStoredAttachmentsByIds,
  deleteAllAttachmentsByCipher as deleteStoredAttachmentsByCipher,
  deleteAttachment as deleteStoredAttachment,
  deleteAttachmentForUser as deleteStoredAttachmentForUser,
  getAttachment as findStoredAttachment,
  getAttachmentForUser as findStoredAttachmentForUser,
  getAttachmentsByCipher as listStoredAttachmentsByCipher,
  getAttachmentsByCipherIds as listStoredAttachmentsByCipherIds,
  getAttachmentsByUserId as listStoredAttachmentsByUserId,
  saveAttachment as saveStoredAttachment,
  updateCipherRevisionDate as updateStoredCipherRevisionDate,
} from './storage-attachment-repo';
import {
  bulkDeleteSends as deleteStoredSends,
  deleteSend as deleteStoredSend,
  getAllSends as listStoredSends,
  getSend as findStoredSend,
  getSendForUser as findStoredSendForUser,
  getSendsByIds as listStoredSendsByIds,
  getSendsPage as listStoredSendsPage,
  incrementSendAccessCount as incrementStoredSendAccessCount,
  saveSend as saveStoredSend,
} from './storage-send-repo';
import {
  constrainRefreshTokenExpiry as constrainStoredRefreshTokenExpiry,
  deleteRefreshToken as deleteStoredRefreshToken,
  deleteRefreshTokensByDevice as deleteStoredRefreshTokensByDevice,
  deleteRefreshTokensByUserId as deleteStoredRefreshTokensByUserId,
  getRefreshTokenRecord as findStoredRefreshTokenRecord,
  saveRefreshToken as saveStoredRefreshToken,
} from './storage-refresh-token-repo';
import {
  deleteDevice as deleteStoredDevice,
  deleteDevicesByUserId as deleteStoredDevicesByUserId,
  clearDevicePushToken as clearStoredDevicePushToken,
  clearDeviceKeys as clearStoredDeviceKeys,
  deleteTrustedTwoFactorTokensByDevice as deleteStoredTrustedTokensByDevice,
  deleteTrustedTwoFactorTokensByUserId as deleteStoredTrustedTokensByUserId,
  getDevice as findStoredDevice,
  getDevicePushUuid as findStoredDevicePushUuid,
  getDevicesByUserId as listStoredDevicesByUserId,
  getTrustedDeviceTokenSummariesByUserId as listStoredTrustedTokenSummaries,
  getTrustedTwoFactorDeviceTokenUserId as findStoredTrustedTokenUserId,
  isKnownDevice as getKnownStoredDevice,
  isKnownDeviceByEmail as getKnownStoredDeviceByEmail,
  saveTrustedTwoFactorDeviceToken as saveStoredTrustedDeviceToken,
  rotateDeviceSessionStamp as rotateStoredDeviceSessionStamp,
  touchDeviceLastSeen as touchStoredDeviceLastSeen,
  upsertDevice as saveStoredDevice,
  updateDeviceName as updateStoredDeviceName,
  updateDeviceKeys as updateStoredDeviceKeys,
  updateDevicePushToken as updateStoredDevicePushToken,
  updateTrustedTwoFactorTokensExpiryByDevice as updateStoredTrustedTokensExpiryByDevice,
  userHasPushDevice as getUserHasPushDevice,
} from './storage-device-repo';
import {
  createAuthRequest as createStoredAuthRequest,
  getAuthRequestById as findStoredAuthRequestById,
  getAuthRequestByIdForUser as findStoredAuthRequestByIdForUser,
  listAuthRequestsByUserId as listStoredAuthRequestsByUserId,
  listPendingAuthRequestsByUserId as listStoredPendingAuthRequestsByUserId,
  markAuthRequestAuthenticated as markStoredAuthRequestAuthenticated,
  pruneExpiredAuthRequests as pruneStoredExpiredAuthRequests,
  updateAuthRequestResponse as updateStoredAuthRequestResponse,
} from './storage-auth-request-repo';
import {
  ensureUsedAttachmentDownloadTokenTable as ensureStoredAttachmentTokenTable,
  consumeAttachmentDownloadToken as consumeStoredAttachmentDownloadToken,
} from './storage-attachment-token-repo';
import {
  consumeTotpLoginCounter as consumeStoredTotpLoginCounter,
} from './storage-totp-replay-repo';
import {
  getRevisionDate as getStoredRevisionDate,
  updateRevisionDate as updateStoredRevisionDate,
} from './storage-revision-repo';
import {
  getUserDomainSettings as getStoredUserDomainSettings,
  saveUserDomainSettings as saveStoredUserDomainSettings,
} from './storage-domain-rules-repo';
import {
  consumeAccountPasskeyChallenge as consumeStoredAccountPasskeyChallenge,
  countAccountPasskeyCredentialsByUserId as countStoredAccountPasskeyCredentialsByUserId,
  deleteAccountPasskeyCredential as deleteStoredAccountPasskeyCredential,
  getAccountPasskeyCredentialByCredentialId as findStoredAccountPasskeyCredentialByCredentialId,
  getAccountPasskeyCredentialById as findStoredAccountPasskeyCredentialById,
  listAccountPasskeyCredentialsByUserId as listStoredAccountPasskeyCredentialsByUserId,
  saveAccountPasskeyChallenge as saveStoredAccountPasskeyChallenge,
  saveAccountPasskeyCredential as saveStoredAccountPasskeyCredential,
  updateAccountPasskeyCounter as updateStoredAccountPasskeyCounter,
  updateAccountPasskeyEncryption as updateStoredAccountPasskeyEncryption,
} from './storage-account-passkey-repo';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const STORAGE_SCHEMA_VERSION_KEY = 'schema.version';
// IMPORTANT:
// Bump this whenever src/services/storage-schema.ts or migrations/0001_init.sql
// changes. Existing D1 installs only rerun ensureStorageSchema() when this value
// differs from config.schema.version.
const STORAGE_SCHEMA_VERSION = '2026-07-05-passkey-2fa';
const REQUIRED_SCHEMA_TABLES = ['webauthn_credentials', 'webauthn_challenges', 'auth_requests', 'totp_login_replays'] as const;

// D1-backed storage.
// Contract:
// - All methods are scoped by userId where applicable.
// - Uses SQL constraints (PK/unique/FK) to avoid KV-style index race conditions.
// - Revision date is maintained per user for Bitwarden sync.

export class StorageService {
  private static attachmentTokenTableReady = false;
  private static schemaVerified = false;
  private static lastRefreshTokenCleanupAt = 0;
  private static lastAttachmentTokenCleanupAt = 0;
  private static lastTotpReplayCleanupAt = 0;
  private static readonly MAX_D1_SQL_VARIABLES = 100;

  private static readonly REFRESH_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.refreshTokenCleanupIntervalMs;
  private static readonly ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS = LIMITS.cleanup.attachmentTokenCleanupIntervalMs;
  private static readonly TOTP_REPLAY_CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
  private static readonly TOTP_REPLAY_MARKER_TTL_MS = 5 * 60 * 1000;
  private static readonly PERIODIC_CLEANUP_PROBABILITY = LIMITS.cleanup.cleanupProbability;

  constructor(private db: D1Database) {}

  /**
   * D1 .bind() throws on `undefined` values. This helper converts every
   * `undefined` in the argument list to `null` so we never hit that runtime
   * error - especially important after the opaque-passthrough change where
   * client-supplied JSON may omit fields we later reference as columns.
   */
  private safeBind(stmt: D1PreparedStatement, ...values: any[]): D1PreparedStatement {
    return stmt.bind(...values.map(v => v === undefined ? null : v));
  }

  private async hasRequiredSchemaTables(): Promise<boolean> {
    const placeholders = REQUIRED_SCHEMA_TABLES.map(() => '?').join(', ');
    const result = await this.db
      .prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`)
      .bind(...REQUIRED_SCHEMA_TABLES)
      .all<{ name: string }>();
    const found = new Set((result.results || []).map((row) => row.name));
    return REQUIRED_SCHEMA_TABLES.every((table) => found.has(table));
  }

  private sqlChunkSize(fixedBindCount: number): number {
    return Math.max(
      1,
      Math.min(LIMITS.performance.bulkMoveChunkSize, StorageService.MAX_D1_SQL_VARIABLES - fixedBindCount)
    );
  }

  private async sha256Hex(input: string): Promise<string> {
    const bytes = new TextEncoder().encode(input);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  private async refreshTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  private shouldRunPeriodicCleanup(lastRunAt: number, intervalMs: number): boolean {
    const now = Date.now();
    if (now - lastRunAt < intervalMs) return false;
    return Math.random() < StorageService.PERIODIC_CLEANUP_PROBABILITY;
  }

  private async maybeCleanupExpiredRefreshTokens(nowMs: number): Promise<void> {
    if (!this.shouldRunPeriodicCleanup(StorageService.lastRefreshTokenCleanupAt, StorageService.REFRESH_TOKEN_CLEANUP_INTERVAL_MS)) {
      return;
    }

    await this.db.prepare('DELETE FROM refresh_tokens WHERE expires_at < ?').bind(nowMs).run();
    StorageService.lastRefreshTokenCleanupAt = nowMs;
  }

  // --- Database initialization ---
  // Strategy:
  // - Run only once per isolate.
  // - Execute idempotent schema SQL on first request in each isolate.
  // - Keep statements idempotent so updates are safe.
  async initializeDatabase(): Promise<void> {
    if (StorageService.schemaVerified) return;

    await this.db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
    const schemaVersion = await getStoredConfigValue(this.db, STORAGE_SCHEMA_VERSION_KEY);
    const schemaMissingRequiredTables = schemaVersion === STORAGE_SCHEMA_VERSION
      ? !(await this.hasRequiredSchemaTables())
      : true;
    if (schemaVersion !== STORAGE_SCHEMA_VERSION || schemaMissingRequiredTables) {
      await ensureStorageSchema(this.db);
      await saveConfigValue(this.db, STORAGE_SCHEMA_VERSION_KEY, STORAGE_SCHEMA_VERSION);
    }
    await ensurePushInstallationCredentials(this.db);

    StorageService.schemaVerified = true;
  }

  // --- Config / setup ---

  async isRegistered(): Promise<boolean> {
    return getRegisteredFlag(this.db);
  }

  async getConfigValue(key: string): Promise<string | null> {
    return getStoredConfigValue(this.db, key);
  }

  async setConfigValue(key: string, value: string): Promise<void> {
    await saveConfigValue(this.db, key, value);
  }

  async setRegistered(): Promise<void> {
    await saveRegisteredFlag(this.db);
  }

  // --- Users ---

  async getUser(email: string): Promise<User | null> {
    return findStoredUserByEmail(this.db, email);
  }

  async getUserById(id: string): Promise<User | null> {
    return findStoredUserById(this.db, id);
  }

  async getUserCount(): Promise<number> {
    return countStoredUsers(this.db);
  }

  async getAllUsers(): Promise<User[]> {
    return listStoredUsers(this.db);
  }

  async saveUser(user: User): Promise<void> {
    await saveStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async createUser(user: User): Promise<void> {
    await createStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async createFirstUser(user: User): Promise<boolean> {
    return createFirstStoredUser(this.db, this.safeBind.bind(this), user);
  }

  async deleteUserById(id: string): Promise<boolean> {
    return deleteStoredUserById(this.db, id);
  }

  async createInvite(invite: Invite): Promise<void> {
    await createStoredInvite(this.db, invite);
  }

  async getInvite(code: string): Promise<Invite | null> {
    return findStoredInvite(this.db, code);
  }

  async listInvites(includeInactive: boolean = false): Promise<Invite[]> {
    return listStoredInvites(this.db, includeInactive);
  }

  async markInviteUsed(code: string, userId: string): Promise<boolean> {
    return markStoredInviteUsed(this.db, code, userId);
  }

  async assignInviteUsedBy(code: string, userId: string): Promise<boolean> {
    return assignStoredInviteUsedBy(this.db, code, userId);
  }

  async revertInviteUsed(code: string, userId: string): Promise<boolean> {
    return revertStoredInviteUsed(this.db, code, userId);
  }

  async deleteInvite(code: string): Promise<boolean> {
    return deleteStoredInvite(this.db, code);
  }

  async deleteInvalidInvites(): Promise<number> {
    return deleteStoredInvalidInvites(this.db);
  }

  async deleteAllInvites(): Promise<number> {
    return deleteStoredInvites(this.db);
  }

  async createAuditLog(log: AuditLog): Promise<void> {
    await createStoredAuditLog(this.db, log);
  }

  async listAuditLogs(options: AuditLogListOptions): Promise<{ logs: AuditLog[]; total: number; hasMore: boolean }> {
    return listStoredAuditLogs(this.db, options);
  }

  async pruneAuditLogs(beforeIso: string): Promise<number> {
    return pruneStoredAuditLogs(this.db, beforeIso);
  }

  async pruneAuditLogsToMax(maxEntries: number): Promise<number> {
    return pruneStoredAuditLogsToMax(this.db, maxEntries);
  }

  async clearAuditLogs(): Promise<number> {
    return clearStoredAuditLogs(this.db);
  }

  // --- Domain rules ---

  async getUserDomainSettings(userId: string) {
    return getStoredUserDomainSettings(this.db, userId);
  }

  async saveUserDomainSettings(
    userId: string,
    equivalentDomains: string[][],
    customEquivalentDomains: CustomEquivalentDomain[],
    excludedGlobalEquivalentDomains: number[]
  ): Promise<void> {
    await saveStoredUserDomainSettings(
      this.db,
      userId,
      equivalentDomains,
      customEquivalentDomains,
      excludedGlobalEquivalentDomains,
      new Date().toISOString()
    );
    await this.updateRevisionDate(userId);
  }

  // --- Account passkeys / WebAuthn login credentials ---

  async saveAccountPasskeyCredential(credential: AccountPasskeyCredential): Promise<void> {
    await saveStoredAccountPasskeyCredential(this.db, this.safeBind.bind(this), credential);
  }

  async getAccountPasskeyCredentialsByUserId(
    userId: string,
    purpose: AccountPasskeyCredential['purpose'] = 'login'
  ): Promise<AccountPasskeyCredential[]> {
    return listStoredAccountPasskeyCredentialsByUserId(this.db, userId, purpose);
  }

  async getAccountPasskeyCredentialById(userId: string, id: string): Promise<AccountPasskeyCredential | null> {
    return findStoredAccountPasskeyCredentialById(this.db, userId, id);
  }

  async getAccountPasskeyCredentialByCredentialId(credentialId: string): Promise<AccountPasskeyCredential | null> {
    return findStoredAccountPasskeyCredentialByCredentialId(this.db, credentialId);
  }

  async countAccountPasskeyCredentialsByUserId(
    userId: string,
    purpose: AccountPasskeyCredential['purpose'] = 'login'
  ): Promise<number> {
    return countStoredAccountPasskeyCredentialsByUserId(this.db, userId, purpose);
  }

  async updateAccountPasskeyCounter(
    userId: string,
    credentialId: string,
    counter: number,
    updatedAt: string = new Date().toISOString()
  ): Promise<void> {
    await updateStoredAccountPasskeyCounter(this.db, userId, credentialId, counter, updatedAt);
  }

  async updateAccountPasskeyEncryption(
    userId: string,
    credentialId: string,
    encryptedUserKey: string,
    encryptedPublicKey: string,
    encryptedPrivateKey: string,
    updatedAt: string = new Date().toISOString()
  ): Promise<boolean> {
    return updateStoredAccountPasskeyEncryption(
      this.db,
      userId,
      credentialId,
      encryptedUserKey,
      encryptedPublicKey,
      encryptedPrivateKey,
      updatedAt
    );
  }

  async deleteAccountPasskeyCredential(
    userId: string,
    id: string,
    purpose: AccountPasskeyCredential['purpose'] = 'login'
  ): Promise<boolean> {
    return deleteStoredAccountPasskeyCredential(this.db, userId, id, purpose);
  }

  async saveAccountPasskeyChallenge(challenge: AccountPasskeyChallenge): Promise<void> {
    await saveStoredAccountPasskeyChallenge(this.db, challenge);
  }

  async consumeAccountPasskeyChallenge(
    challengeHash: string,
    scope: AccountPasskeyChallengeScope,
    userId: string | null,
    nowMs: number = Date.now()
  ): Promise<AccountPasskeyChallenge | null> {
    return consumeStoredAccountPasskeyChallenge(this.db, challengeHash, scope, userId, nowMs);
  }

  // --- Ciphers ---

  async getCipher(id: string): Promise<Cipher | null> {
    return findStoredCipher(this.db, id);
  }

  async getCipherForUser(id: string, userId: string): Promise<Cipher | null> {
    return findStoredCipherForUser(this.db, id, userId);
  }

  async saveCipher(cipher: Cipher): Promise<void> {
    await saveStoredCipher(this.db, this.safeBind.bind(this), cipher);
  }

  async deleteCipher(id: string, userId: string): Promise<void> {
    await deleteStoredCipher(this.db, id, userId);
  }

  async bulkSoftDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    return softDeleteStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkRestoreCiphers(ids: string[], userId: string): Promise<string | null> {
    return restoreStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkArchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    return archiveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkUnarchiveCiphers(ids: string[], userId: string): Promise<string | null> {
    return unarchiveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async bulkDeleteCiphers(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async getAllCiphers(userId: string): Promise<Cipher[]> {
    return listStoredCiphers(this.db, userId);
  }

  async getCiphersPage(userId: string, includeDeleted: boolean, limit: number, offset: number): Promise<Cipher[]> {
    return listStoredCiphersPage(this.db, userId, includeDeleted, limit, offset);
  }

  async getCiphersByIds(ids: string[], userId: string): Promise<Cipher[]> {
    return listStoredCiphersByIds(this.db, this.sqlChunkSize.bind(this), ids, userId);
  }

  async bulkMoveCiphers(ids: string[], folderId: string | null, userId: string): Promise<string | null> {
    return moveStoredCiphers(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, folderId, userId);
  }

  // --- Folders ---

  async getFolder(id: string): Promise<Folder | null> {
    return findStoredFolder(this.db, id);
  }

  async getFolderForUser(id: string, userId: string): Promise<Folder | null> {
    return findStoredFolderForUser(this.db, id, userId);
  }

  async saveFolder(folder: Folder): Promise<void> {
    await saveStoredFolder(this.db, folder);
  }

  async deleteFolder(id: string, userId: string): Promise<void> {
    await deleteStoredFolder(this.db, id, userId);
  }

  async bulkDeleteFolders(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredFolders(
      this.db,
      userId,
      ids,
      this.sqlChunkSize.bind(this),
      this.updateRevisionDate.bind(this)
    );
  }

  // Clear folder references from all ciphers owned by the user.
  // Without this, deleting a folder leaves stale folderId values in cipher JSON.
  async clearFolderFromCiphers(userId: string, folderId: string): Promise<void> {
    await clearStoredFolderFromCiphers(this.db, userId, folderId);
  }

  async getAllFolders(userId: string): Promise<Folder[]> {
    return listStoredFolders(this.db, userId);
  }

  async getFoldersPage(userId: string, limit: number, offset: number): Promise<Folder[]> {
    return listStoredFoldersPage(this.db, userId, limit, offset);
  }

  // --- Attachments ---

  async getAttachment(id: string): Promise<Attachment | null> {
    return findStoredAttachment(this.db, id);
  }

  async getAttachmentForUser(id: string, userId: string): Promise<Attachment | null> {
    return findStoredAttachmentForUser(this.db, id, userId);
  }

  async saveAttachment(attachment: Attachment): Promise<void> {
    await saveStoredAttachment(this.db, this.safeBind.bind(this), attachment);
  }

  async deleteAttachment(id: string): Promise<void> {
    await deleteStoredAttachment(this.db, id);
  }

  async deleteAttachmentForUser(id: string, userId: string): Promise<void> {
    await deleteStoredAttachmentForUser(this.db, id, userId);
  }

  async bulkDeleteAttachmentsByIds(ids: string[]): Promise<void> {
    await deleteStoredAttachmentsByIds(this.db, this.sqlChunkSize.bind(this), ids);
  }

  async getAttachmentsByCipher(cipherId: string): Promise<Attachment[]> {
    return listStoredAttachmentsByCipher(this.db, cipherId);
  }

  async getAttachmentsByCipherIds(cipherIds: string[]): Promise<Map<string, Attachment[]>> {
    return listStoredAttachmentsByCipherIds(this.db, this.sqlChunkSize.bind(this), cipherIds);
  }

  async getAttachmentsByUserId(userId: string): Promise<Map<string, Attachment[]>> {
    return listStoredAttachmentsByUserId(this.db, userId);
  }

  async addAttachmentToCipher(cipherId: string, attachmentId: string): Promise<void> {
    await attachStoredAttachmentToCipher(this.db, cipherId, attachmentId);
  }

  async addAttachmentToCipherForUser(cipherId: string, attachmentId: string, userId: string): Promise<void> {
    await attachStoredAttachmentToCipherForUser(this.db, cipherId, attachmentId, userId);
  }

  async deleteAllAttachmentsByCipher(cipherId: string): Promise<void> {
    await deleteStoredAttachmentsByCipher(this.db, cipherId);
  }

  async updateCipherRevisionDate(cipherId: string): Promise<{ userId: string; revisionDate: string } | null> {
    return updateStoredCipherRevisionDate(
      this.getCipher.bind(this),
      this.saveCipher.bind(this),
      this.updateRevisionDate.bind(this),
      cipherId
    );
  }

  // --- Refresh tokens ---

  async saveRefreshToken(
    token: string,
    userId: string,
    expiresAtMs?: number,
    deviceIdentifier?: string | null,
    deviceSessionStamp?: string | null
  ): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + LIMITS.auth.refreshTokenTtlMs);
    await saveStoredRefreshToken(
      this.db,
      this.refreshTokenKey.bind(this),
      this.maybeCleanupExpiredRefreshTokens.bind(this),
      token,
      userId,
      expiresAt,
      deviceIdentifier,
      deviceSessionStamp
    );
  }

  async getRefreshTokenRecord(token: string): Promise<RefreshTokenRecord | null> {
    return findStoredRefreshTokenRecord(
      this.db,
      this.refreshTokenKey.bind(this),
      this.maybeCleanupExpiredRefreshTokens.bind(this),
      this.deleteRefreshToken.bind(this),
      token
    );
  }

  async getRefreshTokenUserId(token: string): Promise<string | null> {
    const record = await this.getRefreshTokenRecord(token);
    return record?.userId ?? null;
  }

  async deleteRefreshToken(token: string): Promise<void> {
    await deleteStoredRefreshToken(this.db, this.refreshTokenKey.bind(this), token);
  }

  // --- Sends ---

  async getSend(id: string): Promise<Send | null> {
    return findStoredSend(this.db, id);
  }

  async getSendForUser(id: string, userId: string): Promise<Send | null> {
    return findStoredSendForUser(this.db, id, userId);
  }

  async saveSend(send: Send): Promise<void> {
    await saveStoredSend(this.db, this.safeBind.bind(this), send);
  }

  /**
   * Atomically increment access_count and update updated_at.
   * Returns true if the row was updated (send still available),
   * false if max_access_count has already been reached.
   */
  async incrementSendAccessCount(sendId: string): Promise<boolean> {
    return incrementStoredSendAccessCount(this.db, sendId);
  }

  async deleteSend(id: string, userId: string): Promise<void> {
    await deleteStoredSend(this.db, id, userId);
  }

  async getSendsByIds(ids: string[], userId: string): Promise<Send[]> {
    return listStoredSendsByIds(this.db, this.sqlChunkSize.bind(this), ids, userId);
  }

  async bulkDeleteSends(ids: string[], userId: string): Promise<string | null> {
    return deleteStoredSends(this.db, this.sqlChunkSize.bind(this), this.updateRevisionDate.bind(this), ids, userId);
  }

  async getAllSends(userId: string): Promise<Send[]> {
    return listStoredSends(this.db, userId);
  }

  async getSendsPage(userId: string, limit: number, offset: number): Promise<Send[]> {
    return listStoredSendsPage(this.db, userId, limit, offset);
  }

  async deleteRefreshTokensByUserId(userId: string): Promise<number> {
    return deleteStoredRefreshTokensByUserId(this.db, userId);
  }

  async deleteRefreshTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    return deleteStoredRefreshTokensByDevice(this.db, userId, deviceIdentifier);
  }

  // Keep a short overlap window for rotated refresh token to reduce
  // multi-context refresh races (e.g. browser extension popup/background).
  // Expiry is only tightened, never extended.
  async constrainRefreshTokenExpiry(token: string, maxExpiresAtMs: number): Promise<void> {
    await constrainStoredRefreshTokenExpiry(this.db, this.refreshTokenKey.bind(this), token, maxExpiresAtMs);
  }

  private async trustedTwoFactorTokenKey(token: string): Promise<string> {
    const digest = await this.sha256Hex(token);
    return `sha256:${digest}`;
  }

  // --- Devices ---

  async upsertDevice(
    userId: string,
    deviceIdentifier: string,
    name: string,
    type: number,
    sessionStamp?: string,
    keys?: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    }
  ): Promise<void> {
    await saveStoredDevice(this.db, this.getDevice.bind(this), userId, deviceIdentifier, name, type, sessionStamp, keys);
  }

  async isKnownDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    return getKnownStoredDevice(this.db, userId, deviceIdentifier);
  }

  async isKnownDeviceByEmail(email: string, deviceIdentifier: string): Promise<boolean> {
    return getKnownStoredDeviceByEmail(this.getUser.bind(this), this.isKnownDevice.bind(this), email, deviceIdentifier);
  }

  async getDevicesByUserId(userId: string): Promise<Device[]> {
    return listStoredDevicesByUserId(this.db, userId);
  }

  async getDevice(userId: string, deviceIdentifier: string): Promise<Device | null> {
    return findStoredDevice(this.db, userId, deviceIdentifier);
  }

  async rotateDeviceSessionStamp(userId: string, deviceIdentifier: string, sessionStamp: string): Promise<boolean> {
    return rotateStoredDeviceSessionStamp(this.db, userId, deviceIdentifier, sessionStamp);
  }

  async updateDeviceKeys(
    userId: string,
    deviceIdentifier: string,
    keys: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    }
  ): Promise<boolean> {
    return updateStoredDeviceKeys(this.db, userId, deviceIdentifier, keys);
  }

  async updateDeviceName(userId: string, deviceIdentifier: string, name: string): Promise<boolean> {
    return updateStoredDeviceName(this.db, userId, deviceIdentifier, name);
  }

  async touchDeviceLastSeen(userId: string, deviceIdentifier: string): Promise<boolean> {
    return touchStoredDeviceLastSeen(this.db, userId, deviceIdentifier);
  }

  async updateDevicePushToken(
    userId: string,
    deviceIdentifier: string,
    pushUuid: string,
    pushToken: string
  ): Promise<boolean> {
    return updateStoredDevicePushToken(this.db, userId, deviceIdentifier, pushUuid, pushToken);
  }

  async clearDevicePushToken(userId: string, deviceIdentifier: string): Promise<{ pushUuid: string | null } | null> {
    return clearStoredDevicePushToken(this.db, userId, deviceIdentifier);
  }

  async getDevicePushUuid(userId: string, deviceIdentifier: string): Promise<string | null> {
    return findStoredDevicePushUuid(this.db, userId, deviceIdentifier);
  }

  async userHasPushDevice(userId: string): Promise<boolean> {
    return getUserHasPushDevice(this.db, userId);
  }

  async clearDeviceKeys(userId: string, deviceIdentifiers: string[]): Promise<number> {
    return clearStoredDeviceKeys(this.db, userId, deviceIdentifiers);
  }

  async deleteDevice(userId: string, deviceIdentifier: string): Promise<boolean> {
    return deleteStoredDevice(this.db, userId, deviceIdentifier);
  }

  async deleteDevicesByUserId(userId: string): Promise<number> {
    return deleteStoredDevicesByUserId(this.db, userId);
  }

  // --- Auth requests / Login with device ---

  async createAuthRequest(request: AuthRequestRecord): Promise<void> {
    await createStoredAuthRequest(this.db, request);
  }

  async getAuthRequestById(id: string): Promise<AuthRequestRecord | null> {
    return findStoredAuthRequestById(this.db, id);
  }

  async getAuthRequestByIdForUser(id: string, userId: string): Promise<AuthRequestRecord | null> {
    return findStoredAuthRequestByIdForUser(this.db, id, userId);
  }

  async listAuthRequestsByUserId(userId: string): Promise<AuthRequestRecord[]> {
    return listStoredAuthRequestsByUserId(this.db, userId);
  }

  async listPendingAuthRequestsByUserId(userId: string): Promise<AuthRequestRecord[]> {
    return listStoredPendingAuthRequestsByUserId(this.db, userId);
  }

  async updateAuthRequestResponse(
    id: string,
    userId: string,
    update: {
      approved: boolean;
      responseDeviceIdentifier: string;
      key?: string | null;
      masterPasswordHash?: string | null;
    }
  ): Promise<boolean> {
    return updateStoredAuthRequestResponse(this.db, id, userId, update);
  }

  async markAuthRequestAuthenticated(id: string): Promise<boolean> {
    return markStoredAuthRequestAuthenticated(this.db, id);
  }

  async pruneExpiredAuthRequests(): Promise<number> {
    return pruneStoredExpiredAuthRequests(this.db);
  }

  async getTrustedDeviceTokenSummariesByUserId(userId: string): Promise<TrustedDeviceTokenSummary[]> {
    return listStoredTrustedTokenSummaries(this.db, userId);
  }

  async deleteTrustedTwoFactorTokensByDevice(userId: string, deviceIdentifier: string): Promise<number> {
    return deleteStoredTrustedTokensByDevice(this.db, userId, deviceIdentifier);
  }

  async deleteTrustedTwoFactorTokensByUserId(userId: string): Promise<number> {
    return deleteStoredTrustedTokensByUserId(this.db, userId);
  }

  async updateTrustedTwoFactorTokensExpiryByDevice(userId: string, deviceIdentifier: string, expiresAtMs: number): Promise<number> {
    return updateStoredTrustedTokensExpiryByDevice(this.db, userId, deviceIdentifier, expiresAtMs);
  }

  // --- Trusted 2FA remember tokens (device-bound) ---

  async saveTrustedTwoFactorDeviceToken(
    token: string,
    userId: string,
    deviceIdentifier: string,
    expiresAtMs?: number
  ): Promise<void> {
    const expiresAt = expiresAtMs ?? (Date.now() + TWO_FACTOR_REMEMBER_TTL_MS);
    await saveStoredTrustedDeviceToken(this.db, this.trustedTwoFactorTokenKey.bind(this), token, userId, deviceIdentifier, expiresAt);
  }

  async getTrustedTwoFactorDeviceTokenUserId(token: string, deviceIdentifier: string): Promise<string | null> {
    return findStoredTrustedTokenUserId(this.db, this.trustedTwoFactorTokenKey.bind(this), token, deviceIdentifier);
  }

  async consumeTotpLoginCounter(userId: string, timeCounter: number, consumedAtMs: number = Date.now()): Promise<boolean> {
    if (!Number.isSafeInteger(timeCounter) || timeCounter < 0) return false;
    const result = await consumeStoredTotpLoginCounter(
      this.db,
      this.shouldRunPeriodicCleanup.bind(this),
      StorageService.lastTotpReplayCleanupAt,
      StorageService.TOTP_REPLAY_CLEANUP_INTERVAL_MS,
      userId,
      timeCounter,
      consumedAtMs,
      StorageService.TOTP_REPLAY_MARKER_TTL_MS
    );
    if (result.cleanedUpAt !== null) {
      StorageService.lastTotpReplayCleanupAt = result.cleanedUpAt;
    }
    return result.consumed;
  }

  // --- Revision dates ---

  async getRevisionDate(userId: string): Promise<string> {
    return getStoredRevisionDate(this.db, userId);
  }

  async updateRevisionDate(userId: string): Promise<string> {
    return updateStoredRevisionDate(this.db, userId);
  }

  // --- One-time attachment download tokens ---

  private async ensureUsedAttachmentDownloadTokenTable(): Promise<void> {
    if (StorageService.attachmentTokenTableReady) return;
    await ensureStoredAttachmentTokenTable(this.db);

    StorageService.attachmentTokenTableReady = true;
  }

  // Marks an attachment download token JTI as consumed.
  // Returns true only on first use. Reuse returns false.
  async consumeAttachmentDownloadToken(jti: string, expUnixSeconds: number): Promise<boolean> {
    await this.ensureUsedAttachmentDownloadTokenTable();
    const result = await consumeStoredAttachmentDownloadToken(
      this.db,
      this.shouldRunPeriodicCleanup.bind(this),
      StorageService.lastAttachmentTokenCleanupAt,
      StorageService.ATTACHMENT_TOKEN_CLEANUP_INTERVAL_MS,
      jti,
      expUnixSeconds
    );
    if (result.cleanedUpAt !== null) {
      StorageService.lastAttachmentTokenCleanupAt = result.cleanedUpAt;
    }
    return result.consumed;
  }
}
