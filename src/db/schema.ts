// Drizzle v1 schema for the NodeWarden D1 database.
//
// Table and column names are the historical snake_case names from the
// pre-Drizzle D1 schema, so every column passes its DB name explicitly rather
// than relying on a casing helper. Renaming any of them is a breaking data
// migration.
import { sql } from 'drizzle-orm';
import {
  foreignKey,
  index,
  integer,
  primaryKey,
  sqliteTable,
  text,
  unique,
  uniqueIndex,
} from 'drizzle-orm/sqlite-core';

export const config = sqliteTable('config', {
  key: text('key').primaryKey(),
  value: text('value').notNull(),
});

export const users = sqliteTable('users', {
  id: text('id').primaryKey(),
  email: text('email').notNull().unique(),
  name: text('name'),
  masterPasswordHint: text('master_password_hint'),
  masterPasswordHash: text('master_password_hash').notNull(),
  key: text('key').notNull(),
  privateKey: text('private_key'),
  publicKey: text('public_key'),
  kdfType: integer('kdf_type').notNull(),
  kdfIterations: integer('kdf_iterations').notNull(),
  kdfMemory: integer('kdf_memory'),
  kdfParallelism: integer('kdf_parallelism'),
  securityStamp: text('security_stamp').notNull(),
  role: text('role').notNull().default('user'),
  status: text('status').notNull().default('active'),
  verifyDevices: integer('verify_devices').notNull().default(0),
  totpSecret: text('totp_secret'),
  totpRecoveryCode: text('totp_recovery_code'),
  yubikeyKey1: text('yubikey_key1'),
  yubikeyKey2: text('yubikey_key2'),
  yubikeyKey3: text('yubikey_key3'),
  yubikeyKey4: text('yubikey_key4'),
  yubikeyKey5: text('yubikey_key5'),
  yubikeyNfc: integer('yubikey_nfc').notNull().default(0),
  apiKey: text('api_key'),
  emailVerified: integer('email_verified').notNull().default(1),
  image: text('image'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
});

export const session = sqliteTable('session', {
  id: text('id').primaryKey(),
  expiresAt: integer('expires_at').notNull(),
  token: text('token').notNull().unique(),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  userId: text('user_id').notNull(),
  deviceIdentifier: text('device_identifier'),
  deviceSessionStamp: text('device_session_stamp'),
  securityStamp: text('security_stamp'),
  clientType: text('client_type'),
  absoluteExpiresAt: integer('absolute_expires_at'),
  lastUsedAt: integer('last_used_at'),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_session_user').on(table.userId),
  index('idx_session_expires').on(table.expiresAt),
]);

export const account = sqliteTable('account', {
  id: text('id').primaryKey(),
  accountId: text('account_id').notNull(),
  providerId: text('provider_id').notNull(),
  userId: text('user_id').notNull(),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  idToken: text('id_token'),
  accessTokenExpiresAt: integer('access_token_expires_at'),
  refreshTokenExpiresAt: integer('refresh_token_expires_at'),
  scope: text('scope'),
  password: text('password'),
  createdAt: integer('created_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  uniqueIndex('idx_account_provider_account').on(table.providerId, table.accountId),
  index('idx_account_user').on(table.userId),
]);

export const verification = sqliteTable('verification', {
  id: text('id').primaryKey(),
  identifier: text('identifier').notNull(),
  value: text('value').notNull(),
  expiresAt: integer('expires_at').notNull(),
  createdAt: integer('created_at'),
  updatedAt: integer('updated_at'),
}, (table) => [
  index('idx_verification_identifier').on(table.identifier),
]);

export const twoFactor = sqliteTable('two_factor', {
  id: text('id').primaryKey(),
  secret: text('secret').notNull(),
  backupCodes: text('backup_codes').notNull(),
  userId: text('user_id').notNull().unique(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
]);

export const domainSettings = sqliteTable('domain_settings', {
  userId: text('user_id').primaryKey(),
  equivalentDomains: text('equivalent_domains').notNull().default('[]'),
  customEquivalentDomains: text('custom_equivalent_domains').notNull().default('[]'),
  excludedGlobalEquivalentDomains: text('excluded_global_equivalent_domains').notNull().default('[]'),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
]);

export const userRevisions = sqliteTable('user_revisions', {
  userId: text('user_id').primaryKey(),
  revisionDate: text('revision_date').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
]);

export const ciphers = sqliteTable('ciphers', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  type: integer('type').notNull(),
  folderId: text('folder_id'),
  name: text('name'),
  notes: text('notes'),
  favorite: integer('favorite').notNull().default(0),
  data: text('data').notNull(),
  reprompt: integer('reprompt'),
  key: text('key'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  archivedAt: text('archived_at'),
  deletedAt: text('deleted_at'),
  // Personal-vault rows keep this NULL; org-owned rows carry the owning org id.
  // Deliberately not a foreign key: the column was added by ALTER TABLE and
  // organization deletion is handled in application code.
  organizationId: text('organization_id'),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_ciphers_user_updated').on(table.userId, table.updatedAt),
  index('idx_ciphers_user_archived').on(table.userId, table.archivedAt),
  index('idx_ciphers_user_deleted').on(table.userId, table.deletedAt),
  index('idx_ciphers_user_deleted_updated').on(table.userId, table.deletedAt, table.updatedAt),
  index('idx_ciphers_user_folder').on(table.userId, table.folderId),
  index('idx_ciphers_organization').on(table.organizationId),
  index('idx_ciphers_user_personal').on(table.userId, table.organizationId, table.updatedAt),
]);

export const folders = sqliteTable('folders', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_folders_user_updated').on(table.userId, table.updatedAt),
]);

export const attachments = sqliteTable('attachments', {
  id: text('id').primaryKey(),
  cipherId: text('cipher_id').notNull(),
  fileName: text('file_name').notNull(),
  size: integer('size').notNull(),
  sizeName: text('size_name').notNull(),
  key: text('key'),
}, (table) => [
  foreignKey({ columns: [table.cipherId], foreignColumns: [ciphers.id] }).onDelete('cascade'),
  index('idx_attachments_cipher').on(table.cipherId),
]);

export const sends = sqliteTable('sends', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  type: integer('type').notNull(),
  name: text('name').notNull(),
  notes: text('notes'),
  data: text('data').notNull(),
  key: text('key').notNull(),
  passwordHash: text('password_hash'),
  passwordSalt: text('password_salt'),
  passwordIterations: integer('password_iterations'),
  authType: integer('auth_type').notNull().default(2),
  emails: text('emails'),
  maxAccessCount: integer('max_access_count'),
  accessCount: integer('access_count').notNull().default(0),
  disabled: integer('disabled').notNull().default(0),
  hideEmail: integer('hide_email'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  expirationDate: text('expiration_date'),
  deletionDate: text('deletion_date').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_sends_user_updated').on(table.userId, table.updatedAt),
  index('idx_sends_user_deletion').on(table.userId, table.deletionDate),
  index('idx_sends_user_updated_id').on(table.userId, table.updatedAt, table.id),
]);

export const refreshTokens = sqliteTable('refresh_tokens', {
  token: text('token').primaryKey(),
  userId: text('user_id').notNull(),
  expiresAt: integer('expires_at').notNull(),
  deviceIdentifier: text('device_identifier'),
  deviceSessionStamp: text('device_session_stamp'),
  securityStamp: text('security_stamp'),
  createdAt: integer('created_at'),
  lastUsedAt: integer('last_used_at'),
  absoluteExpiresAt: integer('absolute_expires_at'),
  clientType: text('client_type'),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_refresh_tokens_user').on(table.userId),
]);

export const invites = sqliteTable('invites', {
  code: text('code').primaryKey(),
  createdBy: text('created_by').notNull(),
  usedBy: text('used_by'),
  expiresAt: text('expires_at').notNull(),
  status: text('status').notNull(),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.createdBy], foreignColumns: [users.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.usedBy], foreignColumns: [users.id] }).onDelete('set null'),
  index('idx_invites_status_expires').on(table.status, table.expiresAt),
  index('idx_invites_created_by').on(table.createdBy, table.createdAt),
]);

export const auditLogs = sqliteTable('audit_logs', {
  id: text('id').primaryKey(),
  actorUserId: text('actor_user_id'),
  action: text('action').notNull(),
  category: text('category').notNull().default('system'),
  level: text('level').notNull().default('info'),
  targetType: text('target_type'),
  targetId: text('target_id'),
  metadata: text('metadata'),
  createdAt: text('created_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.actorUserId], foreignColumns: [users.id] }).onDelete('set null'),
  index('idx_audit_logs_created_at').on(table.createdAt),
  index('idx_audit_logs_actor_created').on(table.actorUserId, table.createdAt),
  index('idx_audit_logs_category_created').on(table.category, table.createdAt),
  index('idx_audit_logs_level_created').on(table.level, table.createdAt),
]);

export const devices = sqliteTable('devices', {
  userId: text('user_id').notNull(),
  deviceIdentifier: text('device_identifier').notNull(),
  name: text('name').notNull(),
  type: integer('type').notNull(),
  sessionStamp: text('session_stamp'),
  encryptedUserKey: text('encrypted_user_key'),
  encryptedPublicKey: text('encrypted_public_key'),
  encryptedPrivateKey: text('encrypted_private_key'),
  pushUuid: text('push_uuid'),
  pushToken: text('push_token'),
  banned: integer('banned').notNull().default(0),
  bannedAt: text('banned_at'),
  deviceNote: text('device_note'),
  lastSeenAt: text('last_seen_at'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  primaryKey({ columns: [table.userId, table.deviceIdentifier] }),
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_devices_user_updated').on(table.userId, table.updatedAt),
  index('idx_devices_user_last_seen').on(table.userId, table.lastSeenAt),
  index('idx_devices_user_push').on(table.userId, table.pushToken),
]);

export const authRequests = sqliteTable('auth_requests', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  organizationId: text('organization_id'),
  type: integer('type').notNull(),
  requestDeviceIdentifier: text('request_device_identifier').notNull(),
  requestDeviceType: integer('request_device_type').notNull(),
  requestIpAddress: text('request_ip_address'),
  requestCountryName: text('request_country_name'),
  responseDeviceIdentifier: text('response_device_identifier'),
  accessCode: text('access_code').notNull(),
  publicKey: text('public_key').notNull(),
  key: text('key'),
  masterPasswordHash: text('master_password_hash'),
  approved: integer('approved'),
  creationDate: text('creation_date').notNull(),
  responseDate: text('response_date'),
  authenticationDate: text('authentication_date'),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_auth_requests_user_created').on(table.userId, table.creationDate),
  index('idx_auth_requests_user_pending')
    .on(table.userId, table.approved, table.responseDate, table.authenticationDate, table.creationDate),
  index('idx_auth_requests_device_pending').on(table.userId, table.requestDeviceIdentifier, table.creationDate),
]);

export const trustedTwoFactorDeviceTokens = sqliteTable('trusted_two_factor_device_tokens', {
  token: text('token').primaryKey(),
  userId: text('user_id').notNull(),
  deviceIdentifier: text('device_identifier').notNull(),
  expiresAt: integer('expires_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_trusted_two_factor_device_tokens_user_device').on(table.userId, table.deviceIdentifier),
]);

export const totpLoginReplays = sqliteTable('totp_login_replays', {
  userId: text('user_id').notNull(),
  timeCounter: integer('time_counter').notNull(),
  consumedAt: integer('consumed_at').notNull(),
}, (table) => [
  primaryKey({ columns: [table.userId, table.timeCounter] }),
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  index('idx_totp_login_replays_consumed_at').on(table.consumedAt),
]);

export const webauthnCredentials = sqliteTable('webauthn_credentials', {
  id: text('id').primaryKey(),
  userId: text('user_id').notNull(),
  purpose: text('purpose').notNull().default('login'),
  name: text('name').notNull(),
  publicKey: text('public_key').notNull(),
  credentialId: text('credential_id').notNull(),
  counter: integer('counter').notNull().default(0),
  type: text('type'),
  aaGuid: text('aa_guid'),
  transports: text('transports'),
  encryptedUserKey: text('encrypted_user_key'),
  encryptedPublicKey: text('encrypted_public_key'),
  encryptedPrivateKey: text('encrypted_private_key'),
  supportsPrf: integer('supports_prf').notNull().default(0),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  // Redundant with the primary key, but present in every deployed database
  // because src/services/storage-account-passkey-repo.ts creates it.
  uniqueIndex('idx_webauthn_credentials_id').on(table.id),
  uniqueIndex('idx_webauthn_credentials_credential_id').on(table.credentialId),
  index('idx_webauthn_credentials_user').on(table.userId),
  index('idx_webauthn_credentials_user_updated').on(table.userId, table.updatedAt),
]);

export const webauthnChallenges = sqliteTable('webauthn_challenges', {
  challengeHash: text('challenge_hash').primaryKey(),
  scope: text('scope').notNull(),
  userId: text('user_id'),
  expiresAt: integer('expires_at').notNull(),
  usedAt: integer('used_at'),
  createdAt: integer('created_at').notNull(),
}, (table) => [
  index('idx_webauthn_challenges_expires').on(table.expiresAt),
  index('idx_webauthn_challenges_user_scope').on(table.userId, table.scope),
]);

export const loginAttemptsIp = sqliteTable('login_attempts_ip', {
  ip: text('ip').primaryKey(),
  attempts: integer('attempts').notNull(),
  lockedUntil: integer('locked_until'),
  updatedAt: integer('updated_at').notNull(),
});

export const rateLimitBuckets = sqliteTable('rate_limit_buckets', {
  bucketKey: text('bucket_key').primaryKey(),
  count: integer('count').notNull(),
  expiresAt: integer('expires_at').notNull(),
  updatedAt: integer('updated_at').notNull(),
}, (table) => [
  index('idx_rate_limit_buckets_expires').on(table.expiresAt),
]);

export const usedAttachmentDownloadTokens = sqliteTable('used_attachment_download_tokens', {
  jti: text('jti').primaryKey(),
  expiresAt: integer('expires_at').notNull(),
});

export const organizations = sqliteTable('organizations', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  billingEmail: text('billing_email').notNull(),
  identifier: text('identifier'),
  privateKey: text('private_key'),
  publicKey: text('public_key'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  // Partial: many organizations may leave the SSO identifier unset.
  uniqueIndex('idx_organizations_identifier')
    .on(table.identifier)
    .where(sql`${table.identifier} is not null`),
]);

export const organizationMemberships = sqliteTable('organization_memberships', {
  id: text('id').primaryKey(),
  userId: text('user_id'),
  orgId: text('org_id').notNull(),
  email: text('email'),
  invitedByEmail: text('invited_by_email'),
  accessAll: integer('access_all').notNull().default(0),
  key: text('key').notNull().default(''),
  status: integer('status').notNull(),
  type: integer('type').notNull(),
  permissions: text('permissions'),
  resetPasswordKey: text('reset_password_key'),
  externalId: text('external_id'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  // Partial: invited-but-unaccepted rows have no user_id yet and must not collide.
  uniqueIndex('idx_org_memberships_user_org')
    .on(table.userId, table.orgId)
    .where(sql`${table.userId} is not null`),
  index('idx_org_memberships_org_status').on(table.orgId, table.status),
  index('idx_org_memberships_external').on(table.orgId, table.externalId),
]);

export const collections = sqliteTable('collections', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  name: text('name').notNull(),
  externalId: text('external_id'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
  index('idx_collections_org').on(table.orgId),
]);

export const collectionUsers = sqliteTable('collection_users', {
  userId: text('user_id').notNull(),
  collectionId: text('collection_id').notNull(),
  readOnly: integer('read_only').notNull().default(0),
  hidePasswords: integer('hide_passwords').notNull().default(0),
  manage: integer('manage').notNull().default(0),
}, (table) => [
  primaryKey({ columns: [table.userId, table.collectionId] }),
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.collectionId], foreignColumns: [collections.id] }).onDelete('cascade'),
]);

export const cipherCollections = sqliteTable('cipher_collections', {
  cipherId: text('cipher_id').notNull(),
  collectionId: text('collection_id').notNull(),
}, (table) => [
  primaryKey({ columns: [table.cipherId, table.collectionId] }),
  foreignKey({ columns: [table.cipherId], foreignColumns: [ciphers.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.collectionId], foreignColumns: [collections.id] }).onDelete('cascade'),
  index('idx_cipher_collections_collection').on(table.collectionId),
]);

export const orgGroups = sqliteTable('org_groups', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  name: text('name').notNull(),
  accessAll: integer('access_all').notNull().default(0),
  externalId: text('external_id'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
  index('idx_org_groups_org').on(table.orgId),
]);

export const orgGroupMembers = sqliteTable('org_group_members', {
  groupId: text('group_id').notNull(),
  membershipId: text('membership_id').notNull(),
}, (table) => [
  primaryKey({ columns: [table.groupId, table.membershipId] }),
  foreignKey({ columns: [table.groupId], foreignColumns: [orgGroups.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.membershipId], foreignColumns: [organizationMemberships.id] }).onDelete('cascade'),
]);

export const collectionGroups = sqliteTable('collection_groups', {
  collectionId: text('collection_id').notNull(),
  groupId: text('group_id').notNull(),
  readOnly: integer('read_only').notNull().default(0),
  hidePasswords: integer('hide_passwords').notNull().default(0),
  manage: integer('manage').notNull().default(0),
}, (table) => [
  primaryKey({ columns: [table.collectionId, table.groupId] }),
  foreignKey({ columns: [table.collectionId], foreignColumns: [collections.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.groupId], foreignColumns: [orgGroups.id] }).onDelete('cascade'),
]);

export const orgPolicies = sqliteTable('org_policies', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  type: integer('type').notNull(),
  enabled: integer('enabled').notNull().default(0),
  data: text('data').notNull().default('{}'),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  unique().on(table.orgId, table.type),
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
]);

export const organizationApiKeys = sqliteTable('organization_api_keys', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  type: integer('type').notNull().default(0),
  apiKey: text('api_key').notNull(),
  revisionDate: text('revision_date').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
]);

export const organizationScimTokens = sqliteTable('organization_scim_tokens', {
  orgId: text('org_id').primaryKey(),
  tokenHash: text('token_hash').notNull(),
  createdAt: text('created_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
]);

export const ssoAuth = sqliteTable('sso_auth', {
  state: text('state').primaryKey(),
  codeChallenge: text('code_challenge'),
  redirectUri: text('redirect_uri').notNull(),
  clientId: text('client_id').notNull(),
  bindingHash: text('binding_hash'),
  identifier: text('identifier'),
  codeResponse: text('code_response'),
  codeResponseError: text('code_response_error'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
});

export const ssoUsers = sqliteTable('sso_users', {
  userId: text('user_id').primaryKey(),
  identifier: text('identifier').notNull().unique(),
  createdAt: text('created_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.userId], foreignColumns: [users.id] }).onDelete('cascade'),
]);

export const smProjects = sqliteTable('sm_projects', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
  index('idx_sm_projects_org').on(table.orgId),
]);

export const smSecrets = sqliteTable('sm_secrets', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  key: text('key').notNull(),
  value: text('value').notNull(),
  note: text('note'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
  deletedAt: text('deleted_at'),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
  index('idx_sm_secrets_org_updated').on(table.orgId, table.updatedAt),
]);

export const smSecretProjects = sqliteTable('sm_secret_projects', {
  secretId: text('secret_id').notNull(),
  projectId: text('project_id').notNull(),
}, (table) => [
  primaryKey({ columns: [table.secretId, table.projectId] }),
  foreignKey({ columns: [table.secretId], foreignColumns: [smSecrets.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.projectId], foreignColumns: [smProjects.id] }).onDelete('cascade'),
]);

export const smServiceAccounts = sqliteTable('sm_service_accounts', {
  id: text('id').primaryKey(),
  orgId: text('org_id').notNull(),
  name: text('name').notNull(),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.orgId], foreignColumns: [organizations.id] }).onDelete('cascade'),
]);

export const smServiceAccountProjects = sqliteTable('sm_service_account_projects', {
  serviceAccountId: text('service_account_id').notNull(),
  projectId: text('project_id').notNull(),
  readAccess: integer('read_access').notNull().default(1),
  writeAccess: integer('write_access').notNull().default(0),
}, (table) => [
  primaryKey({ columns: [table.serviceAccountId, table.projectId] }),
  foreignKey({ columns: [table.serviceAccountId], foreignColumns: [smServiceAccounts.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.projectId], foreignColumns: [smProjects.id] }).onDelete('cascade'),
]);

export const smAccessTokens = sqliteTable('sm_access_tokens', {
  id: text('id').primaryKey(),
  serviceAccountId: text('service_account_id').notNull(),
  name: text('name').notNull(),
  clientSecretHash: text('client_secret_hash').notNull(),
  wrappedOrgKey: text('wrapped_org_key'),
  expireAt: text('expire_at'),
  revokedAt: text('revoked_at'),
  createdAt: text('created_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.serviceAccountId], foreignColumns: [smServiceAccounts.id] }).onDelete('cascade'),
]);

export const emergencyAccess = sqliteTable('emergency_access', {
  id: text('id').primaryKey(),
  grantorId: text('grantor_id').notNull(),
  granteeId: text('grantee_id'),
  email: text('email'),
  keyEncrypted: text('key_encrypted'),
  type: integer('type').notNull(),
  status: integer('status').notNull(),
  waitTimeDays: integer('wait_time_days').notNull(),
  recoveryInitiatedAt: text('recovery_initiated_at'),
  lastNotificationAt: text('last_notification_at'),
  createdAt: text('created_at').notNull(),
  updatedAt: text('updated_at').notNull(),
}, (table) => [
  foreignKey({ columns: [table.grantorId], foreignColumns: [users.id] }).onDelete('cascade'),
  foreignKey({ columns: [table.granteeId], foreignColumns: [users.id] }).onDelete('set null'),
  index('idx_emergency_access_grantor').on(table.grantorId, table.status),
  index('idx_emergency_access_grantee').on(table.granteeId, table.status),
  index('idx_emergency_access_email').on(table.email),
]);
