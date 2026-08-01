// Environment bindings
export interface Env {
  DB: D1Database;
  NOTIFICATIONS_HUB: DurableObjectNamespace;
  BACKUP_TRANSFER_RUNNER: DurableObjectNamespace;
  ASSETS?: {
    fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
  };
  // Set to "1" to return 404 for the Web Vault while keeping client APIs available.
  HIDE_WEB_VAULT?: string;
  // Prefer R2 when available. Optional to support KV-only deployments.
  ATTACHMENTS?: R2Bucket;
  // Optional fallback for attachment/send file storage (no credit card required).
  ATTACHMENTS_KV?: KVNamespace;
  JWT_SECRET: string;
  WEBAUTHN_RP_ID?: string;
  WEBAUTHN_RP_NAME?: string;
  WEBAUTHN_ALLOWED_ORIGINS?: string;
  YUBICO_VALIDATION_URLS?: string;
  'globalSettings__yubico__validationUrls'?: string;
}

export type UserRole = 'admin' | 'user';
export type UserStatus = 'active' | 'banned';

// Attachment model
export interface Attachment {
  id: string;
  cipherId: string;
  fileName: string;  // encrypted
  size: number;
  sizeName: string;
  key: string | null;  // encrypted attachment key
}

// User model
export interface User {
  id: string;
  email: string;
  name: string | null;
  masterPasswordHint: string | null;
  masterPasswordHash: string;
  key: string;
  privateKey: string | null;
  publicKey: string | null;
  kdfType: number;
  kdfIterations: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  securityStamp: string;
  role: UserRole;
  status: UserStatus;
  verifyDevices?: boolean;
  totpSecret: string | null;
  totpRecoveryCode: string | null;
  yubikeyKey1: string | null;
  yubikeyKey2: string | null;
  yubikeyKey3: string | null;
  yubikeyKey4: string | null;
  yubikeyKey5: string | null;
  yubikeyNfc: boolean;
  apiKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UserDomainSettings {
  userId: string;
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  excludedGlobalEquivalentDomains: number[];
  updatedAt: string | null;
}

export interface CustomEquivalentDomain {
  id: string;
  domains: string[];
  excluded: boolean;
}

export interface GlobalEquivalentDomain {
  type: number;
  domains: string[];
  excluded: boolean;
  [key: string]: unknown;
}

export interface DomainRulesResponse {
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  globalEquivalentDomains: GlobalEquivalentDomain[];
  object: 'domains';
}

export interface Invite {
  code: string;
  createdBy: string;
  usedBy: string | null;
  expiresAt: string;
  status: 'active' | 'used' | 'revoked' | 'expired';
  createdAt: string;
  updatedAt: string;
}

export interface AuditLog {
  id: string;
  actorUserId: string | null;
  actorEmail?: string | null;
  action: string;
  category: 'auth' | 'security' | 'device' | 'data' | 'system';
  level: 'info' | 'warn' | 'error' | 'security';
  targetType: string | null;
  targetId: string | null;
  targetUserEmail?: string | null;
  metadata: string | null;
  createdAt: string;
}

// Cipher types
export enum CipherType {
  Login = 1,
  SecureNote = 2,
  Card = 3,
  Identity = 4,
  SSHKey = 5,
  BankAccount = 6,
  DriversLicense = 7,
  Passport = 8,
}

export interface CipherLoginUri {
  uri: string | null;
  uriChecksum: string | null;
  match: number | null;
}

export interface CipherLogin {
  username: string | null;
  password: string | null;
  uris: CipherLoginUri[] | null;
  totp: string | null;
  autofillOnPageLoad: boolean | null;
  fido2Credentials: any[] | null;
  uri: string | null;
  passwordRevisionDate: string | null;
}

export interface CipherCard {
  cardholderName: string | null;
  brand: string | null;
  number: string | null;
  expMonth: string | null;
  expYear: string | null;
  code: string | null;
}

export interface CipherSshKey {
  publicKey: string;
  privateKey: string;
  keyFingerprint: string;
}

export interface CipherBankAccount {
  bankName: string | null;
  nameOnAccount: string | null;
  accountType: string | null;
  accountNumber: string | null;
  routingNumber: string | null;
  branchNumber: string | null;
  pin: string | null;
  swiftCode: string | null;
  iban: string | null;
  bankContactPhone: string | null;
  [key: string]: any;
}

export interface CipherDriversLicense {
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  dateOfBirth: string | null;
  licenseNumber: string | null;
  issuingCountry: string | null;
  issuingState: string | null;
  issueDate: string | null;
  expirationDate: string | null;
  issuingAuthority: string | null;
  licenseClass: string | null;
  [key: string]: any;
}

export interface CipherPassport {
  surname: string | null;
  givenName: string | null;
  dateOfBirth: string | null;
  sex: string | null;
  birthPlace: string | null;
  nationality: string | null;
  issuingCountry: string | null;
  passportNumber: string | null;
  passportType: string | null;
  nationalIdentificationNumber: string | null;
  issuingAuthority: string | null;
  issueDate: string | null;
  expirationDate: string | null;
  [key: string]: any;
}

export interface CipherIdentity {
  title: string | null;
  firstName: string | null;
  middleName: string | null;
  lastName: string | null;
  address1: string | null;
  address2: string | null;
  address3: string | null;
  city: string | null;
  state: string | null;
  postalCode: string | null;
  country: string | null;
  company: string | null;
  email: string | null;
  phone: string | null;
  ssn: string | null;
  username: string | null;
  passportNumber: string | null;
  licenseNumber: string | null;
}

export interface CipherSecureNote {
  type: number;
}

export interface CipherField {
  name: string | null;
  value: string | null;
  type: number;
  linkedId: number | null;
}

export interface PasswordHistory {
  password: string;
  lastUsedDate: string;
}

export interface Cipher {
  id: string;
  userId: string;
  type: CipherType;
  folderId: string | null;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  bankAccount?: CipherBankAccount | null;
  driversLicense?: CipherDriversLicense | null;
  passport?: CipherPassport | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  key: string | null;
  createdAt: string;
  updatedAt: string;
  archivedAt: string | null;
  deletedAt: string | null;
  /** Allow unknown fields from Bitwarden clients to be stored and passed through transparently. */
  [key: string]: any;
}

// Folder model
export interface Folder {
  id: string;
  userId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface Device {
  userId: string;
  deviceIdentifier: string;
  name: string;
  deviceNote: string | null;
  type: number;
  sessionStamp: string;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
  pushUuid: string | null;
  pushToken: string | null;
  devicePendingAuthRequest?: DevicePendingAuthRequest | null;
  lastSeenAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type AccountPasskeyPrfStatus = 0 | 1 | 2;

export interface AccountPasskeyCredential {
  id: string;
  userId: string;
  purpose: 'login' | 'twoFactor';
  name: string;
  publicKey: string;
  credentialId: string;
  counter: number;
  type: string | null;
  aaGuid: string | null;
  transports: string[] | null;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
  supportsPrf: boolean;
  createdAt: string;
  updatedAt: string;
}

export type AccountPasskeyChallengeScope =
  | 'Authentication'
  | 'CreateCredential'
  | 'UpdateKeySet'
  | 'TwoFactorAuthentication'
  | 'TwoFactorCreate';

export interface AccountPasskeyChallenge {
  challengeHash: string;
  scope: AccountPasskeyChallengeScope;
  userId: string | null;
  expiresAt: number;
  usedAt: number | null;
  createdAt: number;
}

export interface DevicePendingAuthRequest {
  id: string;
  creationDate: string;
}

export type AuthRequestType = 0 | 1 | 2;

export interface AuthRequestRecord {
  id: string;
  userId: string;
  organizationId: string | null;
  type: AuthRequestType;
  requestDeviceIdentifier: string;
  requestDeviceType: number;
  requestIpAddress: string | null;
  requestCountryName: string | null;
  responseDeviceIdentifier: string | null;
  accessCode: string;
  publicKey: string;
  key: string | null;
  masterPasswordHash: string | null;
  approved: boolean | null;
  creationDate: string;
  responseDate: string | null;
  authenticationDate: string | null;
}

export interface DeviceResponse {
  id: string;
  userId?: string | null;
  name: string;
  systemName?: string | null;
  deviceNote?: string | null;
  identifier: string;
  type: number;
  creationDate: string;
  revisionDate: string;
  lastActivityDate?: string | null;
  lastSeenAt?: string | null;
  hasStoredDevice?: boolean;
  isTrusted: boolean;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  devicePendingAuthRequest: DevicePendingAuthRequest | null;
  object: string;
  [key: string]: any;
}

export interface ProtectedDeviceResponse {
  id: string;
  name: string;
  identifier: string;
  type: number;
  creationDate: string;
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  object: string;
  [key: string]: any;
}

export interface RefreshTokenRecord {
  userId: string;
  expiresAt: number;
  deviceIdentifier: string | null;
  deviceSessionStamp: string | null;
  securityStamp: string | null;
  createdAt: number | null;
  lastUsedAt: number | null;
  absoluteExpiresAt: number | null;
  clientType: string | null;
}

export interface TrustedDeviceTokenSummary {
  deviceIdentifier: string;
  expiresAt: number;
  tokenCount: number;
}

export enum SendType {
  Text = 0,
  File = 1,
}

export enum SendAuthType {
  Email = 0,
  Password = 1,
  None = 2,
}

export interface Send {
  id: string;
  userId: string;
  type: SendType;
  name: string;
  notes: string | null;
  data: string;
  key: string;
  passwordHash: string | null;
  passwordSalt: string | null;
  passwordIterations: number | null;
  authType: SendAuthType;
  emails: string | null;
  maxAccessCount: number | null;
  accessCount: number;
  disabled: boolean;
  hideEmail: boolean | null;
  createdAt: string;
  updatedAt: string;
  expirationDate: string | null;
  deletionDate: string;
}

export interface SendResponse {
  id: string;
  accessId: string;
  type: number;
  name: string;
  notes: string | null;
  text: any | null;
  file: any | null;
  key: string;
  maxAccessCount: number | null;
  accessCount: number;
  password: string | null;
  emails: string | null;
  authType: SendAuthType;
  disabled: boolean;
  hideEmail: boolean | null;
  revisionDate: string;
  expirationDate: string | null;
  deletionDate: string;
  object: string;
}

// JWT Payload
export interface JWTPayload {
  sub: string;      // user id
  email: string;
  name: string | null;
  email_verified: boolean; // required by mobile client
  amr: string[];    // authentication methods reference - required by mobile client
  sstamp: string;   // security stamp - invalidates token when user changes password
  did?: string;     // device identifier - invalidates per-device sessions
  dstamp?: string;  // device session stamp
  iat: number;
  exp: number;
  iss: string;
  premium: boolean;
}

// UserDecryptionOptions types for mobile client compatibility
export interface MasterPasswordUnlockKdf {
  KdfType: number;
  Iterations: number;
  Memory: number | null;
  Parallelism: number | null;
}

export interface MasterPasswordUnlock {
  Kdf: MasterPasswordUnlockKdf;
  MasterKeyEncryptedUserKey: string;
  MasterKeyWrappedUserKey: string;
  Salt: string;
  Object: string;
}

export interface WebAuthnPrfDecryptionOption {
  EncryptedPrivateKey: string;
  EncryptedUserKey: string;
  CredentialId: string;
  Transports: string[];
  Object?: string;
}

export interface UserDecryptionOptions {
  HasMasterPassword: boolean;
  Object: string;
  // Bitwarden Android 2026.1.x expects this to exist; missing it breaks unlock when the vault is empty.
  MasterPasswordUnlock: MasterPasswordUnlock;
  TrustedDeviceOption: null;
  KeyConnectorOption: null;
  WebAuthnPrfOption?: WebAuthnPrfDecryptionOption | null;
}

// API Response types
export interface TokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
  refresh_token?: string;
  web_session?: boolean;
  TwoFactorToken?: string;
  Key: string;
  PrivateKey: string | null;
  Kdf: number;
  KdfIterations: number;
  KdfMemory?: number;
  KdfParallelism?: number;
  ForcePasswordReset: boolean;
  ResetMasterPassword: boolean;
  scope: string;
  unofficialServer: boolean;
  UserVerificationToken?: string;
  userVerificationToken?: string;
  MasterPasswordPolicy?: {
    minComplexity: number;
    minLength: number;
    requireUpper: boolean;
    requireLower: boolean;
    requireNumbers: boolean;
    requireSpecial: boolean;
    enforceOnLogin: boolean;
    Object: string;
    object?: string;
  } | null;
  ApiUseKeyConnector?: boolean;
  AccountKeys?: any | null;
  accountKeys?: any | null;
  UserDecryptionOptions: UserDecryptionOptions;
  userDecryptionOptions?: UserDecryptionOptions;
  VaultKeys?: {
    symEncKey: string;
    symMacKey: string;
  };
}

export interface ProfileResponse {
  id: string;
  name: string | null;
  email: string;
  emailVerified: boolean;
  premium: boolean;
  premiumFromOrganization: boolean;
  usesKeyConnector: boolean;
  masterPasswordHint: string | null;
  culture: string;
  twoFactorEnabled: boolean;
  yubikeyEnabled?: boolean;
  key: string;
  privateKey: string | null;
  accountKeys: any | null;
  securityStamp: string;
  organizations: any[];
  organizationsNew?: any[];
  providers: any[];
  providerOrganizations: any[];
  forcePasswordReset: boolean;
  avatarColor: string | null;
  creationDate: string;
  verifyDevices: boolean;
  role?: UserRole;
  status?: UserStatus;
  object: string;
}

export interface CipherResponse {
  id: string;
  organizationId: string | null;
  folderId: string | null;
  type: number;
  name: string | null;
  notes: string | null;
  favorite: boolean;
  login: CipherLogin | null;
  card: CipherCard | null;
  identity: CipherIdentity | null;
  secureNote: CipherSecureNote | null;
  sshKey: CipherSshKey | null;
  bankAccount: CipherBankAccount | null;
  driversLicense: CipherDriversLicense | null;
  passport: CipherPassport | null;
  fields: CipherField[] | null;
  passwordHistory: PasswordHistory[] | null;
  reprompt: number;
  organizationUseTotp: boolean;
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
  edit: boolean;
  viewPassword: boolean;
  permissions: CipherPermissions | null;
  object: string;
  collectionIds: string[];
  attachments: any[] | null;
  key: string | null;
  encryptedFor: string | null;
  /** Allow unknown fields to pass through to clients transparently. */
  [key: string]: any;
}

export interface CipherPermissions {
  delete: boolean;
  restore: boolean;
}

export interface FolderResponse {
  id: string;
  name: string;
  revisionDate: string;
  creationDate: string;
  object: string;
}

export interface SyncResponse {
  profile: ProfileResponse;
  folders: FolderResponse[];
  collections: any[];
  ciphers: CipherResponse[];
  domains: any;
  policies: any[];
  policiesNew?: any[];
  sends: SendResponse[];
  UserDecryption?: {
    MasterPasswordUnlock: MasterPasswordUnlock | null;
    TrustedDeviceOption?: null;
    KeyConnectorOption?: null;
    WebAuthnPrfOption?: WebAuthnPrfDecryptionOption | null;
    WebAuthnPrfOptions?: WebAuthnPrfDecryptionOption[];
    V2UpgradeToken?: {
      WrappedUserKey1: string;
      WrappedUserKey2: string;
    } | null;
    Object?: string;
  } | null;
  // PascalCase for desktop/browser clients
  UserDecryptionOptions: UserDecryptionOptions | null;
  // camelCase for Android client (SyncResponseJson uses @SerialName("userDecryption"))
  userDecryption: {
    masterPasswordUnlock: {
      kdf: {
        kdfType: number;
        iterations: number;
        memory: number | null;
        parallelism: number | null;
      };
      masterKeyWrappedUserKey: string;
      masterKeyEncryptedUserKey: string;
      salt: string;
    } | null;
  } | null;
  object: string;
}
