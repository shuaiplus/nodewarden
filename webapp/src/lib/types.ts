export type AppPhase = 'register' | 'login' | 'locked' | 'app';

export interface SessionState {
  accessToken?: string;
  refreshToken?: string;
  email: string;
  authMode?: 'token' | 'web-cookie';
  symEncKey?: string;
  symMacKey?: string;
}

export interface Profile {
  id: string;
  email: string;
  name: string;
  key: string;
  masterPasswordHint?: string | null;
  yubikeyEnabled?: boolean;
  privateKey?: string | null;
  publicKey?: string | null;
  role: 'admin' | 'user';
  [k: string]: unknown;
}

export interface Folder {
  id: string;
  name: string;
  decName?: string;
  revisionDate?: string;
  creationDate?: string;
}

export interface CipherLoginUri {
  uri?: string | null;
  uriChecksum?: string | null;
  match?: number | null;
  response?: unknown | null;
  decUri?: string;
  [key: string]: unknown;
}

export interface VaultDraftLoginUri {
  uri: string;
  match: number | null;
  originalUri?: string;
  extra?: Record<string, unknown>;
}

export interface CipherAttachment {
  id?: string;
  url?: string | null;
  fileName?: string | null;
  decFileName?: string;
  key?: string | null;
  size?: string | number | null;
  sizeName?: string | null;
  object?: string;
}

export interface CipherLoginPasskey {
  creationDate?: string | null;
  [key: string]: unknown;
}

export interface CipherLogin {
  username?: string | null;
  password?: string | null;
  totp?: string | null;
  uris?: CipherLoginUri[] | null;
  fido2Credentials?: CipherLoginPasskey[] | null;
  autofillOnPageLoad?: boolean | null;
  uri?: string | null;
  passwordRevisionDate?: string | null;
  response?: unknown | null;
  decUsername?: string;
  decPassword?: string;
  decTotp?: string;
  [key: string]: unknown;
}

export interface CipherCard {
  cardholderName?: string | null;
  number?: string | null;
  brand?: string | null;
  expMonth?: string | null;
  expYear?: string | null;
  code?: string | null;
  decCardholderName?: string;
  decNumber?: string;
  decBrand?: string;
  decExpMonth?: string;
  decExpYear?: string;
  decCode?: string;
}

export interface CipherIdentity {
  title?: string | null;
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  username?: string | null;
  company?: string | null;
  ssn?: string | null;
  passportNumber?: string | null;
  licenseNumber?: string | null;
  email?: string | null;
  phone?: string | null;
  address1?: string | null;
  address2?: string | null;
  address3?: string | null;
  city?: string | null;
  state?: string | null;
  postalCode?: string | null;
  country?: string | null;
  decTitle?: string;
  decFirstName?: string;
  decMiddleName?: string;
  decLastName?: string;
  decUsername?: string;
  decCompany?: string;
  decSsn?: string;
  decPassportNumber?: string;
  decLicenseNumber?: string;
  decEmail?: string;
  decPhone?: string;
  decAddress1?: string;
  decAddress2?: string;
  decAddress3?: string;
  decCity?: string;
  decState?: string;
  decPostalCode?: string;
  decCountry?: string;
}

export interface CipherSshKey {
  privateKey?: string | null;
  publicKey?: string | null;
  keyFingerprint?: string | null;
  fingerprint?: string | null;
  decPrivateKey?: string;
  decPublicKey?: string;
  decFingerprint?: string;
}

export interface CipherBankAccount {
  bankName?: string | null;
  nameOnAccount?: string | null;
  accountType?: string | null;
  accountNumber?: string | null;
  routingNumber?: string | null;
  branchNumber?: string | null;
  pin?: string | null;
  swiftCode?: string | null;
  iban?: string | null;
  bankContactPhone?: string | null;
  decBankName?: string;
  decNameOnAccount?: string;
  decAccountType?: string;
  decAccountNumber?: string;
  decRoutingNumber?: string;
  decBranchNumber?: string;
  decPin?: string;
  decSwiftCode?: string;
  decIban?: string;
  decBankContactPhone?: string;
  [key: string]: unknown;
}

export interface CipherDriversLicense {
  firstName?: string | null;
  middleName?: string | null;
  lastName?: string | null;
  dateOfBirth?: string | null;
  licenseNumber?: string | null;
  issuingCountry?: string | null;
  issuingState?: string | null;
  issueDate?: string | null;
  expirationDate?: string | null;
  issuingAuthority?: string | null;
  licenseClass?: string | null;
  decFirstName?: string;
  decMiddleName?: string;
  decLastName?: string;
  decDateOfBirth?: string;
  decLicenseNumber?: string;
  decIssuingCountry?: string;
  decIssuingState?: string;
  decIssueDate?: string;
  decExpirationDate?: string;
  decIssuingAuthority?: string;
  decLicenseClass?: string;
  [key: string]: unknown;
}

export interface CipherPassport {
  surname?: string | null;
  givenName?: string | null;
  dateOfBirth?: string | null;
  sex?: string | null;
  birthPlace?: string | null;
  nationality?: string | null;
  issuingCountry?: string | null;
  passportNumber?: string | null;
  passportType?: string | null;
  nationalIdentificationNumber?: string | null;
  issuingAuthority?: string | null;
  issueDate?: string | null;
  expirationDate?: string | null;
  decSurname?: string;
  decGivenName?: string;
  decDateOfBirth?: string;
  decSex?: string;
  decBirthPlace?: string;
  decNationality?: string;
  decIssuingCountry?: string;
  decPassportNumber?: string;
  decPassportType?: string;
  decNationalIdentificationNumber?: string;
  decIssuingAuthority?: string;
  decIssueDate?: string;
  decExpirationDate?: string;
  [key: string]: unknown;
}

export interface CipherField {
  type?: number | string | null;
  name?: string | null;
  value?: string | null;
  linkedId?: number | null;
  decName?: string;
  decValue?: string;
}

export interface CipherPasswordHistoryEntry {
  password?: string | null;
  lastUsedDate?: string | null;
  decPassword?: string;
}

export interface Cipher {
  id: string;
  type: number;
  folderId?: string | null;
  favorite?: boolean;
  reprompt?: number;
  name?: string | null;
  notes?: string | null;
  key?: string | null;
  creationDate?: string;
  revisionDate?: string;
  deletedDate?: string | null;
  archivedDate?: string | null;
  attachments?: CipherAttachment[] | null;
  login?: CipherLogin | null;
  card?: CipherCard | null;
  identity?: CipherIdentity | null;
  sshKey?: CipherSshKey | null;
  bankAccount?: CipherBankAccount | null;
  driversLicense?: CipherDriversLicense | null;
  passport?: CipherPassport | null;
  secureNote?: { type?: number | null } | null;
  passwordHistory?: CipherPasswordHistoryEntry[] | null;
  fields?: CipherField[] | null;
  decName?: string;
  decNotes?: string;
}

export interface SendTextData {
  text?: string | null;
  hidden?: boolean;
}

export interface Send {
  id: string;
  accessId: string;
  type: number;
  name?: string | null;
  notes?: string | null;
  text?: SendTextData | null;
  key?: string | null;
  maxAccessCount?: number | null;
  accessCount?: number;
  password?: string | null;
  authType?: number | null;
  disabled?: boolean;
  revisionDate?: string;
  expirationDate?: string | null;
  deletionDate?: string;
  decName?: string;
  decNotes?: string;
  decText?: string;
  decShareKey?: string;
  shareUrl?: string;
  file?: {
    id?: string;
    fileName?: string;
    size?: string | number;
    sizeName?: string;
  } | null;
}

export interface SendDraft {
  id?: string;
  type: 'text' | 'file';
  name: string;
  notes: string;
  text: string;
  file: File | null;
  deletionDays: string;
  expirationDays: string;
  maxAccessCount: string;
  password: string;
  hasPassword?: boolean;
  disabled: boolean;
}

export type CustomFieldType = 0 | 1 | 2 | 3;

export interface VaultDraftField {
  type: CustomFieldType;
  label: string;
  value: string;
}

export interface VaultDraft {
  id?: string;
  type: number;
  favorite: boolean;
  name: string;
  folderId: string;
  notes: string;
  reprompt: boolean;
  loginUsername: string;
  loginPassword: string;
  loginTotp: string;
  loginUris: VaultDraftLoginUri[];
  loginFido2Credentials: Array<Record<string, unknown>>;
  cardholderName: string;
  cardNumber: string;
  cardBrand: string;
  cardExpMonth: string;
  cardExpYear: string;
  cardCode: string;
  identTitle: string;
  identFirstName: string;
  identMiddleName: string;
  identLastName: string;
  identUsername: string;
  identCompany: string;
  identSsn: string;
  identPassportNumber: string;
  identLicenseNumber: string;
  identEmail: string;
  identPhone: string;
  identAddress1: string;
  identAddress2: string;
  identAddress3: string;
  identCity: string;
  identState: string;
  identPostalCode: string;
  identCountry: string;
  sshPrivateKey: string;
  sshPublicKey: string;
  sshFingerprint: string;
  bankName: string;
  bankNameOnAccount: string;
  bankAccountType: string;
  bankAccountNumber: string;
  bankRoutingNumber: string;
  bankBranchNumber: string;
  bankPin: string;
  bankSwiftCode: string;
  bankIban: string;
  bankContactPhone: string;
  licenseFirstName: string;
  licenseMiddleName: string;
  licenseLastName: string;
  licenseDateOfBirth: string;
  licenseNumber: string;
  licenseIssuingCountry: string;
  licenseIssuingState: string;
  licenseIssueDate: string;
  licenseExpirationDate: string;
  licenseIssuingAuthority: string;
  licenseClass: string;
  passportSurname: string;
  passportGivenName: string;
  passportDateOfBirth: string;
  passportSex: string;
  passportBirthPlace: string;
  passportNationality: string;
  passportIssuingCountry: string;
  passportNumber: string;
  passportType: string;
  passportNationalIdentificationNumber: string;
  passportIssuingAuthority: string;
  passportIssueDate: string;
  passportExpirationDate: string;
  customFields: VaultDraftField[];
}

export interface ListResponse<T> {
  object: 'list';
  data: T[];
  total?: number;
  limit?: number;
  offset?: number;
  hasMore?: boolean;
  continuationToken?: string | null;
}

export interface WebBootstrapResponse {
  defaultKdfIterations?: number;
  jwtUnsafeReason?: 'missing' | 'too_short' | null;
  jwtSecretMinLength?: number;
  registrationInviteRequired?: boolean;
  webAuthnAllowedOrigins?: string[];
  websiteIconsEnabled?: boolean;
}

export interface YubiKeyOtpSettings {
  enabled: boolean;
  keys: [string, string, string, string, string];
  nfc: boolean;
  yubicoConfigured: boolean;
  yubicoCanManage: boolean;
  yubicoClientId: string;
  yubicoSecretKey: string;
}

export interface TokenSuccess {
  access_token: string;
  refresh_token?: string;
  web_session?: boolean;
  expires_in?: number;
  token_type?: string;
  TwoFactorToken?: string;
  Key?: string;
  PrivateKey?: string | null;
  AccountKeys?: unknown | null;
  accountKeys?: unknown | null;
  Kdf?: number;
  KdfIterations?: number;
  KdfMemory?: number | null;
  KdfParallelism?: number | null;
  ForcePasswordReset?: boolean;
  ResetMasterPassword?: boolean;
  scope?: string;
  unofficialServer?: boolean;
  UserVerificationToken?: string;
  userVerificationToken?: string;
  UserDecryptionOptions?: unknown;
  userDecryptionOptions?: unknown;
  VaultKeys?: {
    symEncKey?: string;
    symMacKey?: string;
  };
}

export interface TokenError {
  error?: string;
  error_description?: string;
  TwoFactorProviders?: unknown;
  TwoFactorProviders2?: unknown;
  CustomResponse?: {
    TwoFactorProviders?: unknown;
    TwoFactorProviders2?: unknown;
  };
}

export interface AccountPasskeyCredential {
  id: string;
  name: string;
  prfStatus: 0 | 1 | 2;
  encryptedPublicKey?: string | null;
  encryptedUserKey?: string | null;
  creationDate?: string;
  revisionDate?: string;
}

export interface TwoFactorPasskeyCredential {
  id: number;
  name: string;
  migrated?: boolean;
}

export interface TwoFactorPasskeySettings {
  enabled: boolean;
  keys: TwoFactorPasskeyCredential[];
}

export interface AuthRequest {
  id: string;
  publicKey: string;
  requestDeviceType?: string | null;
  requestDeviceTypeValue?: number | null;
  requestDeviceIdentifier: string;
  requestIpAddress?: string | null;
  requestCountryName?: string | null;
  key?: string | null;
  creationDate: string;
  requestApproved?: boolean | null;
  responseDate?: string | null;
  deviceId?: string | null;
  requestDeviceId?: string | null;
  fingerprintPhrase?: string;
}

export interface AccountPasskeyAssertionOptionsResponse {
  options: PublicKeyCredentialRequestOptions;
  token: string;
}

export interface AccountPasskeyCreationOptionsResponse {
  options: PublicKeyCredentialCreationOptions;
  token: string;
}

export interface AccountPasskeyPrfOption {
  EncryptedPrivateKey?: string;
  EncryptedUserKey?: string;
  CredentialId?: string;
  Transports?: string[];
  encryptedPrivateKey?: string;
  encryptedUserKey?: string;
  credentialId?: string;
  transports?: string[];
}

export interface ToastMessage {
  id: string;
  type: 'success' | 'error' | 'warning';
  text: string;
}

export interface AdminUser {
  id: string;
  email: string;
  name?: string;
  role: string;
  status: string;
}

export interface AdminInvite {
  code: string;
  inviteLink?: string;
  status: string;
  expiresAt?: string;
}

export type AuditLogCategory = 'auth' | 'security' | 'device' | 'data' | 'system';
export type AuditLogLevel = 'info' | 'warn' | 'error' | 'security';

export interface AuditLogEntry {
  id: string;
  actorUserId: string | null;
  actorEmail?: string | null;
  action: string;
  category: AuditLogCategory;
  level: AuditLogLevel;
  targetType: string | null;
  targetId: string | null;
  targetUserEmail?: string | null;
  metadata: string | null;
  createdAt: string;
  object?: 'auditLog';
}

export interface AuditLogSettings {
  retentionDays: number | null;
  maxEntries: number | null;
}

export interface AuditLogListResult {
  logs: AuditLogEntry[];
  total: number;
  limit: number;
  offset: number;
  hasMore: boolean;
}

export interface AuthorizedDevice {
  id: string;
  name: string;
  systemName?: string | null;
  deviceNote?: string | null;
  identifier: string;
  type: number;
  creationDate: string | null;
  revisionDate: string | null;
  lastSeenAt?: string | null;
  hasStoredDevice?: boolean;
  online: boolean;
  trusted: boolean;
  trustedTokenCount: number;
  trustedUntil: string | null;
}

export interface GlobalEquivalentDomain {
  type: number;
  domains: string[];
  excluded: boolean;
}

export interface CustomEquivalentDomain {
  id: string;
  domains: string[];
  excluded: boolean;
}

export interface DomainRules {
  equivalentDomains: string[][];
  customEquivalentDomains: CustomEquivalentDomain[];
  globalEquivalentDomains: GlobalEquivalentDomain[];
  object: 'domains';
}
