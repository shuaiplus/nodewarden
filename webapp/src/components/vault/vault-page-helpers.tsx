import { useMemo } from 'preact/hooks';
import {
  BookUser,
  CreditCard,
  FileKey2,
  Globe,
  IdCard,
  KeyRound,
  Landmark,
  ShieldUser,
  StickyNote,
} from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import { t } from '@/lib/i18n';
import type { Cipher, CipherAttachment, CustomFieldType, VaultDraft, VaultDraftField, VaultDraftLoginUri } from '@/lib/types';
import { firstCipherUri, hostFromUri, websiteIconUrl } from '@/lib/website-utils';
import { normalizeEquivalentDomain } from '@shared/domain-normalize';
import WebsiteIcon from './WebsiteIcon';

export type TypeFilter = 'login' | 'card' | 'identity' | 'note' | 'ssh' | 'bank' | 'license' | 'passport';
export type VaultSortMode = 'edited' | 'created' | 'name';
export type DuplicateDetectionMode = 'exact' | 'login-site' | 'login-credentials' | 'password';
export type SidebarFilter =
  | { kind: 'all' }
  | { kind: 'favorite' }
  | { kind: 'archive' }
  | { kind: 'trash' }
  | { kind: 'duplicates' }
  | { kind: 'type'; value: TypeFilter }
  | { kind: 'folder'; folderId: string | null };

interface TypeOption {
  type: number;
  label: string;
}

export const CARD_BRAND_OPTIONS = [
  'Visa',
  'Mastercard',
  'American Express',
  'Discover',
  'Diners Club',
  'JCB',
  'Maestro',
  'UnionPay',
  'RuPay',
] as const;

type CardBrand = typeof CARD_BRAND_OPTIONS[number];

const CARD_BRAND_ALIASES: Record<string, CardBrand> = {
  amex: 'American Express',
  'american express': 'American Express',
  americanexpress: 'American Express',
  discover: 'Discover',
  diners: 'Diners Club',
  'diners club': 'Diners Club',
  dinersclub: 'Diners Club',
  jcb: 'JCB',
  maestro: 'Maestro',
  mastercard: 'Mastercard',
  master: 'Mastercard',
  rupay: 'RuPay',
  unionpay: 'UnionPay',
  'union pay': 'UnionPay',
  visa: 'Visa',
};

const CARD_BRAND_LOGO_SLUGS: Partial<Record<CardBrand, string>> = {
  'American Express': 'american-express',
  'Diners Club': 'diners',
  Discover: 'discover',
  JCB: 'jcb',
  Maestro: 'maestro',
  Mastercard: 'mastercard',
  UnionPay: 'unionpay',
  Visa: 'visa',
};

export function normalizeCardBrand(value: string | null | undefined): string {
  const normalized = String(value || '').trim();
  if (!normalized) return '';
  return CARD_BRAND_ALIASES[normalized.toLowerCase().replace(/\s+/g, ' ')] || normalized;
}

export function displayCardBrand(value: string | null | undefined): string {
  return normalizeCardBrand(value);
}

export function cardLast4(value: string | null | undefined): string {
  const digits = String(value || '').replace(/\D/g, '');
  return digits.length >= 4 ? digits.slice(-4) : '';
}

export function cardListSubtitle(cipher: Cipher): string {
  const brand = displayCardBrand(cipher.card?.decBrand ?? cipher.card?.brand);
  const last4 = cardLast4(cipher.card?.decNumber ?? cipher.card?.number);
  if (brand && last4) return `${brand}, *${last4}`;
  if (brand) return brand;
  if (last4) return `*${last4}`;
  return cipherTypeLabel(3);
}

export function bankAccountListSubtitle(cipher: Cipher): string {
  const bankName = valueOrFallback(cipher.bankAccount?.decBankName ?? cipher.bankAccount?.bankName).trim();
  const accountType = valueOrFallback(cipher.bankAccount?.decAccountType ?? cipher.bankAccount?.accountType).trim();
  const accountNumber = valueOrFallback(cipher.bankAccount?.decAccountNumber ?? cipher.bankAccount?.accountNumber).replace(/\D/g, '');
  const last4 = accountNumber.length >= 4 ? accountNumber.slice(-4) : '';
  return [bankName, accountType, last4 ? `*${last4}` : ''].filter(Boolean).join(', ') || cipherTypeLabel(6);
}

export function driversLicenseListSubtitle(cipher: Cipher): string {
  const licenseNumber = valueOrFallback(cipher.driversLicense?.decLicenseNumber ?? cipher.driversLicense?.licenseNumber).trim();
  const name = [
    valueOrFallback(cipher.driversLicense?.decFirstName ?? cipher.driversLicense?.firstName).trim(),
    valueOrFallback(cipher.driversLicense?.decLastName ?? cipher.driversLicense?.lastName).trim(),
  ].filter(Boolean).join(' ');
  return licenseNumber || name || cipherTypeLabel(7);
}

export function passportListSubtitle(cipher: Cipher): string {
  const passportNumber = valueOrFallback(cipher.passport?.decPassportNumber ?? cipher.passport?.passportNumber).trim();
  const name = [
    valueOrFallback(cipher.passport?.decGivenName ?? cipher.passport?.givenName).trim(),
    valueOrFallback(cipher.passport?.decSurname ?? cipher.passport?.surname).trim(),
  ].filter(Boolean).join(' ');
  return passportNumber || name || cipherTypeLabel(8);
}

export function CardBrandIcon({ brand }: { brand?: string | null }) {
  const display = displayCardBrand(brand);
  const key = display.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'generic';
  const label = display || t('txt_card');
  const logoSlug = CARD_BRAND_LOGO_SLUGS[display as CardBrand];
  return (
    <span className={`card-brand-icon card-brand-${key}`} aria-label={label} title={label}>
      {logoSlug ? (
        <img src={`/payment-logos/cards/${logoSlug}.svg`} alt="" loading="lazy" decoding="async" />
      ) : (
        <CreditCard size={18} />
      )}
    </span>
  );
}

export function getCreateTypeOptions(): TypeOption[] {
  return [
    { type: 1, label: t('txt_login') },
    { type: 3, label: t('txt_card') },
    { type: 6, label: t('txt_bank_account') },
    { type: 4, label: t('txt_identity') },
    { type: 7, label: t('txt_drivers_license') },
    { type: 8, label: t('txt_passport') },
    { type: 2, label: t('txt_note') },
    { type: 5, label: t('txt_ssh_key') },
  ];
}

export const VAULT_SORT_STORAGE_KEY = 'nodewarden.vault.sort.v1';
export const FOLDER_SORT_STORAGE_KEY = 'nodewarden.folder-sort.v1';
export const MOBILE_LAYOUT_QUERY = '(max-width: 1180px)';
export const VAULT_LIST_ROW_HEIGHT = 74;
export const VAULT_LIST_OVERSCAN = 10;

export function getDuplicateDetectionOptions(): Array<{ value: DuplicateDetectionMode; label: string }> {
  return [
    { value: 'exact', label: t('txt_duplicate_mode_exact') },
    { value: 'login-site', label: t('txt_duplicate_mode_login_site') },
    { value: 'login-credentials', label: t('txt_duplicate_mode_login_credentials') },
    { value: 'password', label: t('txt_duplicate_mode_password') },
  ];
}

export function getVaultSortOptions(): Array<{ value: VaultSortMode; label: string }> {
  return [
    { value: 'edited', label: t('txt_sort_last_edited') },
    { value: 'created', label: t('txt_sort_created') },
    { value: 'name', label: t('txt_sort_name') },
  ];
}

export function getFolderSortOptions(): Array<{ value: VaultSortMode; label: string }> {
  return [
    { value: 'edited', label: t('txt_sort_last_edited') },
    { value: 'created', label: t('txt_sort_created') },
    { value: 'name', label: t('txt_sort_name') },
  ];
}

export function getFieldTypeOptions(): Array<{ value: CustomFieldType; label: string }> {
  return [
    { value: 0, label: t('txt_text') },
    { value: 1, label: t('txt_hidden') },
    { value: 2, label: t('txt_boolean') },
  ];
}

export function getWebsiteMatchOptions(): Array<{ value: number | null; label: string }> {
  return [
    { value: null, label: t('txt_uri_match_default_base_domain') },
    { value: 0, label: t('txt_uri_match_base_domain') },
    { value: 1, label: t('txt_uri_match_host') },
    { value: 3, label: t('txt_uri_match_exact') },
    { value: 5, label: t('txt_uri_match_never') },
    { value: 2, label: t('txt_uri_match_starts_with') },
    { value: 4, label: t('txt_uri_match_regular_expression') },
  ];
}

const TOTP_RING_RADIUS = 14;
export const TOTP_RING_CIRCUMFERENCE = 2 * Math.PI * TOTP_RING_RADIUS;

export function CreateTypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={15} />;
  if (type === 3) return <CreditCard size={15} />;
  if (type === 4) return <ShieldUser size={15} />;
  if (type === 2) return <StickyNote size={15} />;
  if (type === 5) return <KeyRound size={15} />;
  if (type === 6) return <Landmark size={15} />;
  if (type === 7) return <IdCard size={15} />;
  if (type === 8) return <BookUser size={15} />;
  return <FileKey2 size={15} />;
}

export function cipherTypeKey(type: number): TypeFilter {
  if (type === 1) return 'login';
  if (type === 3) return 'card';
  if (type === 4) return 'identity';
  if (type === 2) return 'note';
  if (type === 5) return 'ssh';
  if (type === 6) return 'bank';
  if (type === 7) return 'license';
  if (type === 8) return 'passport';
  return 'note';
}

function cipherDeletedValue(cipher: Cipher): boolean {
  return !!(cipher.deletedDate || (cipher as { deletedAt?: string | null }).deletedAt);
}

function cipherArchivedValue(cipher: Cipher): boolean {
  return !!(cipher.archivedDate || (cipher as { archivedAt?: string | null }).archivedAt);
}

export function isCipherDeleted(cipher: Cipher): boolean {
  return cipherDeletedValue(cipher);
}

export function isCipherArchived(cipher: Cipher): boolean {
  return cipherArchivedValue(cipher) && !cipherDeletedValue(cipher);
}

export function isCipherVisibleInNormalVault(cipher: Cipher): boolean {
  return !cipherDeletedValue(cipher) && !cipherArchivedValue(cipher);
}

export function isCipherVisibleInArchive(cipher: Cipher): boolean {
  return !cipherDeletedValue(cipher) && cipherArchivedValue(cipher);
}

export function isCipherVisibleInTrash(cipher: Cipher): boolean {
  return cipherDeletedValue(cipher);
}

export function cipherTypeLabel(type: number): string {
  if (type === 1) return t('txt_login');
  if (type === 3) return t('txt_card');
  if (type === 4) return t('txt_identity');
  if (type === 2) return t('txt_secure_note');
  if (type === 5) return t('txt_ssh_key');
  if (type === 6) return t('txt_bank_account');
  if (type === 7) return t('txt_drivers_license');
  if (type === 8) return t('txt_passport');
  return t('txt_item');
}

export function TypeIcon({ type }: { type: number }) {
  if (type === 1) return <Globe size={18} />;
  if (type === 3) return <CreditCard size={18} />;
  if (type === 4) return <ShieldUser size={18} />;
  if (type === 2) return <StickyNote size={18} />;
  if (type === 5) return <KeyRound size={18} />;
  if (type === 6) return <Landmark size={18} />;
  if (type === 7) return <IdCard size={18} />;
  if (type === 8) return <BookUser size={18} />;
  return <FileKey2 size={18} />;
}

export function parseFieldType(value: number | string | null | undefined): CustomFieldType {
  if (value === 1 || value === 2 || value === 3) return value;
  if (value === '1' || String(value).toLowerCase() === 'hidden') return 1;
  if (value === '2' || String(value).toLowerCase() === 'boolean') return 2;
  if (value === '3' || String(value).toLowerCase() === 'linked') return 3;
  return 0;
}

export function toBooleanFieldValue(raw: string): boolean {
  const v = String(raw || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

export { firstCipherUri, hostFromUri, websiteIconUrl };

export function createEmptyLoginUri(): VaultDraftLoginUri {
  return { uri: '', match: null, originalUri: '', extra: {} };
}

export function websiteMatchLabel(value: number | null | undefined): string {
  const normalized = typeof value === 'number' && Number.isFinite(value) ? value : null;
  return getWebsiteMatchOptions().find((option) => option.value === normalized)?.label || t('txt_uri_match_default_base_domain');
}

function valueOrFallback(value: string | null | undefined): string {
  return String(value || '');
}

function duplicateLoginUsername(cipher: Cipher): string {
  return valueOrFallback(cipher.login?.decUsername ?? cipher.login?.username).trim().toLowerCase();
}

function duplicateLoginPassword(cipher: Cipher): string {
  return valueOrFallback(cipher.login?.decPassword ?? cipher.login?.password);
}

function duplicateLoginSites(cipher: Cipher): string[] {
  const sites = new Set<string>();
  for (const uri of cipher.login?.uris || []) {
    const raw = valueOrFallback(uri.decUri ?? uri.uri).trim();
    if (!raw) continue;
    const host = hostFromUri(raw).trim().toLowerCase().replace(/^www\./, '');
    const site = normalizeEquivalentDomain(raw) || host;
    if (site) sites.add(site);
  }
  return Array.from(sites).sort();
}

function duplicateSignature(parts: string[]): string {
  return JSON.stringify(parts);
}

export function buildCipherDuplicateSignature(cipher: Cipher): string {
  const normalized = {
    type: Number(cipher.type || 1),
    folderId: cipher.folderId || null,
    favorite: !!cipher.favorite,
    reprompt: Number(cipher.reprompt || 0),
    name: valueOrFallback(cipher.decName ?? cipher.name),
    notes: valueOrFallback(cipher.decNotes ?? cipher.notes),
    login: cipher.login
      ? {
          username: valueOrFallback(cipher.login.decUsername ?? cipher.login.username),
          password: valueOrFallback(cipher.login.decPassword ?? cipher.login.password),
          totp: valueOrFallback(cipher.login.decTotp ?? cipher.login.totp),
          uris: (cipher.login.uris || []).map((uri) => ({
            uri: valueOrFallback(uri.decUri ?? uri.uri),
            match: uri.match ?? null,
          })),
          fido2Credentials: (cipher.login.fido2Credentials || []).map((credential) => ({
            creationDate: valueOrFallback(credential.creationDate),
          })),
        }
      : null,
    card: cipher.card
      ? {
          cardholderName: valueOrFallback(cipher.card.decCardholderName ?? cipher.card.cardholderName),
          number: valueOrFallback(cipher.card.decNumber ?? cipher.card.number),
          brand: valueOrFallback(cipher.card.decBrand ?? cipher.card.brand),
          expMonth: valueOrFallback(cipher.card.decExpMonth ?? cipher.card.expMonth),
          expYear: valueOrFallback(cipher.card.decExpYear ?? cipher.card.expYear),
          code: valueOrFallback(cipher.card.decCode ?? cipher.card.code),
        }
      : null,
    identity: cipher.identity
      ? {
          title: valueOrFallback(cipher.identity.decTitle ?? cipher.identity.title),
          firstName: valueOrFallback(cipher.identity.decFirstName ?? cipher.identity.firstName),
          middleName: valueOrFallback(cipher.identity.decMiddleName ?? cipher.identity.middleName),
          lastName: valueOrFallback(cipher.identity.decLastName ?? cipher.identity.lastName),
          username: valueOrFallback(cipher.identity.decUsername ?? cipher.identity.username),
          company: valueOrFallback(cipher.identity.decCompany ?? cipher.identity.company),
          ssn: valueOrFallback(cipher.identity.decSsn ?? cipher.identity.ssn),
          passportNumber: valueOrFallback(cipher.identity.decPassportNumber ?? cipher.identity.passportNumber),
          licenseNumber: valueOrFallback(cipher.identity.decLicenseNumber ?? cipher.identity.licenseNumber),
          email: valueOrFallback(cipher.identity.decEmail ?? cipher.identity.email),
          phone: valueOrFallback(cipher.identity.decPhone ?? cipher.identity.phone),
          address1: valueOrFallback(cipher.identity.decAddress1 ?? cipher.identity.address1),
          address2: valueOrFallback(cipher.identity.decAddress2 ?? cipher.identity.address2),
          address3: valueOrFallback(cipher.identity.decAddress3 ?? cipher.identity.address3),
          city: valueOrFallback(cipher.identity.decCity ?? cipher.identity.city),
          state: valueOrFallback(cipher.identity.decState ?? cipher.identity.state),
          postalCode: valueOrFallback(cipher.identity.decPostalCode ?? cipher.identity.postalCode),
          country: valueOrFallback(cipher.identity.decCountry ?? cipher.identity.country),
        }
      : null,
    sshKey: cipher.sshKey
      ? {
          privateKey: valueOrFallback(cipher.sshKey.decPrivateKey ?? cipher.sshKey.privateKey),
          publicKey: valueOrFallback(cipher.sshKey.decPublicKey ?? cipher.sshKey.publicKey),
          fingerprint: valueOrFallback(cipher.sshKey.decFingerprint ?? cipher.sshKey.keyFingerprint ?? cipher.sshKey.fingerprint),
        }
      : null,
    bankAccount: cipher.bankAccount
      ? {
          bankName: valueOrFallback(cipher.bankAccount.decBankName ?? cipher.bankAccount.bankName),
          nameOnAccount: valueOrFallback(cipher.bankAccount.decNameOnAccount ?? cipher.bankAccount.nameOnAccount),
          accountType: valueOrFallback(cipher.bankAccount.decAccountType ?? cipher.bankAccount.accountType),
          accountNumber: valueOrFallback(cipher.bankAccount.decAccountNumber ?? cipher.bankAccount.accountNumber),
          routingNumber: valueOrFallback(cipher.bankAccount.decRoutingNumber ?? cipher.bankAccount.routingNumber),
          branchNumber: valueOrFallback(cipher.bankAccount.decBranchNumber ?? cipher.bankAccount.branchNumber),
          pin: valueOrFallback(cipher.bankAccount.decPin ?? cipher.bankAccount.pin),
          swiftCode: valueOrFallback(cipher.bankAccount.decSwiftCode ?? cipher.bankAccount.swiftCode),
          iban: valueOrFallback(cipher.bankAccount.decIban ?? cipher.bankAccount.iban),
          bankContactPhone: valueOrFallback(cipher.bankAccount.decBankContactPhone ?? cipher.bankAccount.bankContactPhone),
        }
      : null,
    driversLicense: cipher.driversLicense
      ? {
          firstName: valueOrFallback(cipher.driversLicense.decFirstName ?? cipher.driversLicense.firstName),
          middleName: valueOrFallback(cipher.driversLicense.decMiddleName ?? cipher.driversLicense.middleName),
          lastName: valueOrFallback(cipher.driversLicense.decLastName ?? cipher.driversLicense.lastName),
          dateOfBirth: valueOrFallback(cipher.driversLicense.decDateOfBirth ?? cipher.driversLicense.dateOfBirth),
          licenseNumber: valueOrFallback(cipher.driversLicense.decLicenseNumber ?? cipher.driversLicense.licenseNumber),
          issuingCountry: valueOrFallback(cipher.driversLicense.decIssuingCountry ?? cipher.driversLicense.issuingCountry),
          issuingState: valueOrFallback(cipher.driversLicense.decIssuingState ?? cipher.driversLicense.issuingState),
          issueDate: valueOrFallback(cipher.driversLicense.decIssueDate ?? cipher.driversLicense.issueDate),
          expirationDate: valueOrFallback(cipher.driversLicense.decExpirationDate ?? cipher.driversLicense.expirationDate),
          issuingAuthority: valueOrFallback(cipher.driversLicense.decIssuingAuthority ?? cipher.driversLicense.issuingAuthority),
          licenseClass: valueOrFallback(cipher.driversLicense.decLicenseClass ?? cipher.driversLicense.licenseClass),
        }
      : null,
    passport: cipher.passport
      ? {
          surname: valueOrFallback(cipher.passport.decSurname ?? cipher.passport.surname),
          givenName: valueOrFallback(cipher.passport.decGivenName ?? cipher.passport.givenName),
          dateOfBirth: valueOrFallback(cipher.passport.decDateOfBirth ?? cipher.passport.dateOfBirth),
          sex: valueOrFallback(cipher.passport.decSex ?? cipher.passport.sex),
          birthPlace: valueOrFallback(cipher.passport.decBirthPlace ?? cipher.passport.birthPlace),
          nationality: valueOrFallback(cipher.passport.decNationality ?? cipher.passport.nationality),
          issuingCountry: valueOrFallback(cipher.passport.decIssuingCountry ?? cipher.passport.issuingCountry),
          passportNumber: valueOrFallback(cipher.passport.decPassportNumber ?? cipher.passport.passportNumber),
          passportType: valueOrFallback(cipher.passport.decPassportType ?? cipher.passport.passportType),
          nationalIdentificationNumber: valueOrFallback(cipher.passport.decNationalIdentificationNumber ?? cipher.passport.nationalIdentificationNumber),
          issuingAuthority: valueOrFallback(cipher.passport.decIssuingAuthority ?? cipher.passport.issuingAuthority),
          issueDate: valueOrFallback(cipher.passport.decIssueDate ?? cipher.passport.issueDate),
          expirationDate: valueOrFallback(cipher.passport.decExpirationDate ?? cipher.passport.expirationDate),
        }
      : null,
    secureNoteType: cipher.secureNote?.type ?? null,
    fields: (cipher.fields || []).map((field) => ({
      type: field.type ?? null,
      name: valueOrFallback(field.decName ?? field.name),
      value: valueOrFallback(field.decValue ?? field.value),
      linkedId: field.linkedId ?? null,
    })),
    passwordHistory: (cipher.passwordHistory || []).map((entry) => ({
      password: valueOrFallback(entry.decPassword ?? entry.password),
      lastUsedDate: valueOrFallback(entry.lastUsedDate),
    })),
  };
  return JSON.stringify(normalized);
}

export function buildCipherDuplicateSignatures(cipher: Cipher, mode: DuplicateDetectionMode): string[] {
  if (mode === 'exact') return [buildCipherDuplicateSignature(cipher)];
  if (Number(cipher.type || 1) !== 1 || !cipher.login) return [];

  const username = duplicateLoginUsername(cipher);
  const password = duplicateLoginPassword(cipher);
  if (mode === 'password') {
    return password ? [duplicateSignature(['password', password])] : [];
  }
  if (!username || !password) return [];
  if (mode === 'login-credentials') {
    return [duplicateSignature(['login-credentials', username, password])];
  }

  return duplicateLoginSites(cipher).map((site) => duplicateSignature(['login-site', site, username, password]));
}

export function createEmptyDraft(type: number): VaultDraft {
  return {
    type,
    favorite: false,
    name: '',
    folderId: '',
    notes: '',
    reprompt: false,
    loginUsername: '',
    loginPassword: '',
    loginTotp: '',
    loginUris: [createEmptyLoginUri()],
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
}

export function draftFromCipher(cipher: Cipher): VaultDraft {
  const draft = createEmptyDraft(Number(cipher.type || 1));
  draft.id = cipher.id;
  draft.favorite = !!cipher.favorite;
  draft.name = cipher.decName || '';
  draft.folderId = cipher.folderId || '';
  draft.notes = cipher.decNotes || '';
  draft.reprompt = Number(cipher.reprompt || 0) === 1;

  if (cipher.login) {
    draft.loginUsername = cipher.login.decUsername || '';
    draft.loginPassword = cipher.login.decPassword || '';
    draft.loginTotp = cipher.login.decTotp || '';
    draft.loginUris = (cipher.login.uris || []).map((x) => ({
      uri: x.decUri || x.uri || '',
      match: x.match ?? null,
      originalUri: x.decUri || x.uri || '',
      extra: Object.fromEntries(
        Object.entries(x as Record<string, unknown>).filter(([key]) => !['uri', 'match', 'decUri'].includes(key))
      ),
    }));
    draft.loginFido2Credentials = Array.isArray(cipher.login.fido2Credentials)
      ? cipher.login.fido2Credentials.map((credential) => ({ ...credential }))
      : [];
    if (!draft.loginUris.length) draft.loginUris = [createEmptyLoginUri()];
  }
  if (cipher.card) {
    draft.cardholderName = cipher.card.decCardholderName || '';
    draft.cardNumber = cipher.card.decNumber || '';
    draft.cardBrand = normalizeCardBrand(cipher.card.decBrand || '');
    draft.cardExpMonth = cipher.card.decExpMonth || '';
    draft.cardExpYear = cipher.card.decExpYear || '';
    draft.cardCode = cipher.card.decCode || '';
  }
  if (cipher.identity) {
    draft.identTitle = cipher.identity.decTitle || '';
    draft.identFirstName = cipher.identity.decFirstName || '';
    draft.identMiddleName = cipher.identity.decMiddleName || '';
    draft.identLastName = cipher.identity.decLastName || '';
    draft.identUsername = cipher.identity.decUsername || '';
    draft.identCompany = cipher.identity.decCompany || '';
    draft.identSsn = cipher.identity.decSsn || '';
    draft.identPassportNumber = cipher.identity.decPassportNumber || '';
    draft.identLicenseNumber = cipher.identity.decLicenseNumber || '';
    draft.identEmail = cipher.identity.decEmail || '';
    draft.identPhone = cipher.identity.decPhone || '';
    draft.identAddress1 = cipher.identity.decAddress1 || '';
    draft.identAddress2 = cipher.identity.decAddress2 || '';
    draft.identAddress3 = cipher.identity.decAddress3 || '';
    draft.identCity = cipher.identity.decCity || '';
    draft.identState = cipher.identity.decState || '';
    draft.identPostalCode = cipher.identity.decPostalCode || '';
    draft.identCountry = cipher.identity.decCountry || '';
  }
  if (cipher.sshKey) {
    draft.sshPrivateKey = cipher.sshKey.decPrivateKey || '';
    draft.sshPublicKey = cipher.sshKey.decPublicKey || '';
    draft.sshFingerprint = cipher.sshKey.decFingerprint || '';
  }
  if (cipher.bankAccount) {
    draft.bankName = cipher.bankAccount.decBankName || '';
    draft.bankNameOnAccount = cipher.bankAccount.decNameOnAccount || '';
    draft.bankAccountType = cipher.bankAccount.decAccountType || '';
    draft.bankAccountNumber = cipher.bankAccount.decAccountNumber || '';
    draft.bankRoutingNumber = cipher.bankAccount.decRoutingNumber || '';
    draft.bankBranchNumber = cipher.bankAccount.decBranchNumber || '';
    draft.bankPin = cipher.bankAccount.decPin || '';
    draft.bankSwiftCode = cipher.bankAccount.decSwiftCode || '';
    draft.bankIban = cipher.bankAccount.decIban || '';
    draft.bankContactPhone = cipher.bankAccount.decBankContactPhone || '';
  }
  if (cipher.driversLicense) {
    draft.licenseFirstName = cipher.driversLicense.decFirstName || '';
    draft.licenseMiddleName = cipher.driversLicense.decMiddleName || '';
    draft.licenseLastName = cipher.driversLicense.decLastName || '';
    draft.licenseDateOfBirth = cipher.driversLicense.decDateOfBirth || '';
    draft.licenseNumber = cipher.driversLicense.decLicenseNumber || '';
    draft.licenseIssuingCountry = cipher.driversLicense.decIssuingCountry || '';
    draft.licenseIssuingState = cipher.driversLicense.decIssuingState || '';
    draft.licenseIssueDate = cipher.driversLicense.decIssueDate || '';
    draft.licenseExpirationDate = cipher.driversLicense.decExpirationDate || '';
    draft.licenseIssuingAuthority = cipher.driversLicense.decIssuingAuthority || '';
    draft.licenseClass = cipher.driversLicense.decLicenseClass || '';
  }
  if (cipher.passport) {
    draft.passportSurname = cipher.passport.decSurname || '';
    draft.passportGivenName = cipher.passport.decGivenName || '';
    draft.passportDateOfBirth = cipher.passport.decDateOfBirth || '';
    draft.passportSex = cipher.passport.decSex || '';
    draft.passportBirthPlace = cipher.passport.decBirthPlace || '';
    draft.passportNationality = cipher.passport.decNationality || '';
    draft.passportIssuingCountry = cipher.passport.decIssuingCountry || '';
    draft.passportNumber = cipher.passport.decPassportNumber || '';
    draft.passportType = cipher.passport.decPassportType || '';
    draft.passportNationalIdentificationNumber = cipher.passport.decNationalIdentificationNumber || '';
    draft.passportIssuingAuthority = cipher.passport.decIssuingAuthority || '';
    draft.passportIssueDate = cipher.passport.decIssueDate || '';
    draft.passportExpirationDate = cipher.passport.decExpirationDate || '';
  }
  draft.customFields = (cipher.fields || []).map((field) => ({
    type: parseFieldType(field.type),
    label: field.decName || '',
    value: field.decValue || '',
  }));

  return draft;
}

export function maskSecret(value: string): string {
  if (!value) return '';
  return '*'.repeat(Math.max(8, Math.min(24, value.length)));
}

export function formatTotp(code: string): string {
  if (!code) return code;
  if (code.length === 5) return `${code.slice(0, 2)} ${code.slice(2)}`;
  if (code.length <= 4) return code;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code.replace(/(.{3})(?=.)/g, '$1 ');
}

export function formatHistoryTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return value;
  return date.toLocaleString();
}

export function parseAttachmentSizeBytes(attachment: CipherAttachment): number {
  const raw = attachment?.size;
  if (typeof raw === 'number' && Number.isFinite(raw) && raw >= 0) return raw;
  const parsed = Number(raw);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  return 0;
}

export function formatAttachmentSize(attachment: CipherAttachment): string {
  const sizeName = String(attachment?.sizeName || '').trim();
  if (sizeName) return sizeName;
  const bytes = parseAttachmentSizeBytes(attachment);
  if (bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function sortTimeValue(cipher: Cipher): number {
  const candidates = [cipher.revisionDate, cipher.creationDate];
  for (const value of candidates) {
    const time = new Date(String(value || '')).getTime();
    if (Number.isFinite(time)) return time;
  }
  return 0;
}

export function creationTimeValue(cipher: Cipher): number {
  const time = new Date(String(cipher.creationDate || '')).getTime();
  return Number.isFinite(time) ? time : 0;
}

export function firstPasskeyCreationTime(cipher: Cipher | null): string | null {
  const credentials = cipher?.login?.fido2Credentials;
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  for (const credential of credentials) {
    const raw = String(credential?.creationDate || '').trim();
    if (raw) return raw;
  }
  return null;
}

export function VaultListIcon({ cipher }: { cipher: Cipher }) {
  if (Number(cipher.type || 1) === 3) {
    return <CardBrandIcon brand={cipher.card?.decBrand ?? cipher.card?.brand} />;
  }
  return <WebsiteIcon cipher={cipher} fallback={<TypeIcon type={Number(cipher.type || 1)} />} />;
}

export function copyToClipboard(value: string): void {
  if (!value.trim()) return;
  void copyTextToClipboard(value);
}

export function openUri(raw: string): void {
  const value = raw.trim();
  if (!value) return;
  const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  window.open(url, '_blank', 'noopener');
}
