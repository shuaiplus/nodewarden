import type { Cipher } from '@/lib/types';

export const LoginLinkedId = {
  Username: 100,
  Password: 101,
} as const;

export const CardLinkedId = {
  CardholderName: 300,
  ExpMonth: 301,
  ExpYear: 302,
  Code: 303,
  Brand: 304,
  Number: 305,
} as const;

export const IdentityLinkedId = {
  Title: 400,
  MiddleName: 401,
  Address1: 402,
  Address2: 403,
  Address3: 404,
  City: 405,
  State: 406,
  PostalCode: 407,
  Country: 408,
  Company: 409,
  Email: 410,
  Phone: 411,
  Ssn: 412,
  Username: 413,
  PassportNumber: 414,
  LicenseNumber: 415,
  FirstName: 416,
  LastName: 417,
  FullName: 418,
} as const;

export interface LinkedFieldOption {
  value: number;
  labelKey: string;
}

const LOGIN_OPTIONS: LinkedFieldOption[] = [
  { value: LoginLinkedId.Username, labelKey: 'txt_username' },
  { value: LoginLinkedId.Password, labelKey: 'txt_password' },
];

const CARD_OPTIONS: LinkedFieldOption[] = [
  { value: CardLinkedId.CardholderName, labelKey: 'txt_cardholder_name' },
  { value: CardLinkedId.Number, labelKey: 'txt_number' },
  { value: CardLinkedId.Brand, labelKey: 'txt_brand' },
  { value: CardLinkedId.ExpMonth, labelKey: 'txt_expiry_month' },
  { value: CardLinkedId.ExpYear, labelKey: 'txt_expiry_year' },
  { value: CardLinkedId.Code, labelKey: 'txt_security_code' },
];

const IDENTITY_OPTIONS: LinkedFieldOption[] = [
  { value: IdentityLinkedId.Title, labelKey: 'txt_title' },
  { value: IdentityLinkedId.FirstName, labelKey: 'txt_first_name' },
  { value: IdentityLinkedId.MiddleName, labelKey: 'txt_middle_name' },
  { value: IdentityLinkedId.LastName, labelKey: 'txt_last_name' },
  { value: IdentityLinkedId.Username, labelKey: 'txt_username' },
  { value: IdentityLinkedId.Company, labelKey: 'txt_company' },
  { value: IdentityLinkedId.Ssn, labelKey: 'txt_ssn' },
  { value: IdentityLinkedId.PassportNumber, labelKey: 'txt_passport_number' },
  { value: IdentityLinkedId.LicenseNumber, labelKey: 'txt_license_number' },
  { value: IdentityLinkedId.Email, labelKey: 'txt_email' },
  { value: IdentityLinkedId.Phone, labelKey: 'txt_phone' },
  { value: IdentityLinkedId.Address1, labelKey: 'txt_address_1' },
  { value: IdentityLinkedId.City, labelKey: 'txt_city_town' },
  { value: IdentityLinkedId.State, labelKey: 'txt_state_province' },
  { value: IdentityLinkedId.PostalCode, labelKey: 'txt_postal_code' },
  { value: IdentityLinkedId.Country, labelKey: 'txt_country' },
];

const ALL_OPTIONS: LinkedFieldOption[] = [...LOGIN_OPTIONS, ...CARD_OPTIONS, ...IDENTITY_OPTIONS];

const LINKED_FIELD_OPTIONS_BY_TYPE: Partial<Record<number, LinkedFieldOption[]>> = {
  1: LOGIN_OPTIONS,
  3: CARD_OPTIONS,
  4: IDENTITY_OPTIONS,
};

export function supportsLinkedFields(cipherType: number): boolean {
  return cipherType in LINKED_FIELD_OPTIONS_BY_TYPE;
}

export function linkedFieldOptionsForType(cipherType: number): LinkedFieldOption[] {
  return LINKED_FIELD_OPTIONS_BY_TYPE[cipherType] ?? [];
}

export function linkedFieldLabelKey(linkedId: number | null | undefined): string {
  const found = ALL_OPTIONS.find((option) => option.value === linkedId);
  return found ? found.labelKey : 'txt_field';
}

const SENSITIVE_LINKED_IDS = new Set<number>([
  LoginLinkedId.Password,
  CardLinkedId.Code,
  IdentityLinkedId.Ssn,
]);

export function isSensitiveLinkedId(linkedId: number | null | undefined): boolean {
  return linkedId != null && SENSITIVE_LINKED_IDS.has(linkedId);
}

export function linkedFieldValue(cipher: Cipher, linkedId: number | null | undefined): string {
  if (linkedId == null) return '';
  const login = cipher.login;
  const card = cipher.card;
  const identity = cipher.identity;
  switch (linkedId) {
    case LoginLinkedId.Username: return login?.decUsername ?? login?.username ?? '';
    case LoginLinkedId.Password: return login?.decPassword ?? login?.password ?? '';
    case CardLinkedId.CardholderName: return card?.decCardholderName ?? card?.cardholderName ?? '';
    case CardLinkedId.Number: return card?.decNumber ?? card?.number ?? '';
    case CardLinkedId.Brand: return card?.decBrand ?? card?.brand ?? '';
    case CardLinkedId.ExpMonth: return card?.decExpMonth ?? card?.expMonth ?? '';
    case CardLinkedId.ExpYear: return card?.decExpYear ?? card?.expYear ?? '';
    case CardLinkedId.Code: return card?.decCode ?? card?.code ?? '';
    case IdentityLinkedId.Title: return identity?.decTitle ?? identity?.title ?? '';
    case IdentityLinkedId.FirstName: return identity?.decFirstName ?? identity?.firstName ?? '';
    case IdentityLinkedId.MiddleName: return identity?.decMiddleName ?? identity?.middleName ?? '';
    case IdentityLinkedId.LastName: return identity?.decLastName ?? identity?.lastName ?? '';
    case IdentityLinkedId.Username: return identity?.decUsername ?? identity?.username ?? '';
    case IdentityLinkedId.Company: return identity?.decCompany ?? identity?.company ?? '';
    case IdentityLinkedId.Ssn: return identity?.decSsn ?? identity?.ssn ?? '';
    case IdentityLinkedId.PassportNumber: return identity?.decPassportNumber ?? identity?.passportNumber ?? '';
    case IdentityLinkedId.LicenseNumber: return identity?.decLicenseNumber ?? identity?.licenseNumber ?? '';
    case IdentityLinkedId.Email: return identity?.decEmail ?? identity?.email ?? '';
    case IdentityLinkedId.Phone: return identity?.decPhone ?? identity?.phone ?? '';
    case IdentityLinkedId.Address1: return identity?.decAddress1 ?? identity?.address1 ?? '';
    case IdentityLinkedId.Address2: return identity?.decAddress2 ?? identity?.address2 ?? '';
    case IdentityLinkedId.Address3: return identity?.decAddress3 ?? identity?.address3 ?? '';
    case IdentityLinkedId.City: return identity?.decCity ?? identity?.city ?? '';
    case IdentityLinkedId.State: return identity?.decState ?? identity?.state ?? '';
    case IdentityLinkedId.PostalCode: return identity?.decPostalCode ?? identity?.postalCode ?? '';
    case IdentityLinkedId.Country: return identity?.decCountry ?? identity?.country ?? '';
    case IdentityLinkedId.FullName: {
      const first = identity?.decFirstName ?? identity?.firstName ?? '';
      const middle = identity?.decMiddleName ?? identity?.middleName ?? '';
      const last = identity?.decLastName ?? identity?.lastName ?? '';
      return [first, middle, last].filter(Boolean).join(' ');
    }
    default: return '';
  }
}
