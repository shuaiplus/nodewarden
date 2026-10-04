// Server-side hide-passwords enforcement, extracted as a pure function so it
// is testable under node:test (handlers import Workers-typed modules that
// cannot execute outside the runtime).
//
// When an organization owner grants a member access with hidePasswords, the
// member still receives the org key (it is wrapped to their public key) — so
// the viewPassword flag alone is advisory and clients may ignore it. Stripping
// the encrypted password material server-side is the only real enforcement:
// the ciphertext never leaves the server, so it cannot be decrypted at all.
//
// The stripped set mirrors Bitwarden's hidden-field semantics across every
// cipher type: login passwords and TOTP, card security codes, identity SSN /
// license / passport numbers, SSH private keys, bank PIN and account numbers,
// hidden custom fields, and the whole password history. Notes stay visible
// (Bitwarden does not treat notes as password material).
//
// Every value is replaced with an explicit null (never undefined) so official
// client models with non-optional fields keep parsing.

interface StripInputLogin {
  password?: unknown;
  totp?: unknown;
}

interface StripInputField {
  type?: unknown;
  value?: unknown;
}

export interface StripPasswordMaterialInput {
  login?: StripInputLogin | null;
  card?: Record<string, unknown> | null;
  identity?: Record<string, unknown> | null;
  sshKey?: Record<string, unknown> | null;
  bankAccount?: Record<string, unknown> | null;
  driversLicense?: Record<string, unknown> | null;
  passport?: Record<string, unknown> | null;
  fields?: Array<StripInputField | null> | null;
  passwordHistory?: Array<Record<string, unknown>> | null;
}

export interface StripPasswordMaterialResult {
  login: (StripInputLogin & Record<string, unknown>) | null;
  card: Record<string, unknown> | null;
  identity: Record<string, unknown> | null;
  sshKey: Record<string, unknown> | null;
  bankAccount: Record<string, unknown> | null;
  driversLicense: Record<string, unknown> | null;
  passport: Record<string, unknown> | null;
  fields: Array<StripInputField | null> | null;
  passwordHistory: null;
}

function stripKeys(source: Record<string, unknown> | null | undefined, keys: string[]): Record<string, unknown> | null {
  if (!source || typeof source !== 'object') return source ?? null;
  const next: Record<string, unknown> = { ...source };
  for (const key of keys) {
    if (next[key] !== undefined) next[key] = null;
  }
  return next;
}

// Bitwarden custom field type 1 = hidden.
const HIDDEN_FIELD_TYPE = 1;

export function stripPasswordMaterial<T extends StripPasswordMaterialInput>(cipher: T): T {
  const login = cipher.login
    ? { ...cipher.login, password: null, totp: null } as (StripInputLogin & Record<string, unknown>)
    : null;

  const card = stripKeys(cipher.card, ['code']);
  const identity = stripKeys(cipher.identity, ['ssn', 'licenseNumber', 'passportNumber']);
  const sshKey = stripKeys(cipher.sshKey, ['privateKey']);
  const bankAccount = stripKeys(cipher.bankAccount, ['pin', 'accountNumber']);
  const driversLicense = stripKeys(cipher.driversLicense, ['licenseNumber']);
  const passport = stripKeys(cipher.passport, ['passportNumber']);

  const fields = Array.isArray(cipher.fields)
    ? cipher.fields.map((field) =>
        field && typeof field === 'object' && Number(field.type) === HIDDEN_FIELD_TYPE
          ? { ...field, value: null }
          : field
      )
    : null as unknown as Array<StripInputField | null> | null;

  return {
    ...cipher,
    login,
    card,
    identity,
    sshKey,
    bankAccount,
    driversLicense,
    passport,
    fields,
    // The whole history is password material; nothing in it is safe to keep.
    passwordHistory: null,
  };
}
