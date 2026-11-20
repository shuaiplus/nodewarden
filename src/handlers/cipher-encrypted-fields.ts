const REQUIRED_FIDO2_ENCRYPTED_KEYS = [
  'credentialId', 'keyType', 'keyAlgorithm', 'keyCurve', 'keyValue', 'rpId', 'counter', 'discoverable',
] as const;
const OPTIONAL_FIDO2_ENCRYPTED_KEYS = ['userHandle', 'userName', 'rpName', 'userDisplayName'] as const;
const FIDO2_ENCRYPTED_KEYS = [...REQUIRED_FIDO2_ENCRYPTED_KEYS, ...OPTIONAL_FIDO2_ENCRYPTED_KEYS];

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
  if (type === 0 || type === 1 || type === 4) return parts.length >= 2;
  if (type === 2) return parts.length === 3;

  // Keep newer one-part formats, such as COSE Encrypt0, future-compatible.
  return parts.length >= 1;
}

export function optionalEncString(value: unknown): string | null {
  if (value == null || value === '') return null;
  return isValidEncString(value) ? value.trim() : null;
}

function isCredentialObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export function normalizeFido2CredentialsForStorage(credentials: unknown): unknown[] | null {
  if (!Array.isArray(credentials)) return null;
  return credentials.map((credential: unknown) => {
    if (!isCredentialObject(credential)) return credential;

    // Empty strings in optional fields represent missing metadata. Leave other
    // values intact so validation can still reject plaintext or malformed data.
    const normalized = { ...credential };
    for (const key of OPTIONAL_FIDO2_ENCRYPTED_KEYS) {
      if (normalized[key] === '') normalized[key] = null;
    }
    return normalized;
  });
}

export function validateFido2EncryptedFields(credentials: unknown): string | null {
  if (!Array.isArray(credentials)) return null;
  for (const credential of credentials) {
    if (!isCredentialObject(credential)) continue;
    for (const key of FIDO2_ENCRYPTED_KEYS) {
      if (credential[key] != null && !isValidEncString(credential[key])) {
        return `FIDO2 credential ${key} must be an encrypted string.`;
      }
    }
  }
  return null;
}

export function normalizeFido2CredentialsForCompatibility(credentials: unknown): Record<string, unknown>[] | null {
  if (!Array.isArray(credentials) || credentials.length === 0) return null;
  const out: Record<string, unknown>[] = [];
  for (const credential of credentials) {
    if (!isCredentialObject(credential)) continue;
    const next = { ...credential };
    let valid = true;
    for (const key of REQUIRED_FIDO2_ENCRYPTED_KEYS) {
      const value = next[key];
      if (!isValidEncString(value)) {
        valid = false;
        break;
      }
      next[key] = value.trim();
    }
    if (!valid) continue;
    for (const key of OPTIONAL_FIDO2_ENCRYPTED_KEYS) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        next[key] = optionalEncString(next[key]);
      }
    }
    out.push(next);
  }
  return out.length ? out : null;
}
