export type GoogleAuthenticatorMigrationAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

export interface GoogleAuthenticatorMigrationAcceptedAccount {
  kind: 'accepted';
  issuer: string;
  name: string;
  algorithm: GoogleAuthenticatorMigrationAlgorithm;
  digits: 6 | 8;
  period: 30;
  totp: string;
}

export interface GoogleAuthenticatorMigrationExcludedAccount {
  kind: 'excluded';
  reason:
    | 'hotp'
    | 'malformed-record'
    | 'missing-secret'
    | 'unsupported-algorithm'
    | 'unsupported-digits'
    | 'unsupported-type';
}

export interface GoogleAuthenticatorMigrationPage {
  batchId: number;
  batchSize: number;
  batchIndex: number;
  version: 1 | 2;
  accounts: Array<GoogleAuthenticatorMigrationAcceptedAccount | GoogleAuthenticatorMigrationExcludedAccount>;
}

export type GoogleAuthenticatorMigrationParseResult =
  | { ok: true; page: GoogleAuthenticatorMigrationPage }
  | {
    ok: false;
    reason: 'invalid-data' | 'invalid-batch' | 'invalid-uri' | 'malformed-payload' | 'unsupported-version';
    version?: number | null;
    accountCount?: number;
    batchSize?: number | null;
    batchIndex?: number | null;
    batchId?: number | null;
    payloadBytes?: number;
  };

const MAX_URI_LENGTH = 100_000;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_FIELD_BYTES = 4 * 1024;
const MAX_ACCOUNT_COUNT = 512;
const MAX_BATCH_SIZE = 100;
const MIN_SECRET_BYTES = 10;
const SUPPORTED_VERSIONS = new Set([1, 2]);

interface ProtoState {
  offset: number;
}

/** Read a protobuf varint and return the low 32 bits as unsigned (int32/uint32 wire). */
function readVarint32(bytes: Uint8Array, state: ProtoState): number | null {
  let value = 0n;
  for (let index = 0; index < 10; index += 1) {
    if (state.offset >= bytes.length) return null;
    const byte = bytes[state.offset++];
    value |= BigInt(byte & 0x7f) << BigInt(7 * index);
    if ((byte & 0x80) === 0) return Number(value & 0xffffffffn);
  }
  return null;
}

function readBytes(bytes: Uint8Array, state: ProtoState, maxLength: number): Uint8Array | null {
  const length = readVarint32(bytes, state);
  if (length == null || length > maxLength || state.offset + length > bytes.length) return null;
  const value = bytes.slice(state.offset, state.offset + length);
  state.offset += length;
  return value;
}

function skipField(bytes: Uint8Array, state: ProtoState, wireType: number): boolean {
  if (wireType === 0) return readVarint32(bytes, state) != null;
  if (wireType === 1 && state.offset + 8 <= bytes.length) {
    state.offset += 8;
    return true;
  }
  if (wireType === 2) return readBytes(bytes, state, MAX_FIELD_BYTES) != null;
  if (wireType === 5 && state.offset + 4 <= bytes.length) {
    state.offset += 4;
    return true;
  }
  return false;
}

function decodeBase64(value: string): Uint8Array | null {
  const normalized = value.replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return null;
  const padding = normalized.match(/=+$/);
  const firstPadding = normalized.indexOf('=');
  if (firstPadding >= 0 && (!padding || firstPadding < normalized.length - padding[0].length)) return null;
  const unpadded = normalized.replace(/=+$/g, '');
  if (unpadded.length % 4 === 1) return null;
  try {
    const binary = atob(unpadded + '='.repeat((4 - (unpadded.length % 4)) % 4));
    if (binary.length > MAX_PAYLOAD_BYTES) return null;
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

function bytesToBase32(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function algorithmFromEnum(value: number): GoogleAuthenticatorMigrationAlgorithm | null {
  // 0 = ALGORITHM_UNSPECIFIED → SHA-1 (Google export default)
  if (value === 0 || value === 1) return 'SHA-1';
  if (value === 2) return 'SHA-256';
  if (value === 3) return 'SHA-512';
  return null;
}

function digitsFromEnum(value: number): 6 | 8 | null {
  // 0 = DIGIT_COUNT_UNSPECIFIED → 6 (Google export default)
  if (value === 0 || value === 1) return 6;
  if (value === 2) return 8;
  return null;
}

function buildOtpAuthUri(account: Omit<GoogleAuthenticatorMigrationAcceptedAccount, 'kind' | 'totp'> & { secret: string }): string {
  const issuer = account.issuer.trim();
  const name = account.name.trim();
  const label = issuer && name && !name.toLowerCase().startsWith(`${issuer.toLowerCase()}:`)
    ? `${issuer}:${name}`
    : name || issuer || 'TOTP';
  const params = new URLSearchParams({
    secret: account.secret,
    algorithm: account.algorithm.replace('-', ''),
    digits: String(account.digits),
    period: '30',
  });
  if (issuer) params.set('issuer', issuer);
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}

function excluded(reason: GoogleAuthenticatorMigrationExcludedAccount['reason']): GoogleAuthenticatorMigrationExcludedAccount {
  return { kind: 'excluded', reason };
}

function parseOtpParameter(bytes: Uint8Array): GoogleAuthenticatorMigrationAcceptedAccount | GoogleAuthenticatorMigrationExcludedAccount {
  const state = { offset: 0 };
  let secret: Uint8Array | null = null;
  let name = '';
  let issuer = '';
  let algorithm: GoogleAuthenticatorMigrationAlgorithm | null = null;
  let digits: 6 | 8 | null = null;
  let otpType: number | null = null;
  const seen = new Set<number>();

  while (state.offset < bytes.length) {
    const key = readVarint32(bytes, state);
    if (key == null) return excluded('malformed-record');
    const fieldNumber = Math.floor(key / 8);
    const wireType = key % 8;
    if (fieldNumber >= 1 && fieldNumber <= 6 && seen.has(fieldNumber)) return excluded('malformed-record');
    if (fieldNumber >= 1 && fieldNumber <= 6) seen.add(fieldNumber);

    if (fieldNumber === 1 && wireType === 2) {
      secret = readBytes(bytes, state, MAX_FIELD_BYTES);
      if (!secret) return excluded('malformed-record');
    } else if (fieldNumber === 2 && wireType === 2) {
      const value = readBytes(bytes, state, MAX_FIELD_BYTES);
      const decoded = value ? decodeUtf8(value) : null;
      if (decoded == null) return excluded('malformed-record');
      name = decoded;
    } else if (fieldNumber === 3 && wireType === 2) {
      const value = readBytes(bytes, state, MAX_FIELD_BYTES);
      const decoded = value ? decodeUtf8(value) : null;
      if (decoded == null) return excluded('malformed-record');
      issuer = decoded;
    } else if (fieldNumber === 4 && wireType === 0) {
      const value = readVarint32(bytes, state);
      algorithm = value == null ? null : algorithmFromEnum(value);
      if (!algorithm) return excluded('unsupported-algorithm');
    } else if (fieldNumber === 5 && wireType === 0) {
      const value = readVarint32(bytes, state);
      digits = value == null ? null : digitsFromEnum(value);
      if (!digits) return excluded('unsupported-digits');
    } else if (fieldNumber === 6 && wireType === 0) {
      otpType = readVarint32(bytes, state);
      if (otpType == null) return excluded('malformed-record');
    } else if (!skipField(bytes, state, wireType)) {
      return excluded('malformed-record');
    }
  }

  if (!secret || secret.length < MIN_SECRET_BYTES) return excluded('missing-secret');
  if (otpType === 1) return excluded('hotp');
  if (otpType !== 2) return excluded('unsupported-type');
  // Absent algorithm/digits fields use Google's UNSPECIFIED defaults.
  const resolvedAlgorithm = algorithm ?? 'SHA-1';
  const resolvedDigits = digits ?? 6;
  const base32Secret = bytesToBase32(secret);
  return {
    kind: 'accepted',
    issuer,
    name,
    algorithm: resolvedAlgorithm,
    digits: resolvedDigits,
    period: 30,
    totp: buildOtpAuthUri({
      issuer,
      name,
      algorithm: resolvedAlgorithm,
      digits: resolvedDigits,
      period: 30,
      secret: base32Secret,
    }),
  };
}

function parseMigrationPayload(bytes: Uint8Array): GoogleAuthenticatorMigrationParseResult {
  const state = { offset: 0 };
  const accounts: GoogleAuthenticatorMigrationPage['accounts'] = [];
  let version: number | null = null;
  let batchSize: number | null = null;
  let batchIndex: number | null = null;
  let batchId: number | null = null;
  const seen = new Set<number>();

  while (state.offset < bytes.length) {
    const key = readVarint32(bytes, state);
    if (key == null) return { ok: false, reason: 'malformed-payload' };
    const fieldNumber = Math.floor(key / 8);
    const wireType = key % 8;
    if (fieldNumber >= 2 && fieldNumber <= 5 && seen.has(fieldNumber)) {
      return { ok: false, reason: 'malformed-payload' };
    }
    if (fieldNumber >= 2 && fieldNumber <= 5) seen.add(fieldNumber);

    if (fieldNumber === 1 && wireType === 2) {
      if (accounts.length >= MAX_ACCOUNT_COUNT) return { ok: false, reason: 'malformed-payload' };
      const parameter = readBytes(bytes, state, MAX_FIELD_BYTES);
      if (!parameter) return { ok: false, reason: 'malformed-payload' };
      accounts.push(parseOtpParameter(parameter));
    } else if (fieldNumber === 2 && wireType === 0) {
      version = readVarint32(bytes, state);
    } else if (fieldNumber === 3 && wireType === 0) {
      batchSize = readVarint32(bytes, state);
    } else if (fieldNumber === 4 && wireType === 0) {
      batchIndex = readVarint32(bytes, state);
    } else if (fieldNumber === 5 && wireType === 0) {
      batchId = readVarint32(bytes, state);
    } else if (!skipField(bytes, state, wireType)) {
      return { ok: false, reason: 'malformed-payload' };
    }
  }

  // Proto3 scalar defaults: absent version 0/null → 1; absent batch fields → single-page defaults.
  const resolvedVersion = version == null || version === 0 ? 1 : version;
  if (!SUPPORTED_VERSIONS.has(resolvedVersion)) {
    return { ok: false, reason: 'unsupported-version', version: resolvedVersion, accountCount: accounts.length };
  }
  const resolvedBatchSize = batchSize == null || batchSize === 0 ? (accounts.length ? 1 : null) : batchSize;
  const resolvedBatchIndex = batchIndex == null ? 0 : batchIndex;
  const resolvedBatchId = batchId == null ? 0 : batchId;
  if (!accounts.length || resolvedBatchSize == null
    || resolvedBatchSize < 1 || resolvedBatchSize > MAX_BATCH_SIZE
    || resolvedBatchIndex < 0 || resolvedBatchIndex >= resolvedBatchSize) {
    return {
      ok: false,
      reason: 'invalid-batch',
      version: resolvedVersion,
      accountCount: accounts.length,
      batchSize: resolvedBatchSize,
      batchIndex: resolvedBatchIndex,
      batchId: resolvedBatchId,
    };
  }

  return {
    ok: true,
    page: {
      batchId: resolvedBatchId,
      batchSize: resolvedBatchSize,
      batchIndex: resolvedBatchIndex,
      version: resolvedVersion as 1 | 2,
      accounts,
    },
  };
}

function extractMigrationDataParam(raw: string): string | null {
  const trimmed = String(raw || '').trim();
  const queryIndex = trimmed.indexOf('?');
  if (queryIndex < 0) return null;
  let found: string | null = null;
  for (const part of trimmed.slice(queryIndex + 1).split('&')) {
    const eq = part.indexOf('=');
    const key = eq < 0 ? part : part.slice(0, eq);
    if (key !== 'data') {
      if (key) return null;
      continue;
    }
    if (found != null) return null;
    const value = eq < 0 ? '' : part.slice(eq + 1);
    // Keep '+' as '+' (URLSearchParams would turn it into a space and corrupt Base64).
    try {
      found = decodeURIComponent(value.replace(/\+/g, '%2B'));
    } catch {
      return null;
    }
  }
  return found;
}

export function parseGoogleAuthenticatorMigrationPage(raw: string): GoogleAuthenticatorMigrationParseResult {
  if (raw.length > MAX_URI_LENGTH) return { ok: false, reason: 'invalid-uri' };
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'invalid-uri' };
  }
  if (url.protocol.toLowerCase() !== 'otpauth-migration:' || url.hostname.toLowerCase() !== 'offline'
    || (url.pathname !== '' && url.pathname !== '/')) {
    return { ok: false, reason: 'invalid-uri' };
  }
  const data = extractMigrationDataParam(raw);
  if (data == null) return { ok: false, reason: 'invalid-data' };
  const bytes = decodeBase64(data);
  if (!bytes) return { ok: false, reason: 'invalid-data' };
  const parsed = parseMigrationPayload(bytes);
  if (!parsed.ok) return { ...parsed, payloadBytes: bytes.length };
  return parsed;
}
