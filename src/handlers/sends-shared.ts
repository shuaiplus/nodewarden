import { decodeBase64Url } from 'hono/utils/encode';
import { z } from 'zod';
import { Send, SendAuthType, SendResponse, SendType } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { bytesToBase64Url } from '../utils/passkey';
import * as sendRepo from '../services/storage-send-repo';
import * as userRepo from '../services/storage-user-repo';

export const SEND_INACCESSIBLE_MSG = 'Send does not exist or is no longer available';
const SEND_PASSWORD_ITERATIONS = 100_000;
export const SEND_PASSWORD_LIMIT_SCOPE = 'send-password';

function base64UrlDecode(input: string): Uint8Array | null {
  try {
    return decodeBase64Url(input);
  } catch {
    return null;
  }
}

function uuidToBytes(uuid: string): Uint8Array | null {
  const hex = uuid.replace(/-/g, '').toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(hex)) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToUuid(bytes: Uint8Array): string | null {
  if (bytes.length !== 16) return null;
  const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

function toAccessId(sendId: string): string {
  const bytes = uuidToBytes(sendId);
  if (!bytes) return '';
  return bytesToBase64Url(bytes);
}

export function fromAccessId(accessId: string): string | null {
  const bytes = base64UrlDecode(accessId);
  if (!bytes || bytes.length !== 16) return null;
  return bytesToUuid(bytes);
}

export async function resolveSendFromIdOrAccessId(db: D1Database, idOrAccessId: string): Promise<Send | null> {
  if (z.guid().safeParse(idOrAccessId).success) {
    const send = await sendRepo.getSend(db, idOrAccessId);
    if (send) return send;
  }

  const sendId = fromAccessId(idOrAccessId);
  if (!sendId) return null;
  return sendRepo.getSend(db, sendId);
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function parseDate(raw: string): Date | null {
  let value = raw.trim();
  if (!value) return null;
  if (!/[zZ]$/.test(value) && !/[+\-]\d{2}:?\d{2}$/.test(value)) {
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(value)) {
      value += 'Z';
    } else if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(value)) {
      value = value.replace(' ', 'T') + 'Z';
    }
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

// Clients send integers as JSON numbers or numeric strings; a blank string stays invalid.
export const toInteger = (raw: unknown) => (typeof raw === 'string' && raw !== '' ? Number(raw) : raw);

// The stored blob round-trips every client field. Clients read the file size as a string, while
// creation stores the byte count as a number; a malformed field is dropped rather than failing the row.
const StoredSendData = z.looseObject({
  id: z.string().optional().catch(undefined),
  fileName: z.string().optional().catch(undefined),
  size: z.preprocess(toInteger, z.int()).transform(String).optional().catch(undefined),
});

export function parseStoredSendData(send: Send): z.output<typeof StoredSendData> {
  try {
    return StoredSendData.parse(JSON.parse(send.data));
  } catch {
    return {};
  }
}

// A file Send names its stored object inside the data blob; the route's file id must be that one.
export function sendFileIdMatches(send: Send, fileId: string): boolean {
  return parseStoredSendData(send).id === fileId;
}

export function isSendAvailable(send: Send): boolean {
  const now = Date.now();

  if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
    return false;
  }

  if (send.expirationDate) {
    const expirationMs = new Date(send.expirationDate).getTime();
    if (!Number.isNaN(expirationMs) && now >= expirationMs) {
      return false;
    }
  }

  const deletionMs = new Date(send.deletionDate).getTime();
  if (!Number.isNaN(deletionMs) && now >= deletionMs) {
    return false;
  }

  if (send.disabled) {
    return false;
  }

  return true;
}

async function deriveSendPasswordHash(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256',
    },
    key,
    256
  );
  return new Uint8Array(bits);
}

function isLikelyHashB64(value: string): boolean {
  const raw = String(value || '').trim();
  if (!raw) return false;
  if (!/^[A-Za-z0-9+/_=-]+$/.test(raw)) return false;
  const decoded = base64UrlDecode(raw);
  return !!decoded && decoded.length === 32;
}

export async function setSendPassword(send: Send, password: string | null): Promise<void> {
  if (!password) {
    send.passwordHash = null;
    send.passwordSalt = null;
    send.passwordIterations = null;
    if (send.authType === SendAuthType.Password) {
      send.authType = SendAuthType.None;
    }
    return;
  }

  if (isLikelyHashB64(password)) {
    send.passwordHash = password.trim();
    send.passwordSalt = null;
    send.passwordIterations = null;
    send.authType = SendAuthType.Password;
    return;
  }

  const salt = crypto.getRandomValues(new Uint8Array(64));
  const hash = await deriveSendPasswordHash(password, salt, SEND_PASSWORD_ITERATIONS);

  send.passwordSalt = bytesToBase64Url(salt);
  send.passwordHash = bytesToBase64Url(hash);
  send.passwordIterations = SEND_PASSWORD_ITERATIONS;
  send.authType = SendAuthType.Password;
}

export async function verifySendPassword(send: Send, password: string): Promise<boolean> {
  if (!send.passwordHash) {
    return false;
  }

  if (!send.passwordSalt || !send.passwordIterations) {
    return verifySendPasswordHashB64(send, password);
  }

  const salt = base64UrlDecode(send.passwordSalt);
  const expected = base64UrlDecode(send.passwordHash);
  if (!salt || !expected) return false;

  const actual = await deriveSendPasswordHash(password, salt, send.passwordIterations);
  return actual.length === expected.length && crypto.subtle.timingSafeEqual(actual, expected);
}

export function verifySendPasswordHashB64(send: Send, passwordHashB64: string): boolean {
  if (!send.passwordHash || !passwordHashB64) return false;
  const expected = base64UrlDecode(send.passwordHash);
  const provided = base64UrlDecode(passwordHashB64);
  if (!expected || !provided) return false;
  return expected.length === provided.length && crypto.subtle.timingSafeEqual(expected, provided);
}

export function hasEmailAuth(send: Send): boolean {
  return send.authType === SendAuthType.Email;
}

export function extractBearerToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

export function sendToResponse(send: Send): SendResponse {
  const data = parseStoredSendData(send);
  return {
    id: send.id,
    accessId: toAccessId(send.id),
    type: Number(send.type) || 0,
    name: send.name,
    notes: send.notes,
    text: send.type === SendType.Text ? data : null,
    file: send.type === SendType.File ? data : null,
    key: send.key,
    maxAccessCount: send.maxAccessCount,
    accessCount: send.accessCount,
    password: send.passwordHash,
    emails: send.emails,
    authType: send.authType,
    disabled: send.disabled,
    hideEmail: send.hideEmail,
    revisionDate: send.updatedAt,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    object: 'send',
  };
}

export function sendToAccessResponse(send: Send, creatorIdentifier: string | null): Record<string, unknown> {
  const data = parseStoredSendData(send);
  return {
    id: send.id,
    type: Number(send.type) || 0,
    name: send.name,
    text: send.type === SendType.Text ? data : null,
    file: send.type === SendType.File ? data : null,
    expirationDate: send.expirationDate,
    deletionDate: send.deletionDate,
    creatorIdentifier,
    object: 'send-access',
  };
}

export async function getCreatorIdentifier(db: D1Database, send: Send): Promise<string | null> {
  if (send.hideEmail) return null;
  const owner = await userRepo.getUserById(db, send.userId);
  return owner?.email ?? null;
}

export type PublicSendAccessValidationResult =
  | { ok: true }
  | { ok: false; response: Response; reason: 'email_auth_unsupported' | 'password_missing' | 'invalid_password' };

export function sendPasswordLimitKey(clientIdentifier: string, sendId: string): string {
  return `${clientIdentifier}:${SEND_PASSWORD_LIMIT_SCOPE}:${String(sendId || '').trim() || 'unknown-send'}`;
}

function sendPasswordLockMessage(retryAfterSeconds: number): string {
  return `Too many failed send password attempts. Try again in ${Math.ceil(retryAfterSeconds / 60)} minutes.`;
}

export function sendPasswordLockedErrorResponse(retryAfterSeconds: number): Response {
  return errorResponse(sendPasswordLockMessage(retryAfterSeconds), 429);
}

export function sendPasswordLockedOAuthResponse(retryAfterSeconds: number): Response {
  const message = sendPasswordLockMessage(retryAfterSeconds);
  return jsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      send_access_error_type: 'too_many_password_attempts',
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    429
  );
}

const optionalString = z.string().optional().catch(undefined);

// The access body is optional, so anything unreadable counts as no password. Clients spell the
// client-side password hash four ways; the first one sent wins.
const SendAccessBody = z.object({
  password: optionalString,
  password_hash_b64: optionalString,
  passwordHashB64: optionalString,
  passwordHash: optionalString,
  password_hash: optionalString,
}).catch({}).transform(({ password, ...hash }) => ({
  password,
  passwordHashB64: hash.password_hash_b64 ?? hash.passwordHashB64 ?? hash.passwordHash ?? hash.password_hash,
}));

export async function validatePublicSendAccess(send: Send, body: unknown): Promise<PublicSendAccessValidationResult> {
  if (hasEmailAuth(send)) {
    return {
      ok: false,
      response: errorResponse('Send email verification is not supported by this server.', 501),
      reason: 'email_auth_unsupported',
    };
  }

  if (!send.passwordHash) return { ok: true };

  const { password, passwordHashB64 } = SendAccessBody.parse(body);

  let validPassword = false;
  if (send.passwordSalt && send.passwordIterations) {
    if (password === undefined) {
      return { ok: false, response: errorResponse('Password not provided', 401), reason: 'password_missing' };
    }
    validPassword = await verifySendPassword(send, password);
  } else {
    const candidate = passwordHashB64 ?? password;
    if (!candidate) return { ok: false, response: errorResponse('Password not provided', 401), reason: 'password_missing' };
    validPassword = verifySendPasswordHashB64(send, candidate);
  }
  if (!validPassword) {
    return { ok: false, response: errorResponse('Invalid password', 400), reason: 'invalid_password' };
  }

  return { ok: true };
}
