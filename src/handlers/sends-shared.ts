import { Env, Send, SendAuthType, SendResponse, SendType } from '../types';
import {
  notifyUserSendCreate,
  notifyUserSendDelete,
  notifyUserSendUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { LIMITS } from '../config/limits';

export const SEND_INACCESSIBLE_MSG = 'Send does not exist or is no longer available';
const SEND_PASSWORD_ITERATIONS = 100_000;
export const SEND_PASSWORD_LIMIT_SCOPE = 'send-password';

export function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

export function notifySendCreateForRequest(
  request: Request,
  env: Env,
  sendId: string,
  userId: string,
  revisionDate: string
): void {
  notifyUserSendCreate(env, {
    userId,
    sendId,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
}

export function notifySendUpdateForRequest(
  request: Request,
  env: Env,
  sendId: string,
  userId: string,
  revisionDate: string
): void {
  notifyUserSendUpdate(env, {
    userId,
    sendId,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
}

export function notifySendDeleteForRequest(
  request: Request,
  env: Env,
  sendId: string,
  userId: string,
  revisionDate: string
): void {
  notifyUserSendDelete(env, {
    userId,
    sendId,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
}

export function getAliasedProp(source: unknown, aliases: string[]): { present: boolean; value: unknown } {
  if (!source || typeof source !== 'object') return { present: false, value: undefined };
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      const value = (source as Record<string, unknown>)[key];
      return { present: true, value };
    }
  }
  return { present: false, value: undefined };
}

export function base64UrlEncode(data: Uint8Array): string {
  const base64 = btoa(String.fromCharCode(...data));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(input: string): Uint8Array | null {
  try {
    let normalized = input.replace(/-/g, '+').replace(/_/g, '/');
    while (normalized.length % 4) normalized += '=';
    const raw = atob(normalized);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
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
  return base64UrlEncode(bytes);
}

export function fromAccessId(accessId: string): string | null {
  const bytes = base64UrlDecode(accessId);
  if (!bytes || bytes.length !== 16) return null;
  return bytesToUuid(bytes);
}

function isLikelyUuid(value: string): boolean {
  return /^[a-f0-9-]{36}$/i.test(value);
}

export async function resolveSendFromIdOrAccessId(storage: StorageService, idOrAccessId: string): Promise<Send | null> {
  if (isLikelyUuid(idOrAccessId)) {
    const send = await storage.getSend(idOrAccessId);
    if (send) return send;
  }

  const sendId = fromAccessId(idOrAccessId);
  if (!sendId) return null;
  return storage.getSend(sendId);
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function parseDate(raw: unknown): Date | null {
  if (typeof raw !== 'string' || !raw.trim()) return null;
  let value = raw.trim();
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

export function parseInteger(raw: unknown): number | null {
  if (raw === null || raw === undefined || raw === '') return null;
  const value = typeof raw === 'string' ? Number(raw) : raw;
  if (typeof value !== 'number' || !Number.isFinite(value) || !Number.isInteger(value)) return null;
  return value;
}

export function sanitizeSendData(raw: unknown): Record<string, unknown> | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const data = { ...(raw as Record<string, unknown>) };
  delete data.response;
  return data;
}

export function parseStoredSendData(send: Send): Record<string, unknown> {
  try {
    const parsed = JSON.parse(send.data) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ...(parsed as Record<string, unknown>) };
    }
    return {};
  } catch {
    return {};
  }
}

function normalizeSendDataSizeField(data: Record<string, unknown>): Record<string, unknown> {
  const normalized = { ...data };
  if (typeof normalized.size === 'number' && Number.isFinite(normalized.size)) {
    normalized.size = String(Math.trunc(normalized.size));
  }
  return normalized;
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

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
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

  send.passwordSalt = base64UrlEncode(salt);
  send.passwordHash = base64UrlEncode(hash);
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
  return constantTimeEqual(actual, expected);
}

export function verifySendPasswordHashB64(send: Send, passwordHashB64: string): boolean {
  if (!send.passwordHash || !passwordHashB64) return false;
  const expected = base64UrlDecode(send.passwordHash);
  const provided = base64UrlDecode(passwordHashB64);
  if (!expected || !provided) return false;
  return constantTimeEqual(expected, provided);
}

export function validateDeletionDate(date: Date): Response | null {
  const maxMs = Date.now() + LIMITS.send.maxDeletionDays * 24 * 60 * 60 * 1000;
  if (date.getTime() > maxMs) {
    return errorResponse(
      'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.',
      400
    );
  }
  return null;
}

export function parseMaxAccessCount(value: unknown): { ok: true; value: number | null } | { ok: false; response: Response } {
  const parsed = parseInteger(value);
  if (value === undefined || value === null || value === '') {
    return { ok: true, value: null };
  }
  if (parsed === null || parsed < 0) {
    return { ok: false, response: errorResponse('Invalid maxAccessCount', 400) };
  }
  return { ok: true, value: parsed };
}

export function parseFileLength(value: unknown): { ok: true; value: number } | { ok: false; response: Response } {
  const parsed = parseInteger(value);
  if (parsed === null) {
    return { ok: false, response: errorResponse('Invalid send length', 400) };
  }
  if (parsed < 0) {
    return { ok: false, response: errorResponse("Send size can't be negative", 400) };
  }
  return { ok: true, value: parsed };
}

export function parseSendType(value: unknown): SendType | null {
  const type = parseInteger(value);
  if (type === SendType.Text || type === SendType.File) return type;
  return null;
}

export function parseSendAuthType(value: unknown): SendAuthType | null {
  if (value === undefined || value === null || value === '') return null;
  const parsed = parseInteger(value);
  if (parsed === SendAuthType.Email || parsed === SendAuthType.Password || parsed === SendAuthType.None) {
    return parsed;
  }
  return null;
}

export function normalizeEmails(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const strings = value.filter((v) => typeof v === 'string').map((v) => String(v));
    if (strings.length === 0) return null;
    return strings.join(',');
  }
  return null;
}

export function hasEmailAuth(send: Send): boolean {
  return send.authType === SendAuthType.Email;
}

export function getSafeJwtSecret(env: Env): { ok: true; secret: string } | { ok: false; response: Response } {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength) {
    return { ok: false, response: errorResponse('Server configuration error', 500) };
  }
  return { ok: true, secret };
}

export function extractBearerToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

export function sendToResponse(send: Send): SendResponse {
  const data = normalizeSendDataSizeField(parseStoredSendData(send));
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
  const data = normalizeSendDataSizeField(parseStoredSendData(send));
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

export async function getCreatorIdentifier(storage: StorageService, send: Send): Promise<string | null> {
  if (send.hideEmail) return null;
  const owner = await storage.getUserById(send.userId);
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

export async function validatePublicSendAccess(send: Send, body: unknown): Promise<PublicSendAccessValidationResult> {
  if (hasEmailAuth(send)) {
    return {
      ok: false,
      response: errorResponse('Send email verification is not supported by this server.', 501),
      reason: 'email_auth_unsupported',
    };
  }

  if (!send.passwordHash) return { ok: true };

  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  const passwordHashB64Raw = getAliasedProp(body, [
    'password_hash_b64',
    'passwordHashB64',
    'passwordHash',
    'password_hash',
  ]);

  let validPassword = false;
  if (send.passwordSalt && send.passwordIterations) {
    if (typeof passwordRaw.value !== 'string') {
      return { ok: false, response: errorResponse('Password not provided', 401), reason: 'password_missing' };
    }
    validPassword = await verifySendPassword(send, passwordRaw.value);
  } else {
    const candidate =
      typeof passwordHashB64Raw.value === 'string'
        ? passwordHashB64Raw.value
        : typeof passwordRaw.value === 'string'
          ? passwordRaw.value
          : '';
    if (!candidate) return { ok: false, response: errorResponse('Password not provided', 401), reason: 'password_missing' };
    validPassword = verifySendPasswordHashB64(send, candidate);
  }
  if (!validPassword) {
    return { ok: false, response: errorResponse('Invalid password', 400), reason: 'invalid_password' };
  }

  return { ok: true };
}
