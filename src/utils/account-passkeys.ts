import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
  WebAuthnCredential,
} from '@simplewebauthn/server';
import type {
  AccountPasskeyChallengeScope,
  AccountPasskeyCredential,
  AccountPasskeyPrfStatus,
  Env,
  WebAuthnPrfDecryptionOption,
} from '../types';
import { base64UrlToBytes, bytesToBase64Url } from './passkey';
import { getConfiguredWebAuthnAllowedOrigins } from './origins';

const ACCOUNT_PASSKEY_TOKEN_TYPE = 'nodewarden.account-passkey.challenge.v1';
const ACCOUNT_PASSKEY_TOKEN_TTL_MS = 17 * 60 * 1000;
const ACCOUNT_PASSKEY_CREATE_TOKEN_TTL_MS = 7 * 60 * 1000;
const DEFAULT_RP_NAME = 'NodeWarden';

interface AccountPasskeyTokenPayload {
  typ: typeof ACCOUNT_PASSKEY_TOKEN_TYPE;
  scope: AccountPasskeyChallengeScope;
  challenge: string;
  userId: string | null;
  rpId: string;
  iat: number;
  exp: number;
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function hexByte(value: number): string {
  return value.toString(16).padStart(2, '0');
}

function dotNetGuidBytesToUuid(bytes: Uint8Array): string | null {
  if (bytes.length !== 16) return null;
  return [
    [bytes[3], bytes[2], bytes[1], bytes[0]].map(hexByte).join(''),
    [bytes[5], bytes[4]].map(hexByte).join(''),
    [bytes[7], bytes[6]].map(hexByte).join(''),
    [bytes[8], bytes[9]].map(hexByte).join(''),
    Array.from(bytes.slice(10, 16)).map(hexByte).join(''),
  ].join('-');
}

function uuidToDotNetGuidBytes(value: string): Uint8Array | null {
  const match = String(value || '').trim().match(
    /^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i
  );
  if (!match) return null;
  const hex = match.slice(1).join('');
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return new Uint8Array([
    bytes[3], bytes[2], bytes[1], bytes[0],
    bytes[5], bytes[4],
    bytes[7], bytes[6],
    bytes[8], bytes[9],
    bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
  ]);
}

function normalizeWebAuthnBase64(value: unknown): string {
  return String(value || '').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', textBytes(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function hmacSha256(secret: string, data: string): Promise<Uint8Array> {
  const key = await importHmacKey(secret);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, textBytes(data)));
}

function encodeJson(value: unknown): string {
  return bytesToBase64Url(textBytes(JSON.stringify(value)));
}

function decodeJson<T>(value: string): T | null {
  try {
    return JSON.parse(new TextDecoder().decode(base64UrlToBytes(value))) as T;
  } catch {
    return null;
  }
}

export async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', textBytes(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

export function accountPasskeyTokenTtlMs(scope: AccountPasskeyChallengeScope): number {
  return scope === 'CreateCredential' || scope === 'TwoFactorCreate'
    ? ACCOUNT_PASSKEY_CREATE_TOKEN_TTL_MS
    : ACCOUNT_PASSKEY_TOKEN_TTL_MS;
}

export async function createAccountPasskeyToken(
  env: Env,
  input: {
    scope: AccountPasskeyChallengeScope;
    challenge: string;
    userId?: string | null;
    rpId: string;
    ttlMs?: number;
  }
): Promise<string> {
  const now = Date.now();
  const payload: AccountPasskeyTokenPayload = {
    typ: ACCOUNT_PASSKEY_TOKEN_TYPE,
    scope: input.scope,
    challenge: input.challenge,
    userId: input.userId ?? null,
    rpId: input.rpId,
    iat: now,
    exp: now + (input.ttlMs ?? accountPasskeyTokenTtlMs(input.scope)),
  };
  const header = { alg: 'HS256', typ: 'JWT' };
  const data = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = bytesToBase64Url(await hmacSha256(env.JWT_SECRET, data));
  return `${data}.${signature}`;
}

export async function verifyAccountPasskeyToken(
  env: Env,
  token: string,
  scope: AccountPasskeyChallengeScope
): Promise<AccountPasskeyTokenPayload | null> {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const data = `${parts[0]}.${parts[1]}`;
    const expected = await hmacSha256(env.JWT_SECRET, data);
    const actual = base64UrlToBytes(parts[2]);
    if (actual.length !== expected.length) return null;
    let diff = 0;
    for (let i = 0; i < actual.length; i += 1) diff |= actual[i] ^ expected[i];
    if (diff !== 0) return null;

    const payload = decodeJson<AccountPasskeyTokenPayload>(parts[1]);
    if (!payload || payload.typ !== ACCOUNT_PASSKEY_TOKEN_TYPE || payload.scope !== scope) return null;
    if (!payload.challenge || !payload.rpId || !Number.isFinite(payload.exp)) return null;
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

export function getAccountPasskeyRpConfig(request: Request, env: Env): { rpId: string; rpName: string; origins: string[] } {
  const url = new URL(request.url);
  const configuredRpId = String(env.WEBAUTHN_RP_ID || '').trim();
  const rpId = configuredRpId || url.hostname;
  const rpName = String(env.WEBAUTHN_RP_NAME || '').trim() || DEFAULT_RP_NAME;
  const configuredOrigins = getConfiguredWebAuthnAllowedOrigins(env);
  const origins = new Set<string>([url.origin, ...configuredOrigins]);
  return { rpId, rpName, origins: Array.from(origins) };
}

export function userIdToWebAuthnUserId(userId: string): Uint8Array {
  return uuidToDotNetGuidBytes(userId) || textBytes(userId);
}

export function userHandleToUserId(userHandle: string | undefined): string | null {
  if (!userHandle) return null;
  try {
    const bytes = base64UrlToBytes(userHandle);
    const officialGuid = dotNetGuidBytesToUuid(bytes);
    if (officialGuid) return officialGuid;
    const decoded = new TextDecoder().decode(bytes);
    return decoded.trim() || null;
  } catch {
    return null;
  }
}

export function accountPasskeyPrfStatus(credential: Pick<AccountPasskeyCredential, 'supportsPrf' | 'encryptedUserKey' | 'encryptedPublicKey' | 'encryptedPrivateKey'>): AccountPasskeyPrfStatus {
  if (!credential.supportsPrf) return 2;
  if (credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey) return 0;
  return 1;
}

export function buildWebAuthnPrfOption(
  credential: AccountPasskeyCredential
): WebAuthnPrfDecryptionOption | null {
  if (accountPasskeyPrfStatus(credential) !== 0) return null;
  return {
    EncryptedPrivateKey: credential.encryptedPrivateKey!,
    EncryptedUserKey: credential.encryptedUserKey!,
    CredentialId: credential.credentialId,
    Transports: credential.transports || [],
    Object: 'webAuthnPrfDecryptionOption',
  };
}

export function accountPasskeyCredentialToResponse(credential: AccountPasskeyCredential): Record<string, unknown> {
  const prfStatus = accountPasskeyPrfStatus(credential);
  return {
    Id: credential.id,
    id: credential.id,
    Name: credential.name,
    name: credential.name,
    PrfStatus: prfStatus,
    prfStatus,
    EncryptedPublicKey: credential.encryptedPublicKey,
    encryptedPublicKey: credential.encryptedPublicKey,
    EncryptedUserKey: credential.encryptedUserKey,
    encryptedUserKey: credential.encryptedUserKey,
    CreationDate: credential.createdAt,
    RevisionDate: credential.updatedAt,
    Object: 'webauthnCredential',
    object: 'webauthnCredential',
  };
}

export function toSimpleWebAuthnCredential(credential: AccountPasskeyCredential): WebAuthnCredential {
  return {
    id: credential.credentialId,
    publicKey: Uint8Array.from(base64UrlToBytes(credential.publicKey)),
    counter: credential.counter,
    transports: (credential.transports || undefined) as AuthenticatorTransportFuture[] | undefined,
  };
}

export function normalizeRegistrationResponse(raw: unknown): RegistrationResponseJSON | null {
  const input = raw && typeof raw === 'object' ? raw as Record<string, any> : null;
  const response = input?.response && typeof input.response === 'object' ? input.response as Record<string, any> : null;
  if (!input || !response) return null;
  const clientDataJSON = response.clientDataJSON || response.clientDataJson;
  if (!input.id || !input.rawId || !clientDataJSON || !response.attestationObject) return null;
  return {
    id: normalizeWebAuthnBase64(input.id),
    rawId: normalizeWebAuthnBase64(input.rawId),
    type: 'public-key',
    authenticatorAttachment: input.authenticatorAttachment,
    clientExtensionResults: input.clientExtensionResults || input.extensions || {},
    response: {
      attestationObject: normalizeWebAuthnBase64(response.attestationObject),
      clientDataJSON: normalizeWebAuthnBase64(clientDataJSON),
      authenticatorData: response.authenticatorData ? normalizeWebAuthnBase64(response.authenticatorData) : undefined,
      transports: Array.isArray(response.transports) ? response.transports.map(String) as AuthenticatorTransportFuture[] : undefined,
      publicKey: response.publicKey ? normalizeWebAuthnBase64(response.publicKey) : undefined,
      publicKeyAlgorithm: typeof response.publicKeyAlgorithm === 'number' ? response.publicKeyAlgorithm : undefined,
    },
  };
}

export function normalizeAuthenticationResponse(raw: unknown): AuthenticationResponseJSON | null {
  const input = raw && typeof raw === 'object' ? raw as Record<string, any> : null;
  const response = input?.response && typeof input.response === 'object' ? input.response as Record<string, any> : null;
  if (!input || !response) return null;
  const clientDataJSON = response.clientDataJSON || response.clientDataJson;
  if (!input.id || !input.rawId || !clientDataJSON || !response.authenticatorData || !response.signature) return null;
  return {
    id: normalizeWebAuthnBase64(input.id),
    rawId: normalizeWebAuthnBase64(input.rawId),
    type: 'public-key',
    authenticatorAttachment: input.authenticatorAttachment,
    clientExtensionResults: input.clientExtensionResults || input.extensions || {},
    response: {
      authenticatorData: normalizeWebAuthnBase64(response.authenticatorData),
      clientDataJSON: normalizeWebAuthnBase64(clientDataJSON),
      signature: normalizeWebAuthnBase64(response.signature),
      userHandle: response.userHandle ? normalizeWebAuthnBase64(response.userHandle) : undefined,
    },
  };
}

export function normalizeAccountPasskeyName(value: unknown): string {
  const normalized = String(value || '').trim();
  return (normalized || 'Account passkey').slice(0, 128);
}

export function normalizeTransports(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const transports = value.map((item) => String(item || '').trim()).filter(Boolean);
  return transports.length ? transports.slice(0, 12) : null;
}

export function isSerializedEncString(value: unknown): value is string {
  const text = String(value || '').trim();
  if (!text) return false;
  const parts = text.split('.');
  if (parts.length !== 2) return false;
  const type = Number(parts[0]);
  const bodyParts = parts[1].split('|');
  if (type === 2) return bodyParts.length === 3 && bodyParts.every(Boolean);
  if (type === 3 || type === 4) return bodyParts.length === 1 && !!bodyParts[0];
  if (type === 5 || type === 6) return bodyParts.length === 2 && bodyParts.every(Boolean);
  return false;
}
