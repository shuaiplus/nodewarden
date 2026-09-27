import { decodeBase64Url } from 'hono/utils/encode';
import { z } from 'zod';
import type {
  AuthenticationExtensionsClientOutputs,
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
import { signHs256Jwt, verifyHs256Jwt } from './jwt';
import { bytesToBase64Url } from './passkey';
import { getConfiguredWebAuthnAllowedOrigins } from './origins';

// v1 tokens carried a millisecond exp that a seconds-based check reads as far future, so they are refused.
const ACCOUNT_PASSKEY_TOKEN_TYPE = 'nodewarden.account-passkey.challenge.v2';
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

// Official clients send WebAuthn buffers as base64 or base64url, padded or not; @simplewebauthn reads
// unpadded base64url.
const webAuthnBase64 = z
  .string()
  .min(1)
  .transform((value) => value.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''));
const optionalWebAuthnBase64 = webAuthnBase64.optional().catch(undefined);

const TRANSPORTS = [
  'ble',
  'cable',
  'hybrid',
  'internal',
  'nfc',
  'smart-card',
  'usb',
] as const satisfies readonly AuthenticatorTransportFuture[];
// Transport hints outside the WebAuthn set are dropped instead of failing the credential.
const TransportsSchema = z
  .array(z.enum(TRANSPORTS).optional().catch(undefined))
  .transform((transports) => transports.filter((transport) => transport !== undefined))
  .catch([]);

const extensionResults = z
  .custom<AuthenticationExtensionsClientOutputs>((value) => typeof value === 'object' && value !== null)
  .optional()
  .catch(undefined);
const credentialFields = {
  id: webAuthnBase64,
  rawId: webAuthnBase64,
  authenticatorAttachment: z.enum(['platform', 'cross-platform']).optional().catch(undefined),
  clientExtensionResults: extensionResults,
  extensions: extensionResults,
};
const clientDataFields = { clientDataJSON: optionalWebAuthnBase64, clientDataJson: optionalWebAuthnBase64 };

// The official web vault spells the client data clientDataJson; one of the spellings must carry it.
function withClientData<T extends { clientDataJSON?: string; clientDataJson?: string }>(
  { clientDataJSON, clientDataJson, ...response }: T,
  context: z.RefinementCtx,
) {
  const clientData = clientDataJSON || clientDataJson;
  if (!clientData) context.addIssue({ code: 'custom', message: 'clientDataJSON is required' });
  return { ...response, clientDataJSON: clientData ?? '' };
}

function asPublicKeyCredential<
  T extends {
    clientExtensionResults?: AuthenticationExtensionsClientOutputs;
    extensions?: AuthenticationExtensionsClientOutputs;
  },
>({ clientExtensionResults, extensions, ...credential }: T) {
  return {
    ...credential,
    type: 'public-key' as const,
    clientExtensionResults: clientExtensionResults ?? extensions ?? {},
  };
}

const RegistrationResponseSchema = z
  .object({
    ...credentialFields,
    response: z
      .object({
        ...clientDataFields,
        attestationObject: webAuthnBase64,
        authenticatorData: optionalWebAuthnBase64,
        transports: TransportsSchema.optional(),
        publicKey: optionalWebAuthnBase64,
        publicKeyAlgorithm: z.number().optional().catch(undefined),
      })
      .transform(withClientData),
  })
  .transform(asPublicKeyCredential);

const AuthenticationResponseSchema = z
  .object({
    ...credentialFields,
    response: z
      .object({
        ...clientDataFields,
        authenticatorData: webAuthnBase64,
        signature: webAuthnBase64,
        userHandle: optionalWebAuthnBase64,
      })
      .transform(withClientData),
  })
  .transform(asPublicKeyCredential);

export async function sha256Base64Url(value: string): Promise<string> {
  return bytesToBase64Url(await crypto.subtle.digest('SHA-256', textBytes(value)));
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
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt(
    {
      typ: ACCOUNT_PASSKEY_TOKEN_TYPE,
      scope: input.scope,
      challenge: input.challenge,
      userId: input.userId ?? null,
      rpId: input.rpId,
      iat: now,
      exp: now + accountPasskeyTokenTtlMs(input.scope) / 1000,
    } satisfies AccountPasskeyTokenPayload,
    env.JWT_SECRET,
  );
}

export async function verifyAccountPasskeyToken(
  env: Env,
  token: string,
  scope: AccountPasskeyChallengeScope,
): Promise<AccountPasskeyTokenPayload | null> {
  const payload = await verifyHs256Jwt<AccountPasskeyTokenPayload>(token, env.JWT_SECRET);
  return payload?.typ === ACCOUNT_PASSKEY_TOKEN_TYPE && payload.scope === scope && payload.challenge && payload.rpId
    ? payload
    : null;
}

export function getAccountPasskeyRpConfig(
  request: Request,
  env: Env,
): { rpId: string; rpName: string; origins: string[] } {
  const url = new URL(request.url);
  const configuredOrigins = getConfiguredWebAuthnAllowedOrigins(env);
  const origins = new Set<string>([url.origin, ...configuredOrigins]);
  return { rpId: url.hostname, rpName: DEFAULT_RP_NAME, origins: Array.from(origins) };
}

// A UUID user id becomes the bytes of .NET Guid.ToByteArray() (first three groups little-endian), as
// upstream encodes user handles; any other id is sent as its UTF-8 text.
export function userIdToWebAuthnUserId(userId: string): Uint8Array {
  const match = String(userId || '')
    .trim()
    .match(/^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$/i);
  if (!match) return textBytes(userId);
  // .NET Guid bytes: the first three groups little-endian.
  const [first, second, third, fourth, fifth] = match.slice(1).map((group) => Uint8Array.fromHex(group));
  return Uint8Array.from([...first.reverse(), ...second.reverse(), ...third.reverse(), ...fourth, ...fifth]);
}

export function userHandleToUserId(userHandle: string | undefined): string | null {
  if (!userHandle) return null;
  try {
    const bytes = decodeBase64Url(userHandle);
    // Sixteen bytes are a .NET Guid (first three groups little-endian); anything else is the id as text.
    if (bytes.length === 16) {
      return [
        bytes.slice(0, 4).reverse(),
        bytes.slice(4, 6).reverse(),
        bytes.slice(6, 8).reverse(),
        bytes.slice(8, 10),
        bytes.slice(10),
      ]
        .map((group) => group.toHex())
        .join('-');
    }
    const decoded = new TextDecoder().decode(bytes);
    return decoded.trim() || null;
  } catch {
    return null;
  }
}

export function accountPasskeyPrfStatus(
  credential: Pick<
    AccountPasskeyCredential,
    'supportsPrf' | 'encryptedUserKey' | 'encryptedPublicKey' | 'encryptedPrivateKey'
  >,
): AccountPasskeyPrfStatus {
  if (!credential.supportsPrf) return 2;
  if (credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey) return 0;
  return 1;
}

export function buildWebAuthnPrfOption(credential: AccountPasskeyCredential): WebAuthnPrfDecryptionOption | null {
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

export function passkeyDescriptor(credential: AccountPasskeyCredential): {
  id: string;
  transports?: AuthenticatorTransportFuture[];
} {
  return {
    id: credential.credentialId,
    transports: credential.transports ? TransportsSchema.parse(credential.transports) : undefined,
  };
}

export function toSimpleWebAuthnCredential(credential: AccountPasskeyCredential): WebAuthnCredential {
  return {
    ...passkeyDescriptor(credential),
    publicKey: decodeBase64Url(credential.publicKey),
    counter: credential.counter,
  };
}

export function normalizeRegistrationResponse(raw: unknown): RegistrationResponseJSON | null {
  return RegistrationResponseSchema.safeParse(raw).data ?? null;
}

export function normalizeAuthenticationResponse(raw: unknown): AuthenticationResponseJSON | null {
  return AuthenticationResponseSchema.safeParse(raw).data ?? null;
}

export function normalizeAccountPasskeyName(value: unknown): string {
  const normalized = String(value || '').trim();
  return (normalized || 'Account passkey').slice(0, 128);
}

export function normalizeTransports(value: unknown): string[] | null {
  const transports = TransportsSchema.parse(value).slice(0, 12);
  return transports.length ? transports : null;
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
