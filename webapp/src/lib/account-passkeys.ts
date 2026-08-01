import { base64ToBytes, bytesToBase64, decryptBw, encryptBw, hkdfExpand, toBufferSource } from './crypto';
import { t } from './i18n';
import type { AccountPasskeyPrfOption } from './types';

const LOGIN_WITH_PRF_SALT = 'passwordless-login';

export interface AccountPasskeyAssertion {
  token: string;
  deviceResponse: Record<string, unknown>;
  prfKey?: Uint8Array;
}

export interface PendingAccountPasskeyCredential {
  token: string;
  createOptions: PublicKeyCredentialCreationOptions;
  deviceResponse: PublicKeyCredential;
  request: Record<string, unknown>;
  supportsPrf: boolean;
  prfKey?: Uint8Array;
}

export interface AccountPasskeyPrfKeySet {
  encryptedUserKey: string;
  encryptedPublicKey: string;
  encryptedPrivateKey: string;
}

export class AccountPasskeyPrfUnavailableError extends Error {
  constructor() {
    super(t('txt_account_passkey_direct_unlock_unavailable_error'));
    this.name = 'AccountPasskeyPrfUnavailableError';
  }
}

function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  return base64ToBytes(padded);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return toBufferSource(bytes);
}

function cloneCreationOptions(options: any): PublicKeyCredentialCreationOptions {
  if (!options || typeof options !== 'object') throw new Error(t('txt_invalid_passkey_creation_options'));
  return {
    ...options,
    challenge: toArrayBuffer(base64UrlToBytes(options.challenge)),
    user: {
      ...options.user,
      id: toArrayBuffer(base64UrlToBytes(options.user?.id)),
    },
    excludeCredentials: Array.isArray(options.excludeCredentials)
      ? options.excludeCredentials.map((credential: any) => ({
          ...credential,
          id: toArrayBuffer(base64UrlToBytes(credential.id)),
        }))
      : undefined,
  };
}

function cloneRequestOptions(options: any): PublicKeyCredentialRequestOptions {
  if (!options || typeof options !== 'object') throw new Error(t('txt_invalid_passkey_assertion_options'));
  return {
    ...options,
    challenge: toArrayBuffer(base64UrlToBytes(options.challenge)),
    allowCredentials: Array.isArray(options.allowCredentials)
      ? options.allowCredentials.map((credential: any) => ({
          ...credential,
          id: toArrayBuffer(base64UrlToBytes(credential.id)),
        }))
      : options.allowCredentials,
  };
}

async function getLoginWithPrfSalt(): Promise<Uint8Array> {
  const hash = await crypto.subtle.digest('SHA-256', toBufferSource(new TextEncoder().encode(LOGIN_WITH_PRF_SALT)));
  return new Uint8Array(hash);
}

type PrfEvalInput = { first: Uint8Array };

function buildPrfExtension(salt: Uint8Array): Record<string, unknown> {
  const evalInput: PrfEvalInput = { first: salt };
  return {
    prf: {
      eval: evalInput,
    },
  };
}

function withPrfExtension(
  options: PublicKeyCredentialCreationOptions,
  salt: Uint8Array
): PublicKeyCredentialCreationOptions;
function withPrfExtension(
  options: PublicKeyCredentialRequestOptions,
  salt: Uint8Array
): PublicKeyCredentialRequestOptions;
function withPrfExtension(
  options: PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions,
  salt: Uint8Array
): PublicKeyCredentialCreationOptions | PublicKeyCredentialRequestOptions {
  return {
    ...options,
    extensions: {
      ...((options as any).extensions || {}),
      ...buildPrfExtension(salt),
    } as any,
  };
}

function withoutCreatePrfExtension(options: PublicKeyCredentialCreationOptions): PublicKeyCredentialCreationOptions {
  const extensions = { ...(((options as any).extensions || {}) as Record<string, unknown>) };
  delete extensions.prf;
  if (!Object.keys(extensions).length) {
    const { extensions: _extensions, ...rest } = options as any;
    return rest as PublicKeyCredentialCreationOptions;
  }
  return {
    ...options,
    extensions: extensions as any,
  };
}

function readPrfFirstResult(credential: PublicKeyCredential): ArrayBuffer | undefined {
  const result = (credential.getClientExtensionResults() as any).prf?.results?.first;
  return result instanceof ArrayBuffer ? result : undefined;
}

async function getPublicKeyCredentialWithPrf(
  options: PublicKeyCredentialRequestOptions,
  salt: Uint8Array
): Promise<PublicKeyCredential> {
  const credential = await navigator.credentials.get({
    publicKey: withPrfExtension(options, salt),
  });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error(t('txt_no_passkey_selected'));
  }
  return credential;
}

async function prfOutputToKey(prfOutput: ArrayBuffer): Promise<Uint8Array> {
  const prf = new Uint8Array(prfOutput);
  const enc = await hkdfExpand(prf, 'enc', 32);
  const mac = await hkdfExpand(prf, 'mac', 32);
  const out = new Uint8Array(64);
  out.set(enc, 0);
  out.set(mac, 32);
  return out;
}

function publicKeyCredentialBase(credential: PublicKeyCredential): Record<string, unknown> {
  return {
    id: credential.id,
    rawId: bytesToBase64Url(new Uint8Array(credential.rawId)),
    type: credential.type,
    extensions: {},
  };
}

function assertionRequest(credential: PublicKeyCredential): Record<string, unknown> {
  if (!(credential.response instanceof AuthenticatorAssertionResponse)) {
    throw new Error(t('txt_invalid_passkey_assertion_response'));
  }
  return {
    ...publicKeyCredentialBase(credential),
    response: {
      authenticatorData: bytesToBase64Url(new Uint8Array(credential.response.authenticatorData)),
      signature: bytesToBase64Url(new Uint8Array(credential.response.signature)),
      clientDataJSON: bytesToBase64Url(new Uint8Array(credential.response.clientDataJSON)),
      userHandle: credential.response.userHandle
        ? bytesToBase64Url(new Uint8Array(credential.response.userHandle))
        : undefined,
    },
  };
}

function attestationRequest(credential: PublicKeyCredential): Record<string, unknown> {
  if (!(credential.response instanceof AuthenticatorAttestationResponse)) {
    throw new Error(t('txt_invalid_passkey_registration_response'));
  }
  const transports = typeof credential.response.getTransports === 'function'
    ? credential.response.getTransports()
    : undefined;
  return {
    ...publicKeyCredentialBase(credential),
    response: {
      attestationObject: bytesToBase64Url(new Uint8Array(credential.response.attestationObject)),
      clientDataJson: bytesToBase64Url(new Uint8Array(credential.response.clientDataJSON)),
      transports,
    },
  };
}

export async function assertAccountPasskey(
  response: { options: unknown; token: string }
): Promise<AccountPasskeyAssertion> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(t('txt_passkey_browser_not_supported'));
  }
  const nativeOptions = cloneRequestOptions(response.options);
  const credential = await getPublicKeyCredentialWithPrf(
    nativeOptions,
    await getLoginWithPrfSalt()
  );
  const prfResult = readPrfFirstResult(credential);
  return {
    token: response.token,
    deviceResponse: assertionRequest(credential),
    prfKey: prfResult ? await prfOutputToKey(prfResult) : undefined,
  };
}

export async function createAccountPasskeyCredential(
  response: { options: unknown; token: string },
  requestPrf: boolean = false
): Promise<PendingAccountPasskeyCredential> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(t('txt_passkey_browser_not_supported'));
  }
  const nativeOptions = cloneCreationOptions(response.options);
  const noPrfOptions = withoutCreatePrfExtension(nativeOptions);
  const createWithOptions = async (options: PublicKeyCredentialCreationOptions): Promise<PublicKeyCredential> => {
    const credential = await navigator.credentials.create({ publicKey: options });
    if (!(credential instanceof PublicKeyCredential)) {
      throw new Error(t('txt_no_passkey_created'));
    }
    return credential;
  };
  const prfSalt = requestPrf ? await getLoginWithPrfSalt() : null;
  const credential = await createWithOptions(
    prfSalt ? withPrfExtension(noPrfOptions, prfSalt) : noPrfOptions
  );
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error(t('txt_no_passkey_created'));
  }
  const prfResult = readPrfFirstResult(credential);
  const supportsPrf = !!prfResult || (credential.getClientExtensionResults() as any).prf?.enabled === true;
  return {
    token: response.token,
    createOptions: nativeOptions,
    deviceResponse: credential,
    request: attestationRequest(credential),
    supportsPrf,
    prfKey: prfResult ? await prfOutputToKey(prfResult) : undefined,
  };
}

export async function createTwoFactorPasskeyCredential(options: unknown): Promise<Record<string, unknown>> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(t('txt_passkey_browser_not_supported'));
  }
  const credential = await navigator.credentials.create({ publicKey: cloneCreationOptions(options) });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error(t('txt_no_passkey_created'));
  }
  return attestationRequest(credential);
}

export async function assertTwoFactorPasskey(options: unknown): Promise<string> {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error(t('txt_passkey_browser_not_supported'));
  }
  const credential = await navigator.credentials.get({ publicKey: cloneRequestOptions(options) });
  if (!(credential instanceof PublicKeyCredential)) {
    throw new Error(t('txt_invalid_passkey_assertion_response'));
  }
  return JSON.stringify(assertionRequest(credential));
}

function parseRsaEncryptedUserKey(value: string): Uint8Array {
  const text = String(value || '').trim();
  const [type, payload] = text.split('.');
  if (type !== '4' || !payload) throw new Error(t('txt_unsupported_encrypted_user_key'));
  return base64ToBytes(payload);
}

export async function buildAccountPasskeyPrfKeySet(
  pending: PendingAccountPasskeyCredential,
  userKey: { symEncKey: string; symMacKey: string }
): Promise<AccountPasskeyPrfKeySet> {
  if (pending.prfKey) {
    return buildAccountPasskeyPrfKeySetFromPrfKey(pending.prfKey, userKey);
  }
  const rawId = new Uint8Array(pending.deviceResponse.rawId);
  const assertionOptions: PublicKeyCredentialRequestOptions = {
    challenge: pending.createOptions?.challenge!,
    rpId: pending.createOptions?.rp?.id,
    allowCredentials: [{ id: toArrayBuffer(rawId), type: 'public-key' }],
    timeout: pending.createOptions?.timeout,
    userVerification: pending.createOptions?.authenticatorSelection?.userVerification,
  };
  const assertion = await getPublicKeyCredentialWithPrf(
    assertionOptions,
    await getLoginWithPrfSalt()
  );
  const prfResult = readPrfFirstResult(assertion);
  if (!prfResult) {
    throw new AccountPasskeyPrfUnavailableError();
  }
  return buildAccountPasskeyPrfKeySetFromPrfKey(await prfOutputToKey(prfResult), userKey);
}

export async function buildAccountPasskeyPrfKeySetFromPrfKey(
  prfKey: Uint8Array,
  userKey: { symEncKey: string; symMacKey: string }
): Promise<AccountPasskeyPrfKeySet> {
  const userKeyBytes = new Uint8Array(64);
  userKeyBytes.set(base64ToBytes(userKey.symEncKey), 0);
  userKeyBytes.set(base64ToBytes(userKey.symMacKey), 32);

  const pair = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-1',
    },
    true,
    ['encrypt', 'decrypt']
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', pair.publicKey));
  const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const encryptedUserKeyBytes = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    pair.publicKey,
    toBufferSource(userKeyBytes)
  ));

  return {
    encryptedUserKey: `4.${bytesToBase64(encryptedUserKeyBytes)}`,
    encryptedPublicKey: await encryptBw(publicKey, userKeyBytes.slice(0, 32), userKeyBytes.slice(32, 64)),
    encryptedPrivateKey: await encryptBw(privateKey, prfKey.slice(0, 32), prfKey.slice(32, 64)),
  };
}

export async function unlockVaultKeyWithAccountPasskeyPrf(
  prfKey: Uint8Array,
  option: AccountPasskeyPrfOption
): Promise<{ symEncKey: string; symMacKey: string }> {
  const encryptedPrivateKey = option.EncryptedPrivateKey || option.encryptedPrivateKey || '';
  const encryptedUserKey = option.EncryptedUserKey || option.encryptedUserKey || '';
  if (!encryptedPrivateKey || !encryptedUserKey) {
    throw new Error(t('txt_passkey_cannot_unlock_vault'));
  }
  const privateKeyBytes = await decryptBw(encryptedPrivateKey, prfKey.slice(0, 32), prfKey.slice(32, 64));
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    toBufferSource(privateKeyBytes),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['decrypt']
  );
  const userKeyBytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    toBufferSource(parseRsaEncryptedUserKey(encryptedUserKey))
  ));
  if (userKeyBytes.length < 64) throw new Error(t('txt_invalid_passkey_vault_key'));
  return {
    symEncKey: bytesToBase64(userKeyBytes.slice(0, 32)),
    symMacKey: bytesToBase64(userKeyBytes.slice(32, 64)),
  };
}
