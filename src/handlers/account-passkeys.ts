import { EventType, recordUserEvent } from '../services/events';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AccountPasskeyChallengeScope, AccountPasskeyCredential, Env, User } from '../types';
import { AuthService } from '../services/auth';
import { z } from 'zod';
import { errorResponse, identityErrorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { bytesToBase64Url, parseClientDataJSON } from '../utils/passkey';
import {
  accountPasskeyCredentialToResponse,
  accountPasskeyPrfStatus,
  accountPasskeyTokenTtlMs,
  buildWebAuthnPrfOption,
  createAccountPasskeyToken,
  getAccountPasskeyRpConfig,
  isSerializedEncString,
  normalizeAccountPasskeyName,
  normalizeAuthenticationResponse,
  normalizeRegistrationResponse,
  normalizeTransports,
  passkeyDescriptor,
  sha256Base64Url,
  toSimpleWebAuthnCredential,
  userHandleToUserId,
  userIdToWebAuthnUserId,
  verifyAccountPasskeyToken,
} from '../utils/account-passkeys';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { ensureTwoFactorRecoveryCode } from '../services/two-factor-providers';
import { createTwoFactorUserVerificationToken, verifyTwoFactorUserVerificationToken } from '../utils/jwt';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

const MAX_ACCOUNT_PASSKEYS = 5;
const MAX_TWO_FACTOR_PASSKEYS = 5;

// Passkey routes share one loose body: the user-verification fields are typed here (non-strings read as
// absent), while each route parses its own WebAuthn and PRF fields.
const optionalSecret = z.string().trim().optional().catch(undefined);
const PasskeyRequestSchema = z.looseObject({
  masterPasswordHash: optionalSecret,
  master_password_hash: optionalSecret,
  secret: optionalSecret,
  password: optionalSecret,
  userVerificationToken: optionalSecret,
});
type PasskeyRequest = z.output<typeof PasskeyRequestSchema>;

async function readJsonBody(request: Request): Promise<PasskeyRequest | Response> {
  return parseBody(request, PasskeyRequestSchema, 'Invalid request payload');
}

async function verifyUserSecret(
  env: Env,
  user: User,
  body: PasskeyRequest
): Promise<boolean> {
  const secret = body.masterPasswordHash || body.master_password_hash || body.secret || body.password;
  if (!secret) return false;
  const storedHash = String(user.masterPasswordHash || '').trim();
  if (!storedHash) return false;
  const auth = new AuthService(env);
  return auth.verifyPassword(secret, storedHash, user.email);
}

async function verifyTwoFactorWebAuthnUser(env: Env, user: User, body: PasskeyRequest): Promise<boolean> {
  const token = body.userVerificationToken || '';
  return await verifyTwoFactorUserVerificationToken(env, user, 7, token) || await verifyUserSecret(env, user, body);
}

function logAccountPasskeyHandlerError(stage: string, error: unknown, details: Record<string, unknown> = {}): void {
  const err = error instanceof Error ? error : null;
  console.error('Account passkey handler failed', {
    stage,
    name: err?.name || typeof error,
    message: err?.message || String(error),
    stack: err?.stack,
    ...details,
  });
}

function passkeySetupStageMessage(stage: string): string {
  if (stage === 'verify_master_password') return 'verifying master password';
  if (stage === 'load_existing_credentials') return 'loading existing passkeys';
  if (stage === 'generate_options') return 'generating passkey options';
  if (stage === 'save_challenge') return 'saving passkey challenge';
  if (stage === 'create_token') return 'creating passkey challenge token';
  return 'preparing passkey setup';
}

function hasCompletePrfKeySet(body: PasskeyRequest): boolean {
  return !!(body.encryptedUserKey && body.encryptedPublicKey && body.encryptedPrivateKey);
}

function twoFactorWebAuthnResponse(credentials: AccountPasskeyCredential[], object = 'twoFactorWebAuthn'): Record<string, unknown> {
  const keys = credentials.map((credential, index) => ({
    Id: index + 1,
    id: index + 1,
    Name: credential.name,
    name: credential.name,
    Migrated: false,
    migrated: false,
  }));
  return {
    Enabled: credentials.length > 0,
    enabled: credentials.length > 0,
    Keys: keys,
    keys,
    WebAuthn: { Enabled: credentials.length > 0, Keys: keys },
    Object: object,
    object,
  };
}

// The client data carries the challenge the authenticator signed.
function readChallenge(response: { response: { clientDataJSON: string } }): string | null {
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  return String(clientData?.challenge || '').trim() || null;
}

const encryptedKey = z.string().trim().refine(isSerializedEncString);
const PrfKeySetSchema = z.object({ encryptedUserKey: encryptedKey, encryptedPublicKey: encryptedKey, encryptedPrivateKey: encryptedKey });
const NO_PRF_KEY_SET = { encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null };

// A partial key set stores nothing; a complete one must be three EncStrings.
function readPrfKeySet(body: PasskeyRequest) {
  return hasCompletePrfKeySet(body) ? PrfKeySetSchema.safeParse(body) : { success: true as const, data: NO_PRF_KEY_SET };
}

async function saveChallenge(
  db: D1Database,
  scope: AccountPasskeyChallengeScope,
  challenge: string,
  userId: string | null
): Promise<void> {
  const now = Date.now();
  await passkeyRepo.saveAccountPasskeyChallenge(db, {
    challengeHash: await sha256Base64Url(challenge),
    scope,
    userId,
    expiresAt: now + accountPasskeyTokenTtlMs(scope),
    usedAt: null,
    createdAt: now,
  });
}

export async function handleGetAccountPasskeyAssertionOptions(request: Request, env: Env): Promise<Response> {
  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: [],
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(env.DB, 'Authentication', options.challenge, null);
  const token = await createAccountPasskeyToken(env, {
    scope: 'Authentication',
    challenge: options.challenge,
    userId: null,
    rpId,
  });
  return jsonResponse({ options, token, object: 'webAuthnLoginAssertionOptions', Object: 'webAuthnLoginAssertionOptions' });
}

export async function assertAccountPasskeyCredential(
  request: Request,
  env: Env,
  db: D1Database,
  input: {
    token: string;
    deviceResponse: unknown;
    scope: 'Authentication' | 'UpdateKeySet';
    expectedUserId?: string | null;
  }
): Promise<{ user: User; credential: AccountPasskeyCredential }> {
  const payload = await verifyAccountPasskeyToken(env, input.token, input.scope);
  if (!payload) {
    throw new Error('Passkey challenge token is invalid or expired');
  }
  if (input.expectedUserId !== undefined && payload.userId !== input.expectedUserId) {
    throw new Error('Passkey challenge token does not match this user');
  }

  const response = normalizeAuthenticationResponse(input.deviceResponse);
  if (!response) {
    throw new Error('Invalid passkey assertion response');
  }

  const challengeHash = await sha256Base64Url(payload.challenge);
  const consumed = await passkeyRepo.consumeAccountPasskeyChallenge(db,
    challengeHash,
    input.scope,
    payload.userId,
    Date.now()
  );
  if (!consumed) {
    throw new Error('Passkey challenge has expired or was already used');
  }

  const credential = await passkeyRepo.getAccountPasskeyCredentialByCredentialId(db, response.rawId);
  if (!credential) {
    throw new Error('Passkey is not registered for this server');
  }
  if (payload.userId && credential.userId !== payload.userId) {
    throw new Error('Passkey does not belong to this user');
  }
  if (credential.purpose !== 'login') {
    throw new Error('Passkey is not registered for login');
  }

  const userHandleUserId = userHandleToUserId(response.response.userHandle);
  const resolvedUserId = payload.userId || userHandleUserId || credential.userId;
  if (!resolvedUserId || resolvedUserId !== credential.userId) {
    throw new Error('Passkey user handle does not match this credential');
  }

  const user = await userRepo.getUserById(db, resolvedUserId);
  if (!user || user.status !== 'active') {
    throw new Error('Passkey user is not available');
  }

  const { origins } = getAccountPasskeyRpConfig(request, env);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: payload.challenge,
    expectedOrigin: origins,
    expectedRPID: payload.rpId,
    credential: toSimpleWebAuthnCredential(credential),
    requireUserVerification: true,
    advancedFIDOConfig: { userVerification: 'required' },
  });
  if (!verification.verified || !verification.authenticationInfo.userVerified) {
    throw new Error('Passkey assertion could not be verified');
  }

  await passkeyRepo.updateAccountPasskeyCounter(db,
    credential.userId,
    credential.credentialId,
    verification.authenticationInfo.newCounter,
    new Date().toISOString()
  );
  credential.counter = verification.authenticationInfo.newCounter;
  return { user, credential };
}

export async function handleGetAccountPasskeyCredentials(request: Request, env: Env, userId: string): Promise<Response> {
  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId);
  return jsonResponse({
    data: credentials.map(accountPasskeyCredentialToResponse),
    Data: credentials.map(accountPasskeyCredentialToResponse),
    object: 'list',
    Object: 'list',
    continuationToken: null,
    ContinuationToken: null,
  });
}

export async function buildTwoFactorPasskeyAssertionOptions(
  request: Request,
  env: Env,
  db: D1Database,
  user: User
): Promise<Record<string, unknown> | null> {
  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(db, user.id, 'twoFactor');
  if (!credentials.length) return null;

  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map(passkeyDescriptor),
    userVerification: 'discouraged',
    timeout: 60000,
  });
  await saveChallenge(db, 'TwoFactorAuthentication', options.challenge, user.id);
  return options as unknown as Record<string, unknown>;
}

export async function assertTwoFactorPasskeyCredential(
  request: Request,
  env: Env,
  db: D1Database,
  user: User,
  deviceResponse: unknown
): Promise<AccountPasskeyCredential> {
  const response = normalizeAuthenticationResponse(deviceResponse);
  if (!response) {
    throw new Error('Invalid passkey assertion response');
  }

  const credential = await passkeyRepo.getAccountPasskeyCredentialByCredentialId(db, response.rawId);
  if (!credential || credential.userId !== user.id || credential.purpose !== 'twoFactor') {
    throw new Error('Passkey is not registered for two-step login');
  }

  const challenge = readChallenge(response);
  if (!challenge) {
    throw new Error('Passkey assertion challenge is missing');
  }
  const consumed = await passkeyRepo.consumeAccountPasskeyChallenge(db,
    await sha256Base64Url(challenge),
    'TwoFactorAuthentication',
    user.id,
    Date.now()
  );
  if (!consumed) {
    throw new Error('Passkey challenge has expired or was already used');
  }

  const { origins, rpId } = getAccountPasskeyRpConfig(request, env);
  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challenge,
    expectedOrigin: origins,
    expectedRPID: rpId,
    credential: toSimpleWebAuthnCredential(credential),
    requireUserVerification: false,
  });
  if (!verification.verified) {
    throw new Error('Passkey assertion could not be verified');
  }

  await passkeyRepo.updateAccountPasskeyCounter(db,
    credential.userId,
    credential.credentialId,
    verification.authenticationInfo.newCounter,
    new Date().toISOString()
  );
  credential.counter = verification.authenticationInfo.newCounter;
  return credential;
}

export async function handleGetTwoFactorWebAuthn(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor');
  return jsonResponse({
    ...twoFactorWebAuthnResponse(credentials),
    UserVerificationToken: await createTwoFactorUserVerificationToken(env, user, 7),
  });
}

export async function handleGetTwoFactorWebAuthnChallenge(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyTwoFactorWebAuthnUser(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor');
  if (credentials.length >= MAX_TWO_FACTOR_PASSKEYS) {
    return errorResponse('Maximum WebAuthn credential count reached.', 400);
  }

  const { rpId, rpName } = getAccountPasskeyRpConfig(request, env);
  const options = await generateRegistrationOptions({
    rpID: rpId,
    rpName,
    userID: Uint8Array.from(userIdToWebAuthnUserId(user.id)),
    userName: user.email,
    userDisplayName: user.name || user.email,
    attestationType: 'none',
    timeout: 60000,
    excludeCredentials: credentials.map(passkeyDescriptor),
    authenticatorSelection: {
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'discouraged',
    },
  });
  await saveChallenge(env.DB, 'TwoFactorCreate', options.challenge, userId);
  return jsonResponse({ ...options, Options: options, Object: 'twoFactorWebAuthnChallenge' });
}

export async function handlePutTwoFactorWebAuthn(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyTwoFactorWebAuthnUser(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const currentCount = await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor');
  if (currentCount >= MAX_TWO_FACTOR_PASSKEYS) {
    return errorResponse('Maximum WebAuthn credential count reached.', 400);
  }

  const registrationResponse = normalizeRegistrationResponse(body.deviceResponse);
  if (!registrationResponse) {
    return errorResponse('Invalid passkey registration response', 400);
  }
  const challenge = readChallenge(registrationResponse);
  if (!challenge) {
    return errorResponse('Passkey challenge is missing', 400);
  }
  const consumed = await passkeyRepo.consumeAccountPasskeyChallenge(env.DB,
    await sha256Base64Url(challenge),
    'TwoFactorCreate',
    userId,
    Date.now()
  );
  if (!consumed) {
    return errorResponse('Passkey challenge has expired or was already used', 400);
  }

  const { origins, rpId } = getAccountPasskeyRpConfig(request, env);
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: challenge,
      expectedOrigin: origins,
      expectedRPID: rpId,
      requireUserPresence: true,
      requireUserVerification: false,
    });
  } catch {
    return errorResponse('Passkey registration could not be verified', 400);
  }
  if (!verification.verified) {
    return errorResponse('Passkey registration could not be verified', 400);
  }

  const existing = await passkeyRepo.getAccountPasskeyCredentialByCredentialId(env.DB, verification.registrationInfo.credential.id);
  if (existing) {
    return errorResponse('Passkey is already registered', 409);
  }

  if (!await ensureTwoFactorRecoveryCode(env.DB, user.id, user.securityStamp)) return errorResponse('User verification failed.', 400);
  const now = new Date().toISOString();
  const transports = normalizeTransports(registrationResponse.response.transports);
  const saved = await passkeyRepo.saveAccountPasskeyCredential(env.DB, {
    id: generateUUID(),
    userId,
    purpose: 'twoFactor',
    name: normalizeAccountPasskeyName(body.name || `Passkey ${currentCount + 1}`),
    publicKey: bytesToBase64Url(verification.registrationInfo.credential.publicKey),
    credentialId: verification.registrationInfo.credential.id,
    counter: verification.registrationInfo.credential.counter,
    type: verification.registrationInfo.credentialType || 'public-key',
    aaGuid: verification.registrationInfo.aaguid || null,
    transports,
    encryptedUserKey: null,
    encryptedPublicKey: null,
    encryptedPrivateKey: null,
    supportsPrf: false,
    createdAt: now,
    updatedAt: now,
  }, user.securityStamp);
  if (!saved) return errorResponse('User verification failed.', 400);

  await sessionRepo.deleteRefreshTokensByUserId(env.DB, userId);
  AuthService.invalidateUserCache(userId);

  await recordUserEvent(env, request, user.id, EventType.UserUpdated2fa);
  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.enable',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: null,
    metadata: auditRequestMetadata(request),
  });

  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor');
  return jsonResponse(twoFactorWebAuthnResponse(credentials, 'twoFactorWebAuthnUpdate'));
}

export async function handleDeleteTwoFactorWebAuthn(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyTwoFactorWebAuthnUser(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const requestedId = Number(body.id);
  if (!Number.isInteger(requestedId) || requestedId <= 0) {
    return errorResponse('Invalid key id', 400);
  }

  const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor');
  if (credentials.length < 2) {
    return errorResponse('Unable to delete WebAuthn credential.', 400);
  }
  const credential = credentials[requestedId - 1];
  if (!credential) {
    return errorResponse('Unable to delete WebAuthn credential.', 400);
  }

  const deleted = await passkeyRepo.deleteAccountPasskeyCredential(env.DB, userId, credential.id, 'twoFactor');
  if (!deleted) return errorResponse('Unable to delete WebAuthn credential.', 400);
  await sessionRepo.deleteRefreshTokensByUserId(env.DB, userId);
  AuthService.invalidateUserCache(userId);

  await recordUserEvent(env, request, user.id, EventType.UserUpdated2fa);
  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.delete',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: credential.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse(twoFactorWebAuthnResponse(await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId, 'twoFactor'), 'twoFactorWebAuthnDelete'));
}

export async function handleGetAccountPasskeyAttestationOptions(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;

  let stage = 'verify_master_password';
  try {
    if (!(await verifyUserSecret(env, user, body))) {
      return errorResponse('Master password verification failed', 400);
    }

    stage = 'load_existing_credentials';
    const credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId);
    if (credentials.length >= MAX_ACCOUNT_PASSKEYS) {
      return errorResponse('Maximum passkey count reached', 400);
    }

    const { rpId, rpName } = getAccountPasskeyRpConfig(request, env);
    stage = 'generate_options';
    const options = await generateRegistrationOptions({
      rpID: rpId,
      rpName,
      userID: Uint8Array.from(userIdToWebAuthnUserId(user.id)),
      userName: user.email,
      userDisplayName: user.name || user.email,
      attestationType: 'none',
      timeout: 60000,
      excludeCredentials: credentials.map(passkeyDescriptor),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
    });
    stage = 'save_challenge';
    await saveChallenge(env.DB, 'CreateCredential', options.challenge, userId);
    stage = 'create_token';
    const token = await createAccountPasskeyToken(env, {
      scope: 'CreateCredential',
      challenge: options.challenge,
      userId,
      rpId,
    });
    return jsonResponse({ options: { ...options, extensions: { ...options.extensions, prf: {} } }, token, object: 'webauthnCredentialCreateOptions', Object: 'webauthnCredentialCreateOptions' });
  } catch (error) {
    logAccountPasskeyHandlerError(stage, error, { userId });
    return errorResponse(`Passkey setup failed while ${passkeySetupStageMessage(stage)}`, 500);
  }
}

export async function handleGetAccountPasskeyUpdateAssertionOptions(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('Master password verification failed', 400);
  }

  let credentials = await passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId);
  const requestedId = String(body.credentialId || body.id || '').trim();
  if (requestedId) {
    credentials = credentials.filter((credential) => credential.id === requestedId);
    if (!credentials.length) return errorResponse('Account passkey not found', 404);
  }
  if (!credentials.length) return errorResponse('No account passkeys registered', 404);

  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map(passkeyDescriptor),
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(env.DB, 'UpdateKeySet', options.challenge, userId);
  const token = await createAccountPasskeyToken(env, {
    scope: 'UpdateKeySet',
    challenge: options.challenge,
    userId,
    rpId,
  });
  return jsonResponse({ options, token, object: 'webAuthnLoginAssertionOptions', Object: 'webAuthnLoginAssertionOptions' });
}

export async function handleCreateAccountPasskeyCredential(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;

  const payload = await verifyAccountPasskeyToken(env, String(body.token || ''), 'CreateCredential');
  if (!payload || payload.userId !== userId) {
    return errorResponse('Passkey challenge token is invalid or expired', 400);
  }

  const challengeHash = await sha256Base64Url(payload.challenge);
  const consumed = await passkeyRepo.consumeAccountPasskeyChallenge(env.DB, challengeHash, 'CreateCredential', userId, Date.now());
  if (!consumed) {
    return errorResponse('Passkey challenge has expired or was already used', 400);
  }

  const currentCount = await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, userId);
  if (currentCount >= MAX_ACCOUNT_PASSKEYS) {
    return errorResponse('Maximum passkey count reached', 400);
  }

  const prfKeySet = readPrfKeySet(body);
  if (!prfKeySet.success) return errorResponse('Invalid encrypted passkey key set', 400);

  const registrationResponse = normalizeRegistrationResponse(body.deviceResponse);
  if (!registrationResponse) {
    return errorResponse('Invalid passkey registration response', 400);
  }

  const { origins } = getAccountPasskeyRpConfig(request, env);
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: registrationResponse,
      expectedChallenge: payload.challenge,
      expectedOrigin: origins,
      expectedRPID: payload.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
    });
  } catch {
    return errorResponse('Passkey registration could not be verified', 400);
  }
  if (!verification.verified) {
    return errorResponse('Passkey registration could not be verified', 400);
  }

  const existing = await passkeyRepo.getAccountPasskeyCredentialByCredentialId(env.DB, verification.registrationInfo.credential.id);
  if (existing) {
    return errorResponse('Passkey is already registered', 409);
  }

  const now = new Date().toISOString();
  const supportsPrf = !!body.supportsPrf || hasCompletePrfKeySet(body);
  const transports = normalizeTransports(registrationResponse.response.transports);
  const credential: AccountPasskeyCredential = {
    id: generateUUID(),
    userId,
    purpose: 'login',
    name: normalizeAccountPasskeyName(body.name),
    publicKey: bytesToBase64Url(verification.registrationInfo.credential.publicKey),
    credentialId: verification.registrationInfo.credential.id,
    counter: verification.registrationInfo.credential.counter,
    type: verification.registrationInfo.credentialType || 'public-key',
    aaGuid: verification.registrationInfo.aaguid || null,
    transports,
    ...prfKeySet.data,
    supportsPrf,
    createdAt: now,
    updatedAt: now,
  };

  await passkeyRepo.saveAccountPasskeyCredential(env.DB, credential);
  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.passkey.create',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: credential.id,
    metadata: {
      prfStatus: accountPasskeyPrfStatus(credential),
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(accountPasskeyCredentialToResponse(credential));
}

export async function handleUpdateAccountPasskeyEncryption(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;

  if (!hasCompletePrfKeySet(body)) return errorResponse('Encrypted passkey key set is required', 400);
  const prfKeySet = PrfKeySetSchema.safeParse(body);
  if (!prfKeySet.success) return errorResponse('Invalid encrypted passkey key set', 400);

  let assertion: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
  try {
    assertion = await assertAccountPasskeyCredential(request, env, env.DB, {
      token: String(body.token || ''),
      deviceResponse: body.deviceResponse,
      scope: 'UpdateKeySet',
      expectedUserId: userId,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Passkey assertion failed', 400);
  }

  const updated = await passkeyRepo.updateAccountPasskeyEncryption(env.DB,
    userId,
    assertion.credential.credentialId,
    prfKeySet.data.encryptedUserKey,
    prfKeySet.data.encryptedPublicKey,
    prfKeySet.data.encryptedPrivateKey
  );
  if (!updated) return errorResponse('Passkey not found', 404);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.passkey.encryption.enable',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: assertion.credential.id,
    metadata: auditRequestMetadata(request),
  });
  return jsonResponse({ success: true });
}

export async function handleDeleteAccountPasskeyCredential(request: Request, env: Env, userId: string, credentialId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (body instanceof Response) return body;
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('Master password verification failed', 400);
  }

  const deleted = await passkeyRepo.deleteAccountPasskeyCredential(env.DB, userId, credentialId);
  if (!deleted) return errorResponse('Passkey not found', 404);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.passkey.delete',
    category: 'security',
    level: 'info',
    targetType: 'accountPasskey',
    targetId: credentialId,
    metadata: auditRequestMetadata(request),
  });
  return jsonResponse({ success: true });
}

export function buildAccountPasskeyTokenUserDecryptionOption(credential: AccountPasskeyCredential) {
  return buildWebAuthnPrfOption(credential);
}
