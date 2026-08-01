import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import type { AccountPasskeyChallengeScope, AccountPasskeyCredential, Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { errorResponse, identityErrorResponse, jsonResponse } from '../utils/response';
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
  sha256Base64Url,
  toSimpleWebAuthnCredential,
  userHandleToUserId,
  userIdToWebAuthnUserId,
  verifyAccountPasskeyToken,
} from '../utils/account-passkeys';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import { createRecoveryCode } from '../utils/recovery-code';

const MAX_ACCOUNT_PASSKEYS = 5;
const MAX_TWO_FACTOR_PASSKEYS = 5;

function parseBodyObject(body: unknown): Record<string, any> {
  return body && typeof body === 'object' ? body as Record<string, any> : {};
}

async function readJsonBody(request: Request): Promise<Record<string, any> | null> {
  try {
    return parseBodyObject(await request.json());
  } catch {
    return null;
  }
}

async function verifyUserSecret(
  env: Env,
  user: User,
  body: Record<string, any>
): Promise<boolean> {
  const secret = String(body.masterPasswordHash || body.master_password_hash || body.secret || body.password || '').trim();
  if (!secret) return false;
  const storedHash = String(user.masterPasswordHash || '').trim();
  if (!storedHash) return false;
  const auth = new AuthService(env);
  return auth.verifyPassword(secret, storedHash, user.email);
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

function hasCompletePrfKeySet(body: Record<string, any>): boolean {
  return !!(body.encryptedUserKey && body.encryptedPublicKey && body.encryptedPrivateKey);
}

function twoFactorWebAuthnResponse(credentials: AccountPasskeyCredential[]): Record<string, unknown> {
  return {
    Enabled: credentials.length > 0,
    enabled: credentials.length > 0,
    Keys: credentials.map((credential, index) => ({
      Id: index + 1,
      id: index + 1,
      Name: credential.name,
      name: credential.name,
      Migrated: false,
      migrated: false,
    })),
    keys: credentials.map((credential, index) => ({
      Id: index + 1,
      id: index + 1,
      Name: credential.name,
      name: credential.name,
      Migrated: false,
      migrated: false,
    })),
    Object: 'twoFactorWebAuthn',
    object: 'twoFactorWebAuthn',
  };
}

function readRegistrationChallenge(response: ReturnType<typeof normalizeRegistrationResponse>): string | null {
  if (!response) return null;
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  return String(clientData?.challenge || '').trim() || null;
}

function readAuthenticationChallenge(response: ReturnType<typeof normalizeAuthenticationResponse>): string | null {
  if (!response) return null;
  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  return String(clientData?.challenge || '').trim() || null;
}

function readPrfKeySet(body: Record<string, any>): {
  encryptedUserKey: string | null;
  encryptedPublicKey: string | null;
  encryptedPrivateKey: string | null;
} {
  if (!hasCompletePrfKeySet(body)) {
    return { encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null };
  }
  const encryptedUserKey = String(body.encryptedUserKey).trim();
  const encryptedPublicKey = String(body.encryptedPublicKey).trim();
  const encryptedPrivateKey = String(body.encryptedPrivateKey).trim();
  if (!isSerializedEncString(encryptedUserKey) || !isSerializedEncString(encryptedPublicKey) || !isSerializedEncString(encryptedPrivateKey)) {
    throw new Error('Invalid encrypted key set');
  }
  return { encryptedUserKey, encryptedPublicKey, encryptedPrivateKey };
}

async function saveChallenge(
  storage: StorageService,
  scope: AccountPasskeyChallengeScope,
  challenge: string,
  userId: string | null
): Promise<void> {
  const now = Date.now();
  await storage.saveAccountPasskeyChallenge({
    challengeHash: await sha256Base64Url(challenge),
    scope,
    userId,
    expiresAt: now + accountPasskeyTokenTtlMs(scope),
    usedAt: null,
    createdAt: now,
  });
}

export async function handleGetAccountPasskeyAssertionOptions(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: [],
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(storage, 'Authentication', options.challenge, null);
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
  storage: StorageService,
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
  const consumed = await storage.consumeAccountPasskeyChallenge(
    challengeHash,
    input.scope,
    payload.userId,
    Date.now()
  );
  if (!consumed) {
    throw new Error('Passkey challenge has expired or was already used');
  }

  const credential = await storage.getAccountPasskeyCredentialByCredentialId(response.rawId);
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

  const user = await storage.getUserById(resolvedUserId);
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

  await storage.updateAccountPasskeyCounter(
    credential.userId,
    credential.credentialId,
    verification.authenticationInfo.newCounter,
    new Date().toISOString()
  );
  credential.counter = verification.authenticationInfo.newCounter;
  return { user, credential };
}

export async function handleGetAccountPasskeyCredentials(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId);
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
  storage: StorageService,
  user: User
): Promise<Record<string, unknown> | null> {
  const credentials = await storage.getAccountPasskeyCredentialsByUserId(user.id, 'twoFactor');
  if (!credentials.length) return null;

  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: (credential.transports || undefined) as any,
    })),
    userVerification: 'discouraged',
    timeout: 60000,
  });
  await saveChallenge(storage, 'TwoFactorAuthentication', options.challenge, user.id);
  return options as unknown as Record<string, unknown>;
}

export async function assertTwoFactorPasskeyCredential(
  request: Request,
  env: Env,
  storage: StorageService,
  user: User,
  deviceResponse: unknown
): Promise<AccountPasskeyCredential> {
  const response = normalizeAuthenticationResponse(deviceResponse);
  if (!response) {
    throw new Error('Invalid passkey assertion response');
  }

  const credential = await storage.getAccountPasskeyCredentialByCredentialId(response.rawId);
  if (!credential || credential.userId !== user.id || credential.purpose !== 'twoFactor') {
    throw new Error('Passkey is not registered for two-step login');
  }

  const challenge = readAuthenticationChallenge(response);
  if (!challenge) {
    throw new Error('Passkey assertion challenge is missing');
  }
  const consumed = await storage.consumeAccountPasskeyChallenge(
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

  await storage.updateAccountPasskeyCounter(
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
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const storage = new StorageService(env.DB);
  const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  return jsonResponse(twoFactorWebAuthnResponse(credentials));
}

export async function handleGetTwoFactorWebAuthnChallenge(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const storage = new StorageService(env.DB);
  const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
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
    excludeCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: (credential.transports || undefined) as any,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
      requireResidentKey: false,
      userVerification: 'discouraged',
    },
  });
  await saveChallenge(storage, 'TwoFactorCreate', options.challenge, userId);
  return jsonResponse(options);
}

export async function handlePutTwoFactorWebAuthn(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const storage = new StorageService(env.DB);
  const currentCount = await storage.countAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  if (currentCount >= MAX_TWO_FACTOR_PASSKEYS) {
    return errorResponse('Maximum WebAuthn credential count reached.', 400);
  }

  const registrationResponse = normalizeRegistrationResponse(body.deviceResponse);
  if (!registrationResponse) {
    return errorResponse('Invalid passkey registration response', 400);
  }
  const challenge = readRegistrationChallenge(registrationResponse);
  if (!challenge) {
    return errorResponse('Passkey challenge is missing', 400);
  }
  const consumed = await storage.consumeAccountPasskeyChallenge(
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

  const existing = await storage.getAccountPasskeyCredentialByCredentialId(verification.registrationInfo.credential.id);
  if (existing) {
    return errorResponse('Passkey is already registered', 409);
  }

  const now = new Date().toISOString();
  const transports = normalizeTransports(registrationResponse.response.transports);
  await storage.saveAccountPasskeyCredential({
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
  });

  if (!user.totpRecoveryCode) {
    user.totpRecoveryCode = createRecoveryCode();
    user.updatedAt = now;
    await storage.saveUser(user);
  }
  await storage.deleteRefreshTokensByUserId(userId);
  AuthService.invalidateUserCache(userId);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.enable',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: null,
    metadata: auditRequestMetadata(request),
  });

  const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  return jsonResponse(twoFactorWebAuthnResponse(credentials));
}

export async function handleDeleteTwoFactorWebAuthn(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('User verification failed.', 400);
  }

  const requestedId = Number(body.id ?? body.Id);
  if (!Number.isInteger(requestedId) || requestedId <= 0) {
    return errorResponse('Invalid key id', 400);
  }

  const storage = new StorageService(env.DB);
  const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor');
  if (credentials.length < 2) {
    return errorResponse('Unable to delete WebAuthn credential.', 400);
  }
  const credential = credentials[requestedId - 1];
  if (!credential) {
    return errorResponse('Unable to delete WebAuthn credential.', 400);
  }

  const deleted = await storage.deleteAccountPasskeyCredential(userId, credential.id, 'twoFactor');
  if (!deleted) return errorResponse('Unable to delete WebAuthn credential.', 400);
  await storage.deleteRefreshTokensByUserId(userId);
  AuthService.invalidateUserCache(userId);

  await safeWriteAuditEvent(env, {
    actorUserId: userId,
    action: 'account.webauthn_2fa.delete',
    category: 'security',
    level: 'security',
    targetType: 'accountPasskey',
    targetId: credential.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse(twoFactorWebAuthnResponse(await storage.getAccountPasskeyCredentialsByUserId(userId, 'twoFactor')));
}

export async function handleGetAccountPasskeyAttestationOptions(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);

  let stage = 'verify_master_password';
  try {
    if (!(await verifyUserSecret(env, user, body))) {
      return errorResponse('Master password verification failed', 400);
    }

    const storage = new StorageService(env.DB);
    stage = 'load_existing_credentials';
    const credentials = await storage.getAccountPasskeyCredentialsByUserId(userId);
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
      excludeCredentials: credentials.map((credential) => ({
        id: credential.credentialId,
        transports: (credential.transports || undefined) as any,
      })),
      authenticatorSelection: {
        residentKey: 'required',
        requireResidentKey: true,
        userVerification: 'required',
      },
    });
    (options as any).extensions = {
      ...((options as any).extensions || {}),
      prf: {},
    };
    stage = 'save_challenge';
    await saveChallenge(storage, 'CreateCredential', options.challenge, userId);
    stage = 'create_token';
    const token = await createAccountPasskeyToken(env, {
      scope: 'CreateCredential',
      challenge: options.challenge,
      userId,
      rpId,
    });
    return jsonResponse({ options, token, object: 'webauthnCredentialCreateOptions', Object: 'webauthnCredentialCreateOptions' });
  } catch (error) {
    logAccountPasskeyHandlerError(stage, error, { userId });
    return errorResponse(`Passkey setup failed while ${passkeySetupStageMessage(stage)}`, 500);
  }
}

export async function handleGetAccountPasskeyUpdateAssertionOptions(request: Request, env: Env, userId: string, user: User): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('Master password verification failed', 400);
  }

  const storage = new StorageService(env.DB);
  let credentials = await storage.getAccountPasskeyCredentialsByUserId(userId);
  const requestedId = String(body.credentialId || body.id || '').trim();
  if (requestedId) {
    credentials = credentials.filter((credential) => credential.id === requestedId);
    if (!credentials.length) return errorResponse('Account passkey not found', 404);
  }
  if (!credentials.length) return errorResponse('No account passkeys registered', 404);

  const { rpId } = getAccountPasskeyRpConfig(request, env);
  const options = await generateAuthenticationOptions({
    rpID: rpId,
    allowCredentials: credentials.map((credential) => ({
      id: credential.credentialId,
      transports: (credential.transports || undefined) as any,
    })),
    userVerification: 'required',
    timeout: 60000,
  });
  await saveChallenge(storage, 'UpdateKeySet', options.challenge, userId);
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
  if (!body) return errorResponse('Invalid request payload', 400);

  const storage = new StorageService(env.DB);
  const payload = await verifyAccountPasskeyToken(env, String(body.token || ''), 'CreateCredential');
  if (!payload || payload.userId !== userId) {
    return errorResponse('Passkey challenge token is invalid or expired', 400);
  }

  const challengeHash = await sha256Base64Url(payload.challenge);
  const consumed = await storage.consumeAccountPasskeyChallenge(challengeHash, 'CreateCredential', userId, Date.now());
  if (!consumed) {
    return errorResponse('Passkey challenge has expired or was already used', 400);
  }

  const currentCount = await storage.countAccountPasskeyCredentialsByUserId(userId);
  if (currentCount >= MAX_ACCOUNT_PASSKEYS) {
    return errorResponse('Maximum passkey count reached', 400);
  }

  let prfKeySet: ReturnType<typeof readPrfKeySet>;
  try {
    prfKeySet = readPrfKeySet(body);
  } catch {
    return errorResponse('Invalid encrypted passkey key set', 400);
  }

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

  const existing = await storage.getAccountPasskeyCredentialByCredentialId(verification.registrationInfo.credential.id);
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
    encryptedUserKey: prfKeySet.encryptedUserKey,
    encryptedPublicKey: prfKeySet.encryptedPublicKey,
    encryptedPrivateKey: prfKeySet.encryptedPrivateKey,
    supportsPrf,
    createdAt: now,
    updatedAt: now,
  };

  await storage.saveAccountPasskeyCredential(credential);
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
  if (!body) return errorResponse('Invalid request payload', 400);

  let prfKeySet: ReturnType<typeof readPrfKeySet>;
  try {
    prfKeySet = readPrfKeySet(body);
  } catch {
    return errorResponse('Invalid encrypted passkey key set', 400);
  }
  if (!prfKeySet.encryptedUserKey || !prfKeySet.encryptedPublicKey || !prfKeySet.encryptedPrivateKey) {
    return errorResponse('Encrypted passkey key set is required', 400);
  }

  const storage = new StorageService(env.DB);
  let assertion: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
  try {
    assertion = await assertAccountPasskeyCredential(request, env, storage, {
      token: String(body.token || ''),
      deviceResponse: body.deviceResponse,
      scope: 'UpdateKeySet',
      expectedUserId: userId,
    });
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : 'Passkey assertion failed', 400);
  }

  const updated = await storage.updateAccountPasskeyEncryption(
    userId,
    assertion.credential.credentialId,
    prfKeySet.encryptedUserKey,
    prfKeySet.encryptedPublicKey,
    prfKeySet.encryptedPrivateKey
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
  if (!body) return errorResponse('Invalid request payload', 400);
  if (!(await verifyUserSecret(env, user, body))) {
    return errorResponse('Master password verification failed', 400);
  }

  const storage = new StorageService(env.DB);
  const deleted = await storage.deleteAccountPasskeyCredential(userId, credentialId);
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
