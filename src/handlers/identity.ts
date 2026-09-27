import { EventType, recordUserEvent } from '../services/events';
import { eq } from 'drizzle-orm';
import { z } from 'zod';
import { readEnvConfig } from '../config/env';
import { getOrm } from '../db/client';
import { devices } from '../db/schema';
import { markEmailVerified } from '../services/vault-admin-role';
import { redeemEmailOtp } from '../services/email-otp';
import { consumeSsoContinuation, getSsoContinuation, saveSsoContinuation, ssoContinuationContext, type SsoContinuation } from '../services/sso-continuation';
import { readMailConfig } from '../services/mail';
import { notifyMail, notifyFailedTwoFactor, notifyNewDeviceVerification } from '../services/mail-notify';
import { Env, TokenResponse, User } from '../types';
import { AuthService } from '../services/auth';
import { twoFactorProviders, twoFactorClearStatements } from '../services/two-factor-providers';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { deviceErrorResponse, identityErrorResponse, jsonResponse, parseBody, readFormOrJson } from '../utils/response';
import { getRefreshTokenSlidingTtlMs, LIMITS } from '../config/limits';
import { parse, serialize } from 'hono/utils/cookie';
import { sha256 } from 'hono/utils/crypto';
import { findMatchingTotpCounter, isTotpEnabled } from '../utils/totp';
import { signHs256Jwt, createRefreshToken, createSsoEmail2faSessionToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo, deviceTypeName, type AuthRequestDeviceInfo } from '../utils/device';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { generateUUID, isUUID } from '../utils/uuid';
import { issueSendAccessToken } from './sends';
import { registerMobilePushDevice } from '../services/push-relay';
import {
  buildAccountKeys,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { auditRequestMetadata, safeWriteAuditEvent } from '../services/audit-events';
import {
  assertAccountPasskeyCredential,
  assertTwoFactorPasskeyCredential,
  buildAccountPasskeyTokenUserDecryptionOption,
  buildTwoFactorPasskeyAssertionOptions,
} from './account-passkeys';
import { isAuthRequestLoginApproved } from '../services/storage-auth-request-repo';
import { createPasskeyUserVerificationToken } from '../utils/user-verification-token';
import { verifyApiKey } from '../utils/api-key';
import { userYubiKeyPublicIds, verifyYubicoOtp, yubiKeyPublicIdFromOtp } from '../utils/yubico-otp';
import { getYubicoCredentials, initializeYubicoCredentialsOnce } from '../services/yubico-config';
import { exchangeOidcCode, isSsoEnabled, userRequiresSso } from './sso';
import { getAccessTokenWithAccount } from '../services/storage-secret-repo';
import * as orgRepo from '../services/storage-org-repo';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as authRequestRepo from '../services/storage-auth-request-repo';
import * as deviceRepo from '../services/storage-device-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as totpReplayRepo from '../services/storage-totp-replay-repo';
import * as userRepo from '../services/storage-user-repo';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_EMAIL = 1;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_REMEMBER = 5;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;
const TWO_FACTOR_PROVIDER_RECOVERY_CODE = 8;
const WEB_REFRESH_COOKIE = 'nodewarden_web_refresh';
// Some UI surfaces use -1 for the recovery-code settings dialog. Login itself follows
// the official Identity provider enum (RecoveryCode = 8), while request parsing remains
// compatible with older/local provider values.
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE = '-1';
const TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST = 100;

// Official clients post the token form url-encoded, so every field is text; a JSON number reads as
// its decimal text and a JSON null as absent.
const formText = z.coerce.string().trim().nullish();
const requiredText = (error: string) => z.string({ error }).min(1, { error });
const requiredTrimmedText = (error: string) => z.string({ error }).trim().min(1, { error });
const TokenFormSchema = z.looseObject({ client_id: formText, devicePushToken: formText, device_push_token: formText });
type TokenForm = z.output<typeof TokenFormSchema>;
const passwordFields = { authRequest: formText, twoFactorToken: formText, twoFactorProvider: formText, twoFactorRemember: formText, newDeviceOtp: formText };
const EMAIL_AND_PASSWORD_REQUIRED = 'Email and password are required';
const PASSKEY_REQUIRED = 'Passkey token and deviceResponse are required';
const CLIENT_REQUIRED = 'Parameter error';

// Each grant names the fields it cannot run without; their messages are the OAuth error descriptions
// clients have always received.
const TokenRequestSchema = z.discriminatedUnion('grant_type', [
  TokenFormSchema.extend({
    grant_type: z.literal('password'),
    username: requiredText(EMAIL_AND_PASSWORD_REQUIRED).toLowerCase(),
    password: requiredText(EMAIL_AND_PASSWORD_REQUIRED),
    ...passwordFields,
  }),
  TokenFormSchema.extend({ grant_type: z.literal('authorization_code'), code: requiredTrimmedText('code is required'), code_verifier: z.string().optional().catch(undefined), ...passwordFields }),
  TokenFormSchema.extend({ grant_type: z.literal('webauthn'), token: requiredTrimmedText(PASSKEY_REQUIRED), deviceResponse: z.unknown() }),
  TokenFormSchema.extend({ grant_type: z.literal('client_credentials'), client_id: requiredText(CLIENT_REQUIRED), client_secret: requiredText(CLIENT_REQUIRED), scope: z.string().catch('') }),
  TokenFormSchema.extend({
    grant_type: z.literal('send_access'),
    send_id: formText, sendId: formText, password: formText,
    password_hash_b64: formText, passwordHashB64: formText, passwordHash: formText, password_hash: formText,
  }),
  TokenFormSchema.extend({ grant_type: z.literal('refresh_token'), refresh_token: formText }),
], { error: (issue) => issue.code === 'invalid_union' ? 'Unsupported grant type' : 'Invalid request payload' });

// A grant_type outside the union answers unsupported_grant_type; every other issue is invalid_request.
function tokenRequestError({ issues: [issue] }: z.ZodError): Response {
  return identityErrorResponse(issue.message, issue.code === 'invalid_union' ? 'unsupported_grant_type' : 'invalid_request', 400);
}

function identityJsonResponse(data: unknown, status: number = 200): Response {
  return jsonResponse(data, status, { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
}

function resolveTotpSecret(userSecret: string | null): string | null {
  if (userSecret && isTotpEnabled(userSecret)) {
    return userSecret;
  }
  return null;
}

type DeviceSession = { identifier: string; sessionStamp: string; isNewDevice: boolean };

async function resolveDeviceSession(db: D1Database, userId: string, deviceInfo: AuthRequestDeviceInfo): Promise<DeviceSession | null> {
  if (!deviceInfo.deviceIdentifier) return null;
  const existingDevice = await deviceRepo.getDevice(db, userId, deviceInfo.deviceIdentifier);
  const sessionStamp = String(existingDevice?.sessionStamp || '').trim() || generateUUID();
  return { identifier: deviceInfo.deviceIdentifier, sessionStamp, isNewDevice: !existingDevice };
}

function resolveRefreshClientType(request: Request, body: TokenForm): string {
  if (shouldUseWebSession(request)) return 'web';
  const clientId = (body.client_id ?? '').toLowerCase();
  if (clientId === 'mobile') return 'mobile';
  if (clientId === 'browser' || clientId === 'desktop' || clientId === 'cli') return clientId;
  return clientId || 'other';
}

// Persists the device once every factor passed, then mails the new-device notice and registers
// any push token the client sent along.
async function persistLoginDevice(
  env: Env,
  request: Request,
  user: User,
  deviceInfo: AuthRequestDeviceInfo,
  body: TokenForm
): Promise<DeviceSession | null> {
  const candidate = await resolveDeviceSession(env.DB, user.id, deviceInfo);
  if (!candidate) return null;
  await deviceRepo.upsertDevice(env.DB,
    user.id,
    candidate.identifier,
    deviceInfo.deviceName,
    deviceInfo.deviceType,
    candidate.sessionStamp
  );
  const persisted = await deviceRepo.getDevice(env.DB, user.id, candidate.identifier);
  if (!persisted?.sessionStamp) throw new Error('Failed to persist device session');
  const deviceSession = { identifier: persisted.deviceIdentifier, sessionStamp: persisted.sessionStamp, isNewDevice: candidate.isNewDevice };
  if (deviceSession.isNewDevice) notifyNewDevice(env, request, user, deviceInfo.deviceType);
  await persistIdentityDevicePushToken(env, env.DB, user.id, deviceSession, deviceInfo.deviceType, body);
  return deviceSession;
}

function notifyNewDevice(env: Env, request: Request, user: User, type: number): void {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled' || !config.newDeviceNotices || Date.now() - Date.parse(user.createdAt) < LIMITS.mail.newDeviceMinAccountAgeSeconds * 1000) return;
  notifyMail(env, user.email, 'newDeviceLogin', { device: deviceTypeName(type), time: new Date().toISOString(), ip: getClientIdentifier(request) ?? 'Unknown' });
}

async function persistIdentityDevicePushToken(
  env: Env,
  db: D1Database,
  userId: string,
  deviceSession: { identifier: string; sessionStamp: string } | null,
  deviceType: number,
  body: TokenForm
): Promise<void> {
  if (!deviceSession) return;
  const pushToken = body.devicePushToken || body.device_push_token;
  if (!pushToken) return;

  const device = await deviceRepo.getDevice(db, userId, deviceSession.identifier);
  if (!device) return;

  const pushUuid = device.pushUuid || generateUUID();
  await deviceRepo.updateDevicePushToken(db, userId, deviceSession.identifier, pushUuid, pushToken);
  const registered = await registerMobilePushDevice(env, {
    userId,
    deviceIdentifier: deviceSession.identifier,
    type: device.type || deviceType,
    pushUuid,
    pushToken,
  });
  console.info('Mobile push token updated from identity token request', {
    userId,
    deviceIdentifier: deviceSession.identifier,
    deviceType: device.type || deviceType,
    pushUuid,
    pushTokenLength: pushToken.length,
    relayRegistered: registered,
  });
}

function shouldUseWebSession(request: Request): boolean {
  return String(request.headers.get('X-NodeWarden-Web-Session') || '').trim() === '1';
}

async function loginRateLimitKey(clientIdentifier: string, grantType: string, subject: string): Promise<string> {
  const subjectHash = await sha256(`${grantType}:${String(subject || '').trim() || 'unknown'}`);
  return `${clientIdentifier}:login:${grantType}:${subjectHash}`;
}

function withWebRefreshCookie(request: Request, response: Response, refreshToken: string | null): Response {
  const headers = new Headers(response.headers);
  headers.append('Set-Cookie', serialize(WEB_REFRESH_COOKIE, refreshToken ?? '', {
    path: '/identity/connect',
    httpOnly: true,
    sameSite: 'Strict',
    maxAge: refreshToken ? Math.floor(getRefreshTokenSlidingTtlMs('web') / 1000) : 0,
    secure: new URL(request.url).protocol === 'https:',
  }));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function buildPreloginResponse(
  email: string,
  kdfType: number,
  kdfIterations: number,
  kdfMemory: number | null,
  kdfParallelism: number | null
): Record<string, unknown> {
  return {
    kdf: kdfType,
    kdfIterations,
    kdfMemory,
    kdfParallelism,
    // Current official servers expose the consolidated KDF model alongside
    // the legacy flat fields. Keep both shapes while clients migrate.
    kdfSettings: {
      kdfType,
      iterations: kdfIterations,
      memory: kdfMemory,
      parallelism: kdfParallelism,
    },
    salt: null,
    // Preserve the historic NodeWarden aliases for older integrations.
    KdfSettings: {
      KdfType: kdfType,
      Iterations: kdfIterations,
      Memory: kdfMemory,
      Parallelism: kdfParallelism,
    },
    Salt: email.toLowerCase(),
  };
}

function masterPasswordPolicyResponse(): TokenResponse['MasterPasswordPolicy'] {
  return {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    Object: 'masterPasswordPolicy',
    object: 'masterPasswordPolicy',
  };
}

function redactEmail(email: string): string {
  const [local, domain] = email.split('@');
  const visible = local.length <= 2 ? 0 : local.length <= 4 ? 1 : 2;
  return `${local.slice(0, visible)}${'*'.repeat(local.length - visible)}@${domain}`;
}

async function twoFactorRequiredResponse(
  request: Request,
  env: Env,
  db: D1Database,
  user?: User,
  message: string = 'Two factor required.'
): Promise<Response> {
  // Match Bitwarden Identity: TwoFactorProviders2 lists enabled 2FA providers only.
  // Clients expose recovery-code entry points themselves; Android 2026.4 fails to
  // parse the challenge if an unknown recovery provider key such as "8" is included.
  const hasTwoFactorPasskey = user ? await passkeyRepo.countAccountPasskeyCredentialsByUserId(db, user.id, 'twoFactor') > 0 : false;
  const providers = user ? twoFactorProviders(user, hasTwoFactorPasskey).map(String) : [String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)];
  const webAuthnOptions = user && hasTwoFactorPasskey
    ? await buildTwoFactorPasskeyAssertionOptions(request, env, db, user) as Record<string, unknown> | null
    : null;
  const providers2: Record<string, Record<string, unknown> | null> = {};
  for (const provider of providers) {
    providers2[provider] = provider === String(TWO_FACTOR_PROVIDER_YUBIKEY)
      ? { Nfc: user?.yubikeyNfc ?? false }
      : provider === String(TWO_FACTOR_PROVIDER_EMAIL) && user?.twoFactorEmail
        ? { Email: redactEmail(user.twoFactorEmail) }
        : provider === String(TWO_FACTOR_PROVIDER_WEBAUTHN) && webAuthnOptions
          ? webAuthnOptions
          : null;
  }
  const customResponse = {
    TwoFactorProviders: providers,
    TwoFactorProviders2: providers2,
    SsoEmail2faSessionToken: user?.twoFactorEmail ? await createSsoEmail2faSessionToken(env, user) : null,
    ...(user?.twoFactorEmail ? { Email: user.email } : {}),
    MasterPasswordPolicy: masterPasswordPolicyResponse(),
  };

  // Bitwarden clients rely on these fields to trigger the 2FA UI flow.
  return identityJsonResponse(
    {
      error: 'invalid_grant',
      error_description: message,
      Error: 'invalid_grant',
      ErrorDescription: message,
      ErrorMessage: message,
      TwoFactorProviders: customResponse.TwoFactorProviders,
      TwoFactorProviders2: customResponse.TwoFactorProviders2,
      // Required by current Android parser (nullable value is acceptable).
      SsoEmail2faSessionToken: customResponse.SsoEmail2faSessionToken,
      ...(user?.twoFactorEmail ? { Email: user.email } : {}),
      MasterPasswordPolicy: customResponse.MasterPasswordPolicy,
      CustomResponse: customResponse,
      ErrorModel: {
        Message: message,
        Object: 'error',
      },
    },
    400
  );
}

async function recordFailedLoginAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string,
  message: string
): Promise<Response> {
  const result = await rateLimit.recordFailedLogin(loginIdentifier);
  if (result.locked) {
    return identityErrorResponse(
      `Too many failed login attempts. Account locked for ${Math.ceil(result.retryAfterSeconds! / 60)} minutes.`,
      'TooManyRequests',
      429
    );
  }
  return identityErrorResponse(message, 'invalid_grant', 400);
}

// Answers the lockout before any user lookup so a locked address leaks nothing about the account.
async function loginLockoutResponse(rateLimit: RateLimitService, loginIdentifier: string): Promise<Response | null> {
  const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
  if (loginCheck.allowed) return null;
  return identityErrorResponse(
    `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
    'TooManyRequests',
    429
  );
}

// A rejected login leaves the user event and the audit row; the caller applies the rate limit.
async function recordLoginFailure(
  env: Env,
  request: Request,
  user: User,
  grantType: string,
  deviceIdentifier: string | null,
  action: string
): Promise<void> {
  await recordUserEvent(env, request, user.id, EventType.UserFailedLogIn);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action,
    category: 'auth',
    level: 'warn',
    targetType: 'user',
    targetId: user.id,
    metadata: { grantType, deviceIdentifier, ...auditRequestMetadata(request) },
  });
}

interface TokenResponseExtras {
  // Password grant: the remember-device token minted for this login.
  twoFactorToken?: string;
  // Password grant approved through an auth request: the key the approving device wrapped.
  key?: string | null;
  // Passkey grant: proves user verification to the settings that require it.
  userVerificationToken?: string;
  prfOption?: Parameters<typeof buildUserDecryptionOptions>[1];
}

// Every grant answers with the same TokenResponse. The optional fields keep their positions so the
// JSON stays byte-for-byte what official clients parsed per grant before.
function tokenResponse(request: Request, user: User, accessToken: string, refreshToken: string, extras: TokenResponseExtras = {}): Response {
  const accountKeys = buildAccountKeys(user);
  const userDecryptionOptions = buildUserDecryptionOptions(user, extras.prfOption);
  const webSession = shouldUseWebSession(request);
  const response: TokenResponse = {
    access_token: accessToken,
    expires_in: LIMITS.auth.accessTokenTtlSeconds,
    token_type: 'Bearer',
    ...(webSession ? { web_session: true } : { refresh_token: refreshToken }),
    ...(extras.twoFactorToken ? { TwoFactorToken: extras.twoFactorToken } : {}),
    Key: extras.key || user.key,
    PrivateKey: user.privateKey,
    AccountKeys: accountKeys,
    accountKeys: accountKeys,
    Kdf: user.kdfType,
    KdfIterations: user.kdfIterations,
    KdfMemory: user.kdfMemory,
    KdfParallelism: user.kdfParallelism,
    ForcePasswordReset: false,
    ResetMasterPassword: false,
    MasterPasswordPolicy: masterPasswordPolicyResponse(),
    ApiUseKeyConnector: false,
    scope: 'api offline_access',
    unofficialServer: true,
    ...(extras.userVerificationToken === undefined
      ? {}
      : { UserVerificationToken: extras.userVerificationToken, userVerificationToken: extras.userVerificationToken }),
    UserDecryptionOptions: userDecryptionOptions,
    userDecryptionOptions: userDecryptionOptions,
  };
  const baseResponse = identityJsonResponse(response);
  return webSession ? withWebRefreshCookie(request, baseResponse, refreshToken) : baseResponse;
}

// Password, passkey and API-key logins mint the same session pair and leave the same trail.
async function completeLogin(
  request: Request,
  env: Env,
  login: { user: User; body: TokenForm; deviceInfo: AuthRequestDeviceInfo; deviceSession: DeviceSession | null; grantType: string },
  extras: TokenResponseExtras = {},
  audit = { action: 'auth.login.success', targetType: 'user', targetId: login.user.id }
): Promise<Response> {
  const { user, body, deviceInfo, deviceSession, grantType } = login;
  const auth = new AuthService(env);
  const accessToken = await auth.generateAccessToken(user, deviceSession);
  const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
  await recordUserEvent(env, request, user.id, EventType.UserLoggedIn);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: audit.action,
    category: 'auth',
    level: 'info',
    targetType: audit.targetType,
    targetId: audit.targetId,
    metadata: {
      grantType,
      webSession: shouldUseWebSession(request),
      deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
      deviceType: deviceInfo.deviceType,
      ...auditRequestMetadata(request),
    },
  });
  return tokenResponse(request, user, accessToken, refreshToken, extras);
}

// POST /identity/connect/token
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env);

  async function recordFailedTwoFactorAndBuildResponse(
    rateLimit: RateLimitService,
    loginIdentifier: string,
    user: User,
    providerType: number
  ): Promise<Response> {
    await recordUserEvent(env, request, user.id, EventType.UserFailedLogIn2fa);
    notifyFailedTwoFactor(env, request, user, providerType);
    const failed = await rateLimit.recordFailedLogin(loginIdentifier);
    if (failed.locked) {
      return identityErrorResponse(
        `Too many failed login attempts. Account locked for ${Math.ceil(failed.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }
    return identityErrorResponse('Two-step token is invalid. Try again.', 'invalid_grant', 400);
  }


  // An unreadable payload parses as null, which the schema answers as 'Invalid request payload'.
  const parsed = TokenRequestSchema.safeParse(await readFormOrJson(request).catch(() => null));
  if (!parsed.success) return tokenRequestError(parsed.error);
  let body = parsed.data;
  let viaSsoShim = false;
  let ssoContinuation: SsoContinuation | null = null;
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier && body.grant_type !== 'refresh_token') {
    await safeWriteAuditEvent(env, {
      action: 'auth.client_ip.missing',
      category: 'auth',
      level: 'error',
      targetType: 'tokenEndpoint',
      metadata: { grantType: body.grant_type, reason: 'client_ip_missing', ...auditRequestMetadata(request) },
    });
    return identityErrorResponse(
      'Authentication is temporarily unavailable',
      'temporarily_unavailable',
      503,
      { 'Retry-After': '5' }
    );
  }

  if (body.grant_type === 'authorization_code' && isSsoEnabled(env)) {
    const { code } = body;
    const context = await ssoContinuationContext(env, request, body, code);
    const continuation = await getSsoContinuation(env, context);
    if (continuation === null) return identityErrorResponse('SSO sign-in expired or was already completed', 'invalid_grant', 400);
    let user: User | null;
    if (continuation) {
      user = await userRepo.getUserById(env.DB, continuation.userId);
      if (!user || user.status !== 'active' || user.securityStamp !== continuation.securityStamp || user.email !== continuation.email) return identityErrorResponse('SSO sign-in is no longer valid', 'invalid_grant', 400);
      ssoContinuation = continuation;
    } else {
      const claims = await exchangeOidcCode(env, code, new URL(request.url).origin, body.code_verifier);
      if (!claims) return identityErrorResponse('SSO exchange failed', 'invalid_grant', 400);
      const linked = await orgRepo.getSsoUserByIdentifier(env.DB, claims.identifier);
      user = linked ? await userRepo.getUserById(env.DB, linked.userId) : null;
      // Adopting an existing local account by email address is only safe when the
      // provider vouches for the address; otherwise anyone who can claim that email
      // at the IdP inherits the local vault.
      if (!user && !claims.emailVerified) {
        return identityErrorResponse(
          'SSO linking requires an email address verified by your identity provider',
          'invalid_grant',
          400
        );
      }
      if (!user) user = await userRepo.getUser(env.DB, claims.email);
      if (!user) {
        if (!readEnvConfig(env).SSO_SIGNUPS) {
          return identityErrorResponse('SSO sign-up is disabled', 'invalid_grant', 400);
        }
        return identityErrorResponse('Create a local account first, then link SSO', 'invalid_grant', 400);
      }
      await orgRepo.saveSsoUser(env.DB, user.id, claims.identifier, new Date().toISOString());
      if (user.status !== 'active') return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
      ssoContinuation = await saveSsoContinuation(env, context, user);
      if (!ssoContinuation) return identityErrorResponse('SSO sign-in is already in progress', 'invalid_grant', 400);
    }
    // The verified SSO user continues as a password grant carrying the server-side hash.
    const shimmed = TokenRequestSchema.safeParse({ ...body, grant_type: 'password', username: user.email, password: user.masterPasswordHash });
    if (!shimmed.success) return tokenRequestError(shimmed.error);
    body = shimmed.data;
    viaSsoShim = true;
  }
  const grantType = body.grant_type;

  if (body.grant_type === 'password') {
    // Login with password
    const { username: email, password: passwordHash } = body;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, email);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const locked = await loginLockoutResponse(rateLimit, loginIdentifier);
    if (locked) return locked;

    const user = await userRepo.getUser(env.DB, email);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Username or password is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await recordLoginFailure(env, request, user, grantType, deviceInfo.deviceIdentifier, 'auth.login.failed.user_inactive');
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }
    if (ssoContinuation && (user.id !== ssoContinuation.userId || user.securityStamp !== ssoContinuation.securityStamp || user.email !== ssoContinuation.email)) return identityErrorResponse('SSO sign-in is no longer valid', 'invalid_grant', 400);
    if (await userRequiresSso(env, user.id)) {
      if (!viaSsoShim && isSsoEnabled(env)) {
        return identityErrorResponse('SSO sign-in is required', 'invalid_grant', 400);
      }
    }

    let validatedAuthRequestId: string | null = null;
    let authRequestLoginKey: string | null = null;
    let valid = false;
    const normalizedAuthRequestId = body.authRequest ?? '';
    if (normalizedAuthRequestId) {
      const authRequest = await authRequestRepo.getAuthRequestByIdForUser(env.DB, normalizedAuthRequestId, user.id);
      valid = isAuthRequestLoginApproved(authRequest, user.id, passwordHash);
      if (valid) {
        validatedAuthRequestId = authRequest!.id;
        authRequestLoginKey = authRequest!.key;
      }
    } else {
      valid = viaSsoShim || await auth.verifyPassword(passwordHash, user.masterPasswordHash, user.email);
    }
    if (!valid) {
      await recordLoginFailure(env, request, user, grantType, deviceInfo.deviceIdentifier,
        normalizedAuthRequestId ? 'auth.login.failed.bad_auth_request' : 'auth.login.failed.bad_password');
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    // Optional 2FA: enabled by any supported per-user provider.
    let trustedTwoFactorTokenToReturn: string | undefined;
    let recoveredTwoFactor = false;
    const effectiveTotpSecret = resolveTotpSecret(user.totpSecret);
    const effectiveYubiKeyPublicIds = userYubiKeyPublicIds(user);
    const hasTwoFactorPasskey = await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor') > 0;
    const enabledProviders = twoFactorProviders(user, hasTwoFactorPasskey);
    if (enabledProviders.length > 0) {
      const normalizedTwoFactorProvider = body.twoFactorProvider ?? '';
      const normalizedTwoFactorToken = body.twoFactorToken ?? '';
      let rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(body.twoFactorRemember ?? '');
      const hasProvider = normalizedTwoFactorProvider.length > 0;
      const hasToken = normalizedTwoFactorToken.length > 0;

      // Upstream-compatible behavior: if 2FA is required and either provider or token is missing,
      // respond with a 2FA challenge payload.
      if (!hasProvider || !hasToken) {
        return await twoFactorRequiredResponse(request, env, env.DB, user, 'Two factor required.');
      }

      let passedByRememberToken = false;
      if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_REMEMBER)) {
        if (deviceInfo.deviceIdentifier) {
          const trustedUserId = await deviceRepo.getTrustedTwoFactorDeviceTokenUserId(env.DB,
            normalizedTwoFactorToken,
            deviceInfo.deviceIdentifier
          );
          passedByRememberToken = trustedUserId === user.id;
        }

        // Remember token missing/invalid/expired should re-enter the 2FA challenge flow.
        if (!passedByRememberToken) {
          return await twoFactorRequiredResponse(request, env, env.DB, user, 'Two factor required.');
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)) {
        if (!effectiveTotpSecret) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        const matchedCounter = await findMatchingTotpCounter(effectiveTotpSecret, normalizedTwoFactorToken);
        if (matchedCounter == null) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        const consumed = await totpReplayRepo.consumeTotpLoginCounter(env.DB, user.id, matchedCounter);
        if (!consumed) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_EMAIL)) {
        if (!user.twoFactorEmail || !await redeemEmailOtp(env, { purpose: 'two-factor-login', subject: user.id, binding: user.securityStamp }, normalizedTwoFactorToken)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, TWO_FACTOR_PROVIDER_EMAIL);
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_YUBIKEY)) {
        const publicId = yubiKeyPublicIdFromOtp(normalizedTwoFactorToken);
        if (!publicId || !effectiveYubiKeyPublicIds.includes(publicId)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        let credentials = await getYubicoCredentials(env.DB);
        let initializedWithCurrentOtp = false;
        if (!credentials) {
          const initialized = await initializeYubicoCredentialsOnce(env.DB, user.email, normalizedTwoFactorToken);
          if (!initialized) {
            return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
          }
          credentials = initialized.credentials;
          initializedWithCurrentOtp = initialized.created;
        }
        if (!initializedWithCurrentOtp && !await verifyYubicoOtp(env, normalizedTwoFactorToken, credentials)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_WEBAUTHN)) {
        if (!hasTwoFactorPasskey) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        let deviceResponse: unknown;
        try {
          deviceResponse = JSON.parse(normalizedTwoFactorToken);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        try {
          await assertTwoFactorPasskeyCredential(request, env, env.DB, user, deviceResponse);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
      } else if (
        normalizedTwoFactorProvider === TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE) ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST)
      ) {
        if (!recoveryCodeEquals(normalizedTwoFactorToken, user.totpRecoveryCode)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
        }
        recoveredTwoFactor = true;
        rememberRequested = false;
      } else {
        // Unsupported provider for this server profile behaves as an invalid 2FA attempt.
        return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, Number(normalizedTwoFactorProvider));
      }

      // Upstream behavior: do not issue a new remember token when auth itself used remember provider.
      if (rememberRequested && !passedByRememberToken && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
      }
    }

    const mail = readMailConfig(env);
    if (mail.kind === 'enabled' && mail.newDeviceVerification && !viaSsoShim && !validatedAuthRequestId
      && enabledProviders.length === 0 && user.verifyDevices
      && Date.now() - Date.parse(user.createdAt) >= LIMITS.auth.newDeviceVerificationMinAccountAgeSeconds * 1000) {
      const otp = body.newDeviceOtp ?? '';
      if (otp) {
        if (!await redeemEmailOtp(env, { purpose: 'new-device', subject: user.id, binding: user.securityStamp }, otp)) return deviceErrorResponse('invalid_otp');
        await markEmailVerified(env, user.id);
      } else if ((await getOrm(env.DB).select({ userId: devices.userId }).from(devices).where(eq(devices.userId, user.id)).limit(1)).length
        && (!deviceInfo.deviceIdentifier || !await deviceRepo.isKnownDevice(env.DB, user.id, deviceInfo.deviceIdentifier))) {
        notifyNewDeviceVerification(env, request, user, deviceInfo.deviceType);
        return deviceErrorResponse('required');
      }
    }

    // Claim the verified SSO proof once, after every factor check and before creating credentials.
    const recovery = recoveredTwoFactor ? { recoveryCode: createRecoveryCode(), securityStamp: generateUUID() } : undefined;
    if (ssoContinuation) {
      if (!await consumeSsoContinuation(env, ssoContinuation, user, recovery)) return identityErrorResponse('SSO sign-in expired or was already completed', 'invalid_grant', 400);
    } else if (recovery) {
      const [cleared] = await getOrm(env.DB).batch(twoFactorClearStatements(env.DB, user.id, recovery, user));
      if (!cleared.meta.changes) return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier, user, TWO_FACTOR_PROVIDER_RECOVERY_CODE);
    }
    if (recovery) {
      user.securityStamp = recovery.securityStamp;
      AuthService.invalidateUserCache(user.id);
      await recordUserEvent(env, request, user.id, EventType.UserRecovered2fa);
      notifyMail(env, user.email, 'twoFactorRecovered', { time: new Date().toISOString(), ip: getClientIdentifier(request) ?? 'Unknown' });
    }
    if (trustedTwoFactorTokenToReturn && deviceInfo.deviceIdentifier) {
      await deviceRepo.saveTrustedTwoFactorDeviceToken(env.DB, trustedTwoFactorTokenToReturn, user.id, deviceInfo.deviceIdentifier, Date.now() + TWO_FACTOR_REMEMBER_TTL_MS);
    }

    // Persist device only after successful password + (optional) 2FA verification.
    const deviceSession = await persistLoginDevice(env, request, user, deviceInfo, body);

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);
    if (validatedAuthRequestId) {
      await authRequestRepo.markAuthRequestAuthenticated(env.DB, validatedAuthRequestId);
    }

    return completeLogin(request, env, { user, body, deviceInfo, deviceSession, grantType },
      { twoFactorToken: trustedTwoFactorTokenToReturn, key: authRequestLoginKey });

  } else if (body.grant_type === 'webauthn') {
    const { token } = body;
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, token);
    const locked = await loginLockoutResponse(rateLimit, loginIdentifier);
    if (locked) return locked;

    let deviceResponse: unknown = body.deviceResponse;
    if (typeof deviceResponse === 'string') {
      try {
        deviceResponse = JSON.parse(deviceResponse);
      } catch {
        return identityErrorResponse('Invalid passkey response', 'invalid_request', 400);
      }
    }
    if (!deviceResponse) return identityErrorResponse(PASSKEY_REQUIRED, 'invalid_request', 400);

    let asserted: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
    try {
      asserted = await assertAccountPasskeyCredential(request, env, env.DB, {
        token,
        deviceResponse,
        scope: 'Authentication',
      });
    } catch (error) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: null,
        action: 'auth.passkey.login.failed',
        category: 'auth',
        level: 'warn',
        targetType: 'accountPasskey',
        targetId: null,
        metadata: {
          grantType,
          reason: error instanceof Error ? error.message : 'assertion_failed',
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Passkey is invalid. Try again', 'invalid_grant', 400);
    }

    const { user, credential } = asserted;
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    const deviceInfo = readAuthRequestDeviceInfo(body, request);
    const deviceSession = await persistLoginDevice(env, request, user, deviceInfo, body);

    await rateLimit.clearLoginAttempts(loginIdentifier);

    const userVerificationToken = await createPasskeyUserVerificationToken(env, user.id, 'backup.settings.repair');
    return completeLogin(request, env, { user, body, deviceInfo, deviceSession, grantType },
      { userVerificationToken, prfOption: buildAccountPasskeyTokenUserDecryptionOption(credential) },
      { action: 'auth.passkey.login.success', targetType: 'accountPasskey', targetId: credential.id });

  } else if (body.grant_type === 'client_credentials') {
    // Login with client credentials
    const { client_id: clientId, client_secret: clientSecret, scope } = body;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    if (scope === 'api.secrets' || isUUID(String(clientId))) {
      const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, clientId.toLowerCase());
      const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
      if (!loginCheck.allowed) return identityErrorResponse('Too many failed login attempts.', 'TooManyRequests', 429);
      const token = await getAccessTokenWithAccount(env.DB, clientId.toLowerCase());
      if (!token || !token.key || !token.encryptedPayload || (token.expireAt && !(Date.parse(token.expireAt) > Date.now())) || !(await verifyApiKey(clientSecret, token.clientSecretHash))) {
        await rateLimit.recordFailedLogin(loginIdentifier);
        return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_client', 400);
      }
      await rateLimit.clearLoginAttempts(loginIdentifier);
      const now = Math.floor(Date.now() / 1000);
      const accessToken = await signHs256Jwt({ iss: 'nodewarden', iat: now, nbf: now, exp: now + LIMITS.auth.smAccessTokenTtlSeconds, sub: token.serviceAccountId, type: 'ServiceAccount', organization: token.orgId, client_id: token.id, scope: ['api.secrets'] }, env.JWT_SECRET);
      return identityJsonResponse({ access_token: accessToken, expires_in: LIMITS.auth.smAccessTokenTtlSeconds, token_type: 'Bearer', scope: 'api.secrets', encrypted_payload: token.encryptedPayload });
    }
    const parmValid = checkClientCredentialsParam(clientId, clientSecret, scope);
    if (!parmValid) {
      return identityErrorResponse('Parameter error', 'invalid_request', 400);
    }
    const uid = clientId.slice(5);
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, uid);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const locked = await loginLockoutResponse(rateLimit, loginIdentifier);
    if (locked) return locked;

    const user = await userRepo.getUserById(env.DB, uid);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await recordLoginFailure(env, request, user, grantType, deviceInfo.deviceIdentifier, 'auth.login.failed.user_inactive');
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    if (!user.apiKey || !(await verifyApiKey(clientSecret, user.apiKey))) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await recordLoginFailure(env, request, user, grantType, deviceInfo.deviceIdentifier, 'auth.login.failed.bad_api_key');
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }

    // Persist device only after successful client credential verification.
    const deviceSession = await persistLoginDevice(env, request, user, deviceInfo, body);

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    return completeLogin(request, env, { user, body, deviceInfo, deviceSession, grantType });

  } else if (body.grant_type === 'send_access') {
    const sendAccessLimit = await rateLimit.consumeBudget(`${clientIdentifier}:public`, LIMITS.rateLimit.publicRequestsPerMinute);
    if (!sendAccessLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${sendAccessLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    const sendId = body.send_id || body.sendId;
    if (!sendId) {
      return identityJsonResponse(
        {
          error: 'invalid_request',
          error_description: 'send_id is required',
          send_access_error_type: 'invalid_send_id',
          ErrorModel: {
            Message: 'send_id is required',
            Object: 'error',
          },
        },
        400
      );
    }

    const passwordHashB64 = body.password_hash_b64 || body.passwordHashB64 || body.passwordHash || body.password_hash || null;
    const password = body.password || null;

    const result = await issueSendAccessToken(
      env,
      sendId,
      passwordHashB64,
      password,
      rateLimit,
      clientIdentifier || undefined
    );
    if ('error' in result) {
      return result.error;
    }

    return identityJsonResponse({
      access_token: result.token,
      expires_in: LIMITS.auth.sendAccessTokenTtlSeconds,
      token_type: 'Bearer',
      scope: 'api.send',
      unofficialServer: true,
    });
  } else if (body.grant_type === 'refresh_token') {
    const refreshToken = body.refresh_token || (
      shouldUseWebSession(request)
        ? parse(request.headers.get('Cookie') ?? '', WEB_REFRESH_COOKIE)[WEB_REFRESH_COOKIE]
        : null
    );
    if (!refreshToken) {
      return identityErrorResponse('Refresh token is required', 'invalid_request', 400);
    }

    const refreshTokenHash = await sha256(refreshToken);
    try {
      const sessionLimit = await rateLimit.consumeBudget(
        `refresh-session:${refreshTokenHash}`,
        LIMITS.rateLimit.refreshTokenRequestsPerMinute
      );
      const ipLimit = clientIdentifier
        ? await rateLimit.consumeBudget(
            `refresh-ip:${clientIdentifier}`,
            LIMITS.rateLimit.refreshTokenRequestsPerIpMinute
          )
        : null;
      const rejected = !sessionLimit.allowed ? sessionLimit : (ipLimit && !ipLimit.allowed ? ipLimit : null);
      if (rejected) {
        const retryAfter = Math.max(1, rejected.retryAfterSeconds || 1);
        return identityErrorResponse(
          `Rate limit exceeded. Try again in ${retryAfter} seconds.`,
          'temporarily_unavailable',
          429,
          { 'Retry-After': String(retryAfter) }
        );
      }
    } catch (error) {
      await safeWriteAuditEvent(env, {
        action: 'auth.refresh.failed.rate_limit_unavailable',
        category: 'auth',
        level: 'error',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'rate_limit_unavailable', error: error instanceof Error ? error.message : String(error), ...auditRequestMetadata(request) },
      });
      return identityErrorResponse(
        'Session refresh is temporarily unavailable',
        'temporarily_unavailable',
        503,
        { 'Retry-After': '5' }
      );
    }

    if (!clientIdentifier) {
      await safeWriteAuditEvent(env, {
        action: 'auth.client_ip.missing',
        category: 'auth',
        level: 'warn',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'client_ip_missing', webSession: shouldUseWebSession(request), ...auditRequestMetadata(request) },
      });
    }

    let result: Awaited<ReturnType<AuthService['refreshAccessTokenDetailed']>>;
    try {
      result = await auth.refreshAccessTokenDetailed(refreshToken);
    } catch (error) {
      await safeWriteAuditEvent(env, {
        action: 'auth.refresh.failed.temporarily_unavailable',
        category: 'auth',
        level: 'error',
        targetType: 'refreshToken',
        metadata: { grantType, reason: 'storage_or_worker_error', error: error instanceof Error ? error.message : String(error), webSession: shouldUseWebSession(request), ...auditRequestMetadata(request) },
      });
      return identityErrorResponse(
        'Session refresh is temporarily unavailable',
        'temporarily_unavailable',
        503,
        { 'Retry-After': '5' }
      );
    }
    if (!result.ok) {
      await safeWriteAuditEvent(env, {
        actorUserId: result.userId ?? null,
        action: `auth.refresh.failed.${result.reason}`,
        category: 'auth',
        level: 'warn',
        targetType: result.deviceIdentifier ? 'device' : 'refreshToken',
        targetId: result.deviceIdentifier ?? null,
        metadata: {
          grantType,
          reason: result.reason,
          webSession: shouldUseWebSession(request),
          ...auditRequestMetadata(request),
        },
      });
      const invalidResponse = identityErrorResponse('Invalid refresh token', 'invalid_grant', 400);
      return shouldUseWebSession(request)
        ? withWebRefreshCookie(request, invalidResponse, null)
        : invalidResponse;
    }

    const { accessToken, user, device } = result;
    if (device?.identifier) {
      await deviceRepo.touchDeviceLastSeen(env.DB, user.id, device.identifier);
    }
    return tokenResponse(request, user, accessToken, refreshToken);
  }

  return identityErrorResponse('Unsupported grant type', 'unsupported_grant_type', 400);
}

// POST /identity/accounts/prelogin
export async function handlePrelogin(request: Request, env: Env): Promise<Response> {
  const body = await parseBody(request, z.object({ email: requiredText('Email is required').toLowerCase() }));
  if (body instanceof Response) return body;
  const { email } = body;

  const user = await userRepo.getUser(env.DB, email);

  // Return default KDF settings even if user doesn't exist (to prevent user enumeration)
  const kdfType = user?.kdfType ?? 0;
  const kdfIterations = user?.kdfIterations ?? LIMITS.auth.defaultKdfIterations;
  // Use ?? null so non-existent users return null (not undefined/omitted) for these fields,
  // matching the response shape of real PBKDF2 users and reducing enumeration signal.
  const kdfMemory = user?.kdfMemory ?? null;
  const kdfParallelism = user?.kdfParallelism ?? null;

  return identityJsonResponse(buildPreloginResponse(email, kdfType, kdfIterations, kdfMemory, kdfParallelism));
}

// POST /identity/connect/revocation
// Best-effort OAuth token revocation endpoint.
// RFC 7009 allows returning 200 even if token is unknown.
export async function handleRevocation(request: Request, env: Env): Promise<Response> {
  let form: unknown;
  try {
    form = await readFormOrJson(request);
  } catch {
    return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' } });
  }

  const token = z.object({ token: formText }).catch({}).parse(form).token || (
    shouldUseWebSession(request)
      ? (parse(request.headers.get('Cookie') ?? '', WEB_REFRESH_COOKIE)[WEB_REFRESH_COOKIE] || '')
      : ''
  );
  if (token) {
    await sessionRepo.deleteRefreshToken(env.DB, token);
  }

  const baseResponse = new Response(null, {
    status: 200,
    headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
  });
  return shouldUseWebSession(request)
    ? withWebRefreshCookie(request, baseResponse, null)
    : baseResponse;
}

export function checkClientCredentialsParam(clientId: string, clientSecret: string, scope: string): boolean {
  if (scope !== 'api') {
    return false;
  }
  if (!clientId.startsWith('user.')) {
    return false;
  }
  if (!clientSecret) {
    return false;
  }
  return true;
}
