import { Env, TokenResponse, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse, identityErrorResponse } from '../utils/response';
import { getRefreshTokenSlidingTtlMs, LIMITS } from '../config/limits';
import { findMatchingTotpCounter, isTotpEnabled } from '../utils/totp';
import { createRefreshToken } from '../utils/jwt';
import { readAuthRequestDeviceInfo } from '../utils/device';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { generateUUID } from '../utils/uuid';
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
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import { createPasskeyUserVerificationToken } from '../utils/user-verification-token';
import { constantTimeEquals, verifyApiKey } from '../utils/api-key';
import { isYubiKeyEnabled, userYubiKeyPublicIds, verifyYubicoOtp, yubiKeyPublicIdFromOtp } from '../utils/yubico-otp';
import { getYubicoCredentials, initializeYubicoCredentialsOnce } from '../services/yubico-config';

const TWO_FACTOR_REMEMBER_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
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

function identityJsonResponse(data: unknown, status: number = 200): Response {
  return jsonResponse(data, status, { 'Cache-Control': 'no-store', Pragma: 'no-cache' });
}

function resolveTotpSecret(userSecret: string | null): string | null {
  if (userSecret && isTotpEnabled(userSecret)) {
    return userSecret;
  }
  return null;
}

async function resolveDeviceSession(
  storage: StorageService,
  userId: string,
  deviceInfo: ReturnType<typeof readAuthRequestDeviceInfo>
): Promise<{ identifier: string; sessionStamp: string } | null> {
  if (!deviceInfo.deviceIdentifier) return null;
  const existingDevice = await storage.getDevice(userId, deviceInfo.deviceIdentifier);
  const sessionStamp = String(existingDevice?.sessionStamp || '').trim() || generateUUID();
  return { identifier: deviceInfo.deviceIdentifier, sessionStamp };
}

function resolveRefreshClientType(request: Request, body: Record<string, string>): string {
  if (shouldUseWebSession(request)) return 'web';
  const clientId = String(body.client_id || '').trim().toLowerCase();
  if (clientId === 'mobile') return 'mobile';
  if (clientId === 'browser' || clientId === 'desktop' || clientId === 'cli') return clientId;
  return clientId || 'other';
}

async function persistAndResolveDeviceSession(
  storage: StorageService,
  userId: string,
  deviceInfo: ReturnType<typeof readAuthRequestDeviceInfo>
): Promise<{ identifier: string; sessionStamp: string } | null> {
  const candidate = await resolveDeviceSession(storage, userId, deviceInfo);
  if (!candidate) return null;
  await storage.upsertDevice(
    userId,
    candidate.identifier,
    deviceInfo.deviceName,
    deviceInfo.deviceType,
    candidate.sessionStamp
  );
  const persisted = await storage.getDevice(userId, candidate.identifier);
  if (!persisted?.sessionStamp) throw new Error('Failed to persist device session');
  return { identifier: persisted.deviceIdentifier, sessionStamp: persisted.sessionStamp };
}

function readDevicePushToken(body: Record<string, string>): string {
  return String(readBodyValue(body, ['devicePushToken', 'DevicePushToken', 'device_push_token']) || '').trim();
}

async function persistIdentityDevicePushToken(
  env: Env,
  storage: StorageService,
  userId: string,
  deviceSession: { identifier: string; sessionStamp: string } | null,
  deviceType: number,
  body: Record<string, string>
): Promise<void> {
  if (!deviceSession) return;
  const pushToken = readDevicePushToken(body);
  if (!pushToken) return;

  const device = await storage.getDevice(userId, deviceSession.identifier);
  if (!device) return;

  const pushUuid = device.pushUuid || generateUUID();
  await storage.updateDevicePushToken(userId, deviceSession.identifier, pushUuid, pushToken);
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

function parseCookieValue(request: Request, name: string): string | null {
  const rawCookie = String(request.headers.get('Cookie') || '').trim();
  if (!rawCookie) return null;
  for (const part of rawCookie.split(';')) {
    const [key, ...rest] = part.trim().split('=');
    if (key !== name) continue;
    const value = rest.join('=').trim();
    return value ? decodeURIComponent(value) : null;
  }
  return null;
}

function readBodyValue(body: Record<string, string>, names: string[]): string | undefined {
  for (const name of names) {
    const value = body[name];
    if (value != null) return value;
  }
  return undefined;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function loginRateLimitKey(clientIdentifier: string, grantType: string, subject: string): Promise<string> {
  const subjectHash = await sha256Hex(`${grantType}:${String(subject || '').trim() || 'unknown'}`);
  return `${clientIdentifier}:login:${grantType}:${subjectHash}`;
}

function buildRefreshCookie(request: Request, refreshToken: string, maxAgeSeconds: number): string {
  const isHttps = new URL(request.url).protocol === 'https:';
  const parts = [
    `${WEB_REFRESH_COOKIE}=${encodeURIComponent(refreshToken)}`,
    'Path=/identity/connect',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}`,
  ];
  if (isHttps) parts.push('Secure');
  return parts.join('; ');
}

function buildClearedRefreshCookie(request: Request): string {
  return buildRefreshCookie(request, '', 0);
}

function withWebRefreshCookie(request: Request, response: Response, refreshToken: string | null): Response {
  const headers = new Headers(response.headers);
  headers.append(
    'Set-Cookie',
    refreshToken
      ? buildRefreshCookie(request, refreshToken, Math.floor(getRefreshTokenSlidingTtlMs('web') / 1000))
      : buildClearedRefreshCookie(request)
  );
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

async function twoFactorRequiredResponse(
  request: Request,
  env: Env,
  storage: StorageService,
  user?: User,
  message: string = 'Two factor required.'
): Promise<Response> {
  // Match Bitwarden Identity: TwoFactorProviders2 lists enabled 2FA providers only.
  // Clients expose recovery-code entry points themselves; Android 2026.4 fails to
  // parse the challenge if an unknown recovery provider key such as "8" is included.
  const providers: string[] = [];
  let webAuthnOptions: Record<string, unknown> | null = null;
  if (!user || resolveTotpSecret(user.totpSecret)) providers.push(String(TWO_FACTOR_PROVIDER_AUTHENTICATOR));
  if (user && isYubiKeyEnabled(user)) providers.push(String(TWO_FACTOR_PROVIDER_YUBIKEY));
  if (user) {
    webAuthnOptions = await buildTwoFactorPasskeyAssertionOptions(request, env, storage, user) as Record<string, unknown> | null;
    if (webAuthnOptions) providers.push(String(TWO_FACTOR_PROVIDER_WEBAUTHN));
  }
  const providers2: Record<string, Record<string, unknown> | null> = {};
  for (const provider of providers) {
    providers2[provider] = provider === String(TWO_FACTOR_PROVIDER_YUBIKEY)
      ? { Nfc: user?.yubikeyNfc ?? false }
      : provider === String(TWO_FACTOR_PROVIDER_WEBAUTHN) && webAuthnOptions
        ? webAuthnOptions
        : null;
  }
  const customResponse = {
    TwoFactorProviders: providers,
    TwoFactorProviders2: providers2,
    SsoEmail2faSessionToken: null,
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

async function recordFailedTwoFactorAndBuildResponse(
  rateLimit: RateLimitService,
  loginIdentifier: string
): Promise<Response> {
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

// POST /identity/connect/token
export async function handleToken(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env.DB);

  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return identityErrorResponse('Invalid request payload', 'invalid_request', 400);
  }

  const grantType = body.grant_type;
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier && grantType !== 'refresh_token') {
    await safeWriteAuditEvent(env, {
      action: 'auth.client_ip.missing',
      category: 'auth',
      level: 'error',
      targetType: 'tokenEndpoint',
      metadata: { grantType, reason: 'client_ip_missing', ...auditRequestMetadata(request) },
    });
    return identityErrorResponse(
      'Authentication is temporarily unavailable',
      'temporarily_unavailable',
      503,
      { 'Retry-After': '5' }
    );
  }

  if (grantType === 'password') {
    // Login with password
    const email = body.username?.toLowerCase();
    const passwordHash = body.password;
    const authRequestId = readBodyValue(body, ['authRequest', 'AuthRequest']);
    const twoFactorToken = readBodyValue(body, ['twoFactorToken', 'TwoFactorToken']);
    const twoFactorProvider = readBodyValue(body, ['twoFactorProvider', 'TwoFactorProvider']);
    const twoFactorRemember = readBodyValue(body, ['twoFactorRemember', 'TwoFactorRemember']);
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    if (!email || !passwordHash) {
      // Bitwarden clients expect OAuth-style error fields.
      return identityErrorResponse('Email and password are required', 'invalid_request', 400);
    }
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, email);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUser(email);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('Username or password is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    let validatedAuthRequestId: string | null = null;
    let authRequestLoginKey: string | null = null;
    let valid = false;
    const normalizedAuthRequestId = String(authRequestId || '').trim();
    if (normalizedAuthRequestId) {
      const authRequest = await storage.getAuthRequestByIdForUser(normalizedAuthRequestId, user.id);
      valid = !!(
        authRequest &&
        authRequest.userId === user.id &&
        authRequest.type === 0 &&
        authRequest.approved === true &&
        authRequest.responseDate &&
        !authRequest.authenticationDate &&
        !isAuthRequestExpired(authRequest) &&
        !!authRequest.key &&
        constantTimeEquals(authRequest.accessCode, passwordHash)
      );
      if (valid) {
        validatedAuthRequestId = authRequest!.id;
        authRequestLoginKey = authRequest!.key;
      }
    } else {
      valid = await auth.verifyPassword(passwordHash, user.masterPasswordHash, user.email);
    }
    if (!valid) {
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: normalizedAuthRequestId ? 'auth.login.failed.bad_auth_request' : 'auth.login.failed.bad_password',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return recordFailedLoginAndBuildResponse(
        rateLimit,
        loginIdentifier,
        'Username or password is incorrect. Try again'
      );
    }

    // Optional 2FA: enabled by any supported per-user provider.
    let trustedTwoFactorTokenToReturn: string | undefined;
    const effectiveTotpSecret = resolveTotpSecret(user.totpSecret);
    const effectiveYubiKeyPublicIds = userYubiKeyPublicIds(user);
    const effectiveWebAuthnCredentials = await storage.getAccountPasskeyCredentialsByUserId(user.id, 'twoFactor');
    if (effectiveTotpSecret || effectiveYubiKeyPublicIds.length > 0 || effectiveWebAuthnCredentials.length > 0) {
      const normalizedTwoFactorProvider = String(twoFactorProvider ?? '').trim();
      const normalizedTwoFactorToken = String(twoFactorToken ?? '').trim();
      let rememberRequested = ['1', 'true', 'True', 'TRUE', 'on', 'yes', 'Yes', 'YES'].includes(String(twoFactorRemember || '').trim());
      const hasProvider = normalizedTwoFactorProvider.length > 0;
      const hasToken = normalizedTwoFactorToken.length > 0;

      // Upstream-compatible behavior: if 2FA is required and either provider or token is missing,
      // respond with a 2FA challenge payload.
      if (!hasProvider || !hasToken) {
        return await twoFactorRequiredResponse(request, env, storage, user, 'Two factor required.');
      }

      let passedByRememberToken = false;
      if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_REMEMBER)) {
        if (deviceInfo.deviceIdentifier) {
          const trustedUserId = await storage.getTrustedTwoFactorDeviceTokenUserId(
            normalizedTwoFactorToken,
            deviceInfo.deviceIdentifier
          );
          passedByRememberToken = trustedUserId === user.id;
        }

        // Remember token missing/invalid/expired should re-enter the 2FA challenge flow.
        if (!passedByRememberToken) {
          return await twoFactorRequiredResponse(request, env, storage, user, 'Two factor required.');
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_AUTHENTICATOR)) {
        if (!effectiveTotpSecret) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        const matchedCounter = await findMatchingTotpCounter(effectiveTotpSecret, normalizedTwoFactorToken);
        if (matchedCounter == null) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        const consumed = await storage.consumeTotpLoginCounter(user.id, matchedCounter);
        if (!consumed) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_YUBIKEY)) {
        const publicId = yubiKeyPublicIdFromOtp(normalizedTwoFactorToken);
        if (!publicId || !effectiveYubiKeyPublicIds.includes(publicId)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        let credentials = await getYubicoCredentials(env.DB);
        let initializedWithCurrentOtp = false;
        if (!credentials) {
          const initialized = await initializeYubicoCredentialsOnce(env.DB, user.email, normalizedTwoFactorToken);
          if (!initialized) {
            return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
          }
          credentials = initialized.credentials;
          initializedWithCurrentOtp = initialized.created;
        }
        if (!initializedWithCurrentOtp && !await verifyYubicoOtp(env, normalizedTwoFactorToken, credentials)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_WEBAUTHN)) {
        if (!effectiveWebAuthnCredentials.length) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        let deviceResponse: unknown;
        try {
          deviceResponse = JSON.parse(normalizedTwoFactorToken);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        try {
          await assertTwoFactorPasskeyCredential(request, env, storage, user, deviceResponse);
        } catch {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
      } else if (
        normalizedTwoFactorProvider === TWO_FACTOR_PROVIDER_RECOVERY_CODE_RESPONSE ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE) ||
        normalizedTwoFactorProvider === String(TWO_FACTOR_PROVIDER_RECOVERY_CODE_ANDROID_REQUEST)
      ) {
        if (!recoveryCodeEquals(normalizedTwoFactorToken, user.totpRecoveryCode)) {
          return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
        }
        user.totpSecret = null;
        user.yubikeyKey1 = null;
        user.yubikeyKey2 = null;
        user.yubikeyKey3 = null;
        user.yubikeyKey4 = null;
        user.yubikeyKey5 = null;
        user.yubikeyNfc = false;
        for (const credential of effectiveWebAuthnCredentials) {
          await storage.deleteAccountPasskeyCredential(user.id, credential.id, 'twoFactor');
        }
        user.totpRecoveryCode = createRecoveryCode();
        user.securityStamp = generateUUID();
        user.updatedAt = new Date().toISOString();
        await storage.saveUser(user);
        await storage.deleteRefreshTokensByUserId(user.id);
        AuthService.invalidateUserCache(user.id);
        rememberRequested = false;
      } else {
        // Unsupported provider for this server profile behaves as an invalid 2FA attempt.
        return recordFailedTwoFactorAndBuildResponse(rateLimit, loginIdentifier);
      }

      // Upstream behavior: do not issue a new remember token when auth itself used remember provider.
      if (rememberRequested && !passedByRememberToken && deviceInfo.deviceIdentifier) {
        trustedTwoFactorTokenToReturn = createRefreshToken();
        await storage.saveTrustedTwoFactorDeviceToken(
          trustedTwoFactorTokenToReturn,
          user.id,
          deviceInfo.deviceIdentifier,
          Date.now() + TWO_FACTOR_REMEMBER_TTL_MS
        );
      }
    }

    // Persist device only after successful password + (optional) 2FA verification.
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);
    if (validatedAuthRequestId) {
      await storage.markAuthRequestAuthenticated(validatedAuthRequestId);
    }

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      ...(trustedTwoFactorTokenToReturn ? { TwoFactorToken: trustedTwoFactorTokenToReturn } : {}),
      Key: authRequestLoginKey || user.key,
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
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'webauthn') {
    const token = String(body.token || '').trim();
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, token || 'missing-token');
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    let deviceResponse: unknown = body.deviceResponse;
    if (typeof deviceResponse === 'string') {
      try {
        deviceResponse = JSON.parse(deviceResponse);
      } catch {
        return identityErrorResponse('Invalid passkey response', 'invalid_request', 400);
      }
    }
    if (!token || !deviceResponse) {
      return identityErrorResponse('Passkey token and deviceResponse are required', 'invalid_request', 400);
    }

    let asserted: Awaited<ReturnType<typeof assertAccountPasskeyCredential>>;
    try {
      asserted = await assertAccountPasskeyCredential(request, env, storage, {
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
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const userVerificationToken = await createPasskeyUserVerificationToken(env, user.id, 'backup.settings.repair');
    const accountKeys = buildAccountKeys(user);
    const webAuthnPrfOption = buildAccountPasskeyTokenUserDecryptionOption(credential);
    const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOption);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.passkey.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'accountPasskey',
      targetId: credential.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
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
      UserVerificationToken: userVerificationToken,
      userVerificationToken,
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'client_credentials') {
    // Login with client credentials
    const clientId = body.client_id;
    const clientSecret = body.client_secret;
    const scope = body.scope;
    const deviceInfo = readAuthRequestDeviceInfo(body, request);

    const parmValid = checkClientCredentialsParam(clientId, clientSecret, scope);
    if (!parmValid) {
      return identityErrorResponse('Parameter error', 'invalid_request', 400);
    }
    const uid = clientId.slice(5);
    const loginIdentifier = await loginRateLimitKey(clientIdentifier!, grantType, uid);

    // Check login lockout before user lookup to reduce user-enumeration signal
    const loginCheck = await rateLimit.checkLoginAttempt(loginIdentifier);
    if (!loginCheck.allowed) {
      return identityErrorResponse(
        `Too many failed login attempts. Try again in ${Math.ceil(loginCheck.retryAfterSeconds! / 60)} minutes.`,
        'TooManyRequests',
        429
      );
    }

    const user = await storage.getUserById(uid);
    if (!user) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }
    if (user.status !== 'active') {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.user_inactive',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('Account is disabled', 'invalid_grant', 400);
    }

    if (!user.apiKey || !(await verifyApiKey(clientSecret, user.apiKey))) {
      await rateLimit.recordFailedLogin(loginIdentifier);
      await safeWriteAuditEvent(env, {
        actorUserId: user.id,
        action: 'auth.login.failed.bad_api_key',
        category: 'auth',
        level: 'warn',
        targetType: 'user',
        targetId: user.id,
        metadata: {
          grantType,
          deviceIdentifier: deviceInfo.deviceIdentifier,
          ...auditRequestMetadata(request),
        },
      });
      return identityErrorResponse('ClientId or clientSecret is incorrect. Try again', 'invalid_grant', 400);
    }

    // Persist device only after successful client credential verification.
    const deviceSession = await persistAndResolveDeviceSession(storage, user.id, deviceInfo);
    if (deviceSession) {
      await persistIdentityDevicePushToken(env, storage, user.id, deviceSession, deviceInfo.deviceType, body);
    }

    // Successful login - clear failed attempts
    await rateLimit.clearLoginAttempts(loginIdentifier);

    const accessToken = await auth.generateAccessToken(user, deviceSession);
    const refreshToken = await auth.generateRefreshToken(user, deviceSession, resolveRefreshClientType(request, body));
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);
    await safeWriteAuditEvent(env, {
      actorUserId: user.id,
      action: 'auth.login.success',
      category: 'auth',
      level: 'info',
      targetType: 'user',
      targetId: user.id,
      metadata: {
        grantType,
        webSession: shouldUseWebSession(request),
        deviceIdentifier: deviceSession?.identifier ?? deviceInfo.deviceIdentifier,
        deviceType: deviceInfo.deviceType,
        ...auditRequestMetadata(request),
      },
    });

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
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
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;

  } else if (grantType === 'send_access') {
    const sendAccessLimit = await rateLimit.consumeBudget(`${clientIdentifier}:public`, LIMITS.rateLimit.publicRequestsPerMinute);
    if (!sendAccessLimit.allowed) {
      return identityErrorResponse(
        `Rate limit exceeded. Try again in ${sendAccessLimit.retryAfterSeconds} seconds.`,
        'TooManyRequests',
        429
      );
    }

    const sendId = String(body.send_id || body.sendId || '').trim();
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

    const passwordHashB64 = String(
      body.password_hash_b64 || body.passwordHashB64 || body.passwordHash || body.password_hash || ''
    ).trim() || null;
    const password = String(body.password || '').trim() || null;

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
  } else if (grantType === 'refresh_token') {
    const refreshToken = String(body.refresh_token || '').trim() || (
      shouldUseWebSession(request)
        ? parseCookieValue(request, WEB_REFRESH_COOKIE)
        : null
    );
    if (!refreshToken) {
      return identityErrorResponse('Refresh token is required', 'invalid_request', 400);
    }

    const refreshTokenHash = await sha256Hex(refreshToken);
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
      await storage.touchDeviceLastSeen(user.id, device.identifier);
    }
    const accountKeys = buildAccountKeys(user);
    const userDecryptionOptions = buildUserDecryptionOptions(user);

    const response: TokenResponse = {
      access_token: accessToken,
      expires_in: LIMITS.auth.accessTokenTtlSeconds,
      token_type: 'Bearer',
      ...(shouldUseWebSession(request) ? { web_session: true } : { refresh_token: refreshToken }),
      Key: user.key,
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
      UserDecryptionOptions: userDecryptionOptions,
      userDecryptionOptions: userDecryptionOptions,
    };

    const baseResponse = identityJsonResponse(response);
    return shouldUseWebSession(request)
      ? withWebRefreshCookie(request, baseResponse, refreshToken)
      : baseResponse;
  }

  return identityErrorResponse('Unsupported grant type', 'unsupported_grant_type', 400);
}

// POST /identity/accounts/prelogin
export async function handlePrelogin(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { email?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const email = body.email?.toLowerCase();
  if (!email) {
    return errorResponse('Email is required', 400);
  }

  const user = await storage.getUser(email);

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
  const storage = new StorageService(env.DB);
  let body: Record<string, string>;
  const contentType = request.headers.get('content-type') || '';
  try {
    if (contentType.includes('application/x-www-form-urlencoded')) {
      const formData = await request.formData();
      body = Object.fromEntries(formData.entries()) as Record<string, string>;
    } else {
      body = await request.json();
    }
  } catch {
    return new Response(null, { status: 200, headers: { 'Cache-Control': 'no-store', Pragma: 'no-cache' } });
  }

  const token = String(body.token || '').trim() || (
    shouldUseWebSession(request)
      ? (parseCookieValue(request, WEB_REFRESH_COOKIE) || '')
      : ''
  );
  if (token) {
    await storage.deleteRefreshToken(token);
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
