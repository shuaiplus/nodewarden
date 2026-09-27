import { EventType, recordUserEvent } from '../services/events';
import { sql } from 'drizzle-orm';
import { toSafeUrl } from '../utils/html';
import { runInBackground, notifyMail, notifyFailedTwoFactor, notifyNewDeviceVerification } from '../services/mail-notify';
import { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { isAuthRequestLoginApproved } from '../services/storage-auth-request-repo';
import { readAuthRequestDeviceInfo, deviceTypeName } from '../utils/device';
import { syncVaultAdminRoles } from '../services/vault-admin-role';
import { deleteUserAccount } from '../services/account-deletion';
import { notifyUserLogout } from '../durable/notifications-hub';
import { issueEmailOtp, redeemEmailOtp, spendEmailOtpIssueBudget } from '../services/email-otp';
import { twoFactorProviders, twoFactorClearStatements, ensureTwoFactorRecoveryCode } from '../services/two-factor-providers';
import { upsertCredentialAccount, credentialAccountStatement } from '../services/auth-accounts';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { auditRequestMetadata, writeAuditEvent, safeWriteAuditEvent, auditEventStatement } from '../services/audit-events';
import { z } from 'zod';
import { bodyIssues, errorResponse, jsonResponse, parseBody, unsupportedResponse, normalizeJsonKeys } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { LIMITS } from '../config/limits';
import { isStoredApiKeyHash, randomStringAlphanum } from '../utils/api-key';
import { Secret } from 'otpauth';
import { findMatchingTotpCounter, isTotpEnabled, normalizeTotpSecret } from '../utils/totp';
import { createRecoveryCode, recoveryCodeEquals } from '../utils/recovery-code';
import { buildAccountKeys } from '../utils/user-decryption';
import { buildProfileResponse } from '../utils/profile-response';
import { createRegisterVerifyToken, verifyRegisterVerifyToken, createTwoFactorUserVerificationToken, verifyTwoFactorUserVerificationToken, verifySsoEmail2faSessionToken, createDeleteRecoverToken, verifyDeleteRecoverToken } from '../utils/jwt';
import { isOpenRegistrationEnabled, KdfSettings, MasterPasswordHint, RegisterSchema } from '../services/register-payload';
import {
  mailStatusCheck,
  type MailOutcome,
  readMailConfig,
  EMAIL_PATTERN,
  isReservedDocumentationEmail,
  registerVerifyVaultOrigin,
  configuredVaultOrigin,
  sendMail,
} from '../services/mail';
import { isYubiKeyEnabled, isYubiKeyPublicId, requestYubicoApiCredentials, verifyYubicoOtp, yubiKeyPublicIdFromOtp } from '../utils/yubico-otp';
import {
  getYubicoCredentials,
  initializeYubicoCredentialsOnce,
  replaceYubicoCredentials,
} from '../services/yubico-config';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as adminRepo from '../services/storage-admin-repo';
import * as authRequestRepo from '../services/storage-auth-request-repo';
import * as configRepo from '../services/storage-config-repo';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as totpReplayRepo from '../services/storage-totp-replay-repo';
import * as userRepo from '../services/storage-user-repo';

const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_EMAIL = 1;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;

// CONTRACT:
// users.master_password_hash is server-side login verification only. It does
// not decrypt vault data. Password changes must keep encrypted user key material,
// securityStamp, refresh-token invalidation, and client compatibility together.
// Password hints are non-secret reminders; never treat them as recovery secrets.
function looksLikeEncString(value: string): boolean {
  if (!value) return false;
  const firstDot = value.indexOf('.');
  if (firstDot <= 0 || firstDot === value.length - 1) return false;
  const payload = value.slice(firstDot + 1);
  const parts = payload.split('|');
  // Bitwarden encrypted payloads should have at least IV + ciphertext.
  return parts.length >= 2;
}

function jwtSecretUnsafeReason(env: Env): 'missing' | 'too_short' | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret) return 'missing';
  if (secret.length < LIMITS.auth.jwtSecretMinLength) return 'too_short';
  return null;
}

async function verifyUserSecret(
  auth: AuthService,
  user: User,
  secret: string | null | undefined
): Promise<boolean> {
  const normalized = String(secret || '').trim();
  if (!normalized) return false;
  return auth.verifyPassword(normalized, user.masterPasswordHash, user.email);
}


// Account bodies read an absent or wrongly typed string as empty; the verification that follows rejects it.
const text = z.string().catch('');
const trimmed = z.string().trim().catch('');

// Mail goes to, and codes bind to, one address the transport accepts.
export const emailAddress = (error: string) => z.string({ error })
  .trim()
  .toLowerCase()
  .refine((email) => email.length <= 256 && EMAIL_PATTERN.test(email), { error });

// User verification takes the master password hash, which older clients also post as otp or secret.
const VerifiedBody = z.object({ masterPasswordHash: text, otp: text, OTP: text, secret: text });
const verificationSecret = (body: z.output<typeof VerifiedBody>) => body.masterPasswordHash || body.otp || body.OTP || body.secret;

// Older clients post the current master password hash as master_password_hash or password.
const CurrentPasswordHash = z.object({ masterPasswordHash: text, master_password_hash: text, password: text })
  .transform((body) => (body.masterPasswordHash || body.master_password_hash || body.password).trim())
  .refine(Boolean, 'masterPasswordHash is required');

// Clients may echo the account KDF; changing it takes the KDF endpoint, which this server does not support.
function unchangedKdf(user: User, endpoint: 'password' | 'email') {
  const same = (expected: unknown) => z.unknown()
    .refine((value) => value === expected, { error: `KDF settings cannot be changed with the ${endpoint} endpoint` })
    .optional();
  return {
    kdf: same(user.kdfType),
    kdfType: same(user.kdfType),
    kdfIterations: same(user.kdfIterations),
    kdfMemory: same(user.kdfMemory ?? null),
    kdfParallelism: same(user.kdfParallelism ?? null),
  };
}

const masterPasswordHalf = { salt: text, kdf: KdfSettings };

// A new master password arrives either as web 2026.9's nested authenticationData/unlockData
// (server MasterPasswordAuthenticationData/UnlockData) or as legacy newMasterPasswordHash + key.
export const MasterPasswordFields = z.object({
  authenticationData: z.object({ ...masterPasswordHalf, masterPasswordAuthenticationHash: trimmed }).optional().catch(undefined),
  unlockData: z.object({ ...masterPasswordHalf, masterKeyWrappedUserKey: trimmed }).optional().catch(undefined),
  newMasterPasswordHash: trimmed,
  newKey: trimmed,
  key: trimmed,
}, { error: 'Request body must be a JSON object' });

// Password change, email change and emergency takeover share this check: the nested halves must agree
// with each other and with the user's stored KDF and email salt, otherwise the stored hash and wrapped
// user key stop matching what clients derive at the next login.
export function masterPasswordUpdate(body: z.output<typeof MasterPasswordFields>, user: User): { masterPasswordHash: string; key: string } | Response {
  const reject = (message: string) => errorResponse(message, 400);
  const { authenticationData: auth, unlockData: unlock } = body;
  if (!auth !== !unlock) return reject('authenticationData and unlockData must be provided together');
  const update = auth && unlock
    ? { masterPasswordHash: auth.masterPasswordAuthenticationHash, key: unlock.masterKeyWrappedUserKey }
    : { masterPasswordHash: body.newMasterPasswordHash, key: body.newKey || body.key };

  if (auth && unlock) {
    if (!update.masterPasswordHash || !update.key) return reject('authenticationData and unlockData are incomplete');
    const [authKdf, unlockKdf] = [auth.kdf, unlock.kdf];
    if (authKdf?.kdfType === undefined || authKdf.iterations === undefined || unlockKdf?.kdfType === undefined || unlockKdf.iterations === undefined) {
      return reject('authenticationData and unlockData must include KDF settings');
    }
    if ((['kdfType', 'iterations', 'memory', 'parallelism'] as const).some((name) => authKdf[name] !== unlockKdf[name])) {
      return reject('authenticationData and unlockData must use the same KDF settings');
    }
    if (!auth.salt || auth.salt !== unlock.salt || auth.salt !== user.email.trim().toLowerCase()) {
      return reject('Invalid master password salt');
    }
    if (
      authKdf.kdfType !== user.kdfType ||
      authKdf.iterations !== user.kdfIterations ||
      (authKdf.kdfType === 1 && (authKdf.memory !== user.kdfMemory || authKdf.parallelism !== user.kdfParallelism))
    ) {
      return reject('KDF settings cannot be changed with the password endpoint');
    }
  } else if (!update.masterPasswordHash || !update.key) {
    return reject('newMasterPasswordHash and key must be provided together');
  }

  if (!looksLikeEncString(update.key)) return reject('new key is not a valid encrypted string');
  return update;
}

// Account routes accept form posts from older clients as well as JSON; JSON keys are normalized.
async function readRequestBody<S extends z.ZodType>(request: Request, schema: S): Promise<z.output<S> | Response> {
  let body: unknown;
  try {
    body = request.headers.get('content-type')?.includes('application/x-www-form-urlencoded')
      ? Object.fromEntries((await request.formData()).entries())
      : normalizeJsonKeys(await request.json());
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  const result = schema.safeParse(body);
  return result.success ? result.data : errorResponse(result.error.issues[0].message, 400, {}, bodyIssues(result.error));
}

function masterPasswordPolicyResponse(): Record<string, unknown> {
  return {
    minComplexity: 0,
    minLength: 0,
    requireUpper: false,
    requireLower: false,
    requireNumbers: false,
    requireSpecial: false,
    enforceOnLogin: false,
    object: 'masterPasswordPolicy',
  };
}

function keysResponse(user: User): Record<string, unknown> {
  const accountKeys = buildAccountKeys(user);
  return {
    Key: user.key,
    PublicKey: user.publicKey ?? '',
    PrivateKey: user.privateKey ?? '',
    AccountKeys: accountKeys,
    Object: 'keys',
    key: user.key,
    publicKey: user.publicKey ?? '',
    privateKey: user.privateKey ?? '',
    accountKeys,
    object: 'keys',
  };
}

// POST /api/accounts/register
// - First user becomes admin.
// - Any subsequent user must provide a valid inviteCode.
export async function handleRegister(request: Request, env: Env): Promise<Response> {

  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    const message = unsafe === 'missing'
      ? 'JWT_SECRET is not set'
      : 'JWT_SECRET must be at least 32 characters';
    return errorResponse(message, 400);
  }

  const parsed = await parseBody(request, RegisterSchema);
  if (parsed instanceof Response) return parsed;
  const { email, name, masterPasswordHash, key, privateKey, publicKey, inviteCode, masterPasswordHint } = parsed;

  if (parsed.emailVerificationToken) {
    const claims = await verifyRegisterVerifyToken(parsed.emailVerificationToken, env.JWT_SECRET);
    if (!claims || claims.email !== email) {
      return errorResponse('Email verification token is invalid or expired', 400);
    }
  }
  if (!looksLikeEncString(key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (!looksLikeEncString(privateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  const now = new Date().toISOString();
  const auth = new AuthService(env);
  const serverHash = await auth.hashPasswordServer(masterPasswordHash, email);

  const user: User = {
    id: generateUUID(),
    email,
    emailVerified: !!parsed.emailVerificationToken,
    name,
    masterPasswordHint,
    masterPasswordHash: serverHash,
    key,
    privateKey,
    publicKey,
    kdfType: parsed.kdf ?? 0,
    kdfIterations: parsed.kdfIterations ?? LIMITS.auth.defaultKdfIterations,
    kdfMemory: parsed.kdfMemory,
    kdfParallelism: parsed.kdfParallelism,
    securityStamp: generateUUID(),
    role: 'user',
    status: 'active',
    verifyDevices: true,
    totpSecret: null,
    totpRecoveryCode: null,
    twoFactorEmail: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    // Bitwarden creates a readable personal API key with the account. It is
    // returned only after fresh user verification and is excluded from backups.
    apiKey: randomStringAlphanum(LIMITS.auth.clientSecretLength),
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
  };

  const userCount = await userRepo.getUserCount(env.DB);
  if (userCount === 0) {
    user.role = 'admin';
    const created = await userRepo.createFirstUser(env.DB, user);
    if (!created) {
      return errorResponse('Registration is temporarily unavailable, retry once', 409);
    }
    AuthService.invalidateUserCache(user.id);
    if (!await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash, user.securityStamp)) return errorResponse('User verification failed.', 400);
    await configRepo.setRegistered(env.DB);
    await writeAuditEvent(env.DB, {
      actorUserId: user.id,
      action: 'user.register.first_admin',
      targetType: 'user',
      targetId: user.id,
      category: 'security',
      level: 'security',
      metadata: { email: user.email, ...auditRequestMetadata(request) },
    });
    notifyMail(env, user.email, 'welcome', { name: user.name || user.email, vaultOrigin: configuredVaultOrigin(request, env) });
    await syncVaultAdminRoles(env);
    return registerSuccessResponse((await userRepo.getUserById(env.DB, user.id))!.role);
  }

  if (!inviteCode && !isOpenRegistrationEnabled(env)) {
    return errorResponse('Invite code is required', 403);
  }

  if (inviteCode) {
    const inviteMarked = await adminRepo.markInviteUsed(env.DB, inviteCode, user.id);
    if (!inviteMarked) {
      return errorResponse('Invite code is invalid or expired', 403);
    }
  }

  try {
    await userRepo.createUser(env.DB, user);
    AuthService.invalidateUserCache(user.id);
    if (!await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash, user.securityStamp)) return errorResponse('User verification failed.', 400);
  } catch (error) {
    if (inviteCode) await adminRepo.revertInviteUsed(env.DB, inviteCode, user.id);
    let cause = error;
    while (cause instanceof Error && cause.cause) cause = cause.cause;
    const msg = (cause instanceof Error ? cause.message : String(cause)).toLowerCase();
    if (msg.includes('unique') || msg.includes('constraint')) {
      return errorResponse('Email already registered', 409);
    }
    console.error('Registration failed after invite reservation:', error);
    throw error;
  }

  if (inviteCode) {
    try {
      const assigned = await adminRepo.assignInviteUsedBy(env.DB, inviteCode, user.id);
      if (!assigned) {
        console.warn('Invite used_by was not assigned after registration', { inviteCode, userId: user.id });
      }
    } catch (error) {
      console.error('Invite used_by assignment failed after registration:', error);
    }
  }

  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: inviteCode ? 'user.register.invite' : 'user.register.open',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'info',
    metadata: { email: user.email, inviteCode, ...auditRequestMetadata(request) },
  });

  notifyMail(env, user.email, 'welcome', { name: user.name || user.email, vaultOrigin: configuredVaultOrigin(request, env) });
  await syncVaultAdminRoles(env);
  return registerSuccessResponse((await userRepo.getUserById(env.DB, user.id))!.role);
}

function registerSuccessResponse(role: User['role']): Response {
  return jsonResponse({
    object: 'register',
    captchaBypassToken: '',
    success: true,
    role,
  }, 200);
}

export async function handleRegisterSendVerificationEmail(request: Request, env: Env): Promise<Response> {
  const unsafe = jwtSecretUnsafeReason(env);
  if (unsafe) {
    return errorResponse(unsafe === 'missing' ? 'JWT_SECRET is not set' : 'JWT_SECRET must be at least 32 characters', 400);
  }

  const body = await parseBody(request, z.object({ email: emailAddress('Invalid email address'), name: trimmed }));
  if (body instanceof Response) return body;
  const { email } = body;
  const name = body.name || null;

  const userCount = await userRepo.getUserCount(env.DB);
  if (userCount > 0 && !isOpenRegistrationEnabled(env)) {
    return errorResponse('Registration is invite-only', 403);
  }

  if (readMailConfig(env).kind !== 'enabled') return errorResponse('Email sending is not configured', 503);
  runInBackground('register-verification', async () => {
    if (isReservedDocumentationEmail(email) || await userRepo.getUser(env.DB, email)) return;
    const token = await createRegisterVerifyToken(env.JWT_SECRET, email, name);
    await sendMail(env, email, 'registerVerification', { vaultOrigin: registerVerifyVaultOrigin(request, env), email, token });
  });

  // Official clients treat a non-empty string as an inline token (no SMTP).
  // An empty JSON string means "check your email".
  return jsonResponse('');
}

export async function handleRegisterFinish(request: Request, env: Env): Promise<Response> {
  // Official self-host web still continues to the password form when
  // send-verification-email returns an empty body. The emailed link carries a
  // token when present; do not require it here or signup breaks.
  return handleRegister(request, env);
}

// POST /api/accounts/password-hint
export async function handleGetPasswordHint(request: Request, env: Env): Promise<Response> {
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }

  const body = await parseBody(request, z.object({
    email: z.string({ error: 'Email is required' }).trim().toLowerCase().min(1, { error: 'Email is required' }),
  }));
  if (body instanceof Response) return body;
  const { email } = body;

  const rateLimit = new RateLimitService(env);
  const minuteBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint`,
    LIMITS.rateLimit.passwordHintRequestsPerMinute,
    60
  );
  if (!minuteBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${minuteBudget.retryAfterSeconds || 60} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(minuteBudget.retryAfterSeconds || 60),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const hourlyBudget = await rateLimit.consumeStrictBudgetWithWindow(
    `${clientIdentifier}:password-hint-hour`,
    LIMITS.rateLimit.passwordHintRequestsPerHour,
    60 * 60
  );
  if (!hourlyBudget.allowed) {
    return new Response(
      JSON.stringify({
        error: 'Too many requests',
        error_description: `Rate limit exceeded. Try again in ${hourlyBudget.retryAfterSeconds || 3600} seconds.`,
      }),
      {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(hourlyBudget.retryAfterSeconds || 3600),
          'X-RateLimit-Remaining': '0',
        },
      }
    );
  }

  const mail = readMailConfig(env);
  if (mail.kind === 'misconfigured') return errorResponse('Email sending is not configured', 503);
  if (mail.kind === 'enabled') {
    runInBackground('password-hint', async () => {
      const user = await userRepo.getUser(env.DB, email);
      if (!user || user.status !== 'active') return;
      const hint = user.masterPasswordHint?.trim();
      if (hint) await sendMail(env, user.email, 'passwordHint', { hint });
      else await sendMail(env, user.email, 'noPasswordHint', {});
    });
    return jsonResponse({ object: 'passwordHint', hasHint: false, masterPasswordHint: null, sentByEmail: true });
  }
  const user = await userRepo.getUser(env.DB, email);
  const hint = user?.status === 'active' ? user.masterPasswordHint?.trim() || null : null;
  return jsonResponse({
    object: 'passwordHint',
    hasHint: !!hint,
    masterPasswordHint: hint,
  });
}

// DELETE /api/accounts; POST /api/accounts/delete
export async function handleDeleteAccount(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, VerifiedBody);
  if (body instanceof Response) return body;
  if (!await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash)) return errorResponse('User verification failed.', 400);
  const result = await deleteUserAccount(env, userId, {
    actorUserId: userId,
    action: 'user.account.delete',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: auditRequestMetadata(request),
  }, user.securityStamp);
  if (result.kind === 'not-found') return errorResponse('User not found', 404);
  if (result.kind === 'blocked-by-orgs') return errorResponse('You cannot delete this member because they are the sole owner of at least one organization vault. Delete these organization vaults or make another member an owner.', 400);
  if (result.kind === 'last-vault-admin') return errorResponse('You cannot delete the last instance administrator.', 400);
  notifyUserLogout(env, userId, null);
  return new Response(null, { status: 200 });
}

export async function handleEmailToken(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, VerifiedBody.extend({ newEmail: emailAddress('Invalid email address') }));
  if (body instanceof Response) return body;
  if (!await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash)) {
    return errorResponse('Invalid password.', 400, {}, { MasterPasswordHash: ['Invalid password.'] });
  }
  const email = body.newEmail;
  if (readMailConfig(env).kind !== 'enabled') return errorResponse('Email sending is not configured', 503);
  const target = { purpose: 'email-change' as const, subject: user.id, binding: `${user.securityStamp}:${email}` };
  let outcome: MailOutcome;
  if (await userRepo.getUser(env.DB, email)) {
    outcome = await spendEmailOtpIssueBudget(env, target)
      ? await sendMail(env, user.email, 'emailChangeAlreadyExists', {})
      : { kind: 'throttled', retryAfterSeconds: 3600 - Math.floor(Date.now() / 1000) % 3600 };
  } else {
    outcome = await issueEmailOtp(env, target, code => sendMail(env, email, 'verificationCode', { code, reason: 'email-change' }));
  }
  const check = mailStatusCheck(outcome);
  return check.ok ? new Response(null, { status: 200 }) : errorResponse(check.message, check.status, check.headers);
}

export async function handleChangeEmail(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, MasterPasswordFields.extend({
    masterPasswordHash: text, newEmail: emailAddress('Invalid email address'), token: text, ...unchangedKdf(user, 'email'),
  }));
  if (body instanceof Response) return body;
  const auth = new AuthService(env);
  if (!await verifyUserSecret(auth, user, body.masterPasswordHash)) return errorResponse('Invalid password.', 400, {}, { MasterPasswordHash: ['Invalid password.'] });
  const email = body.newEmail;
  const update = masterPasswordUpdate(body, { ...user, email });
  if (update instanceof Response) return update;
  if (!await redeemEmailOtp(env, { purpose: 'email-change', subject: user.id, binding: `${user.securityStamp}:${email}` }, body.token)) return errorResponse('Invalid token.', 400);
  const passwordHash = await auth.hashPasswordServer(update.masterPasswordHash, email);
  const stamp = generateUUID();
  const now = new Date().toISOString();
  const guard = sql`EXISTS (SELECT 1 FROM users WHERE id = ${user.id} AND security_stamp = ${stamp})`;
  const event = auditEventStatement(env.DB, {
    actorUserId: user.id, action: 'user.email.change', category: 'security', level: 'security',
    targetType: 'user', targetId: user.id, metadata: auditRequestMetadata(request),
  }, guard).toSQL();
  let result: D1Result[];
  try {
    result = await env.DB.batch([
      env.DB.prepare("UPDATE users SET email = ?, email_verified = 1, master_password_hash = ?, key = ?, security_stamp = ?, updated_at = ? WHERE id = ? AND security_stamp = ? AND status = 'active'")
        .bind(email, passwordHash, update.key, stamp, now, user.id, user.securityStamp),
      credentialAccountStatement(env.DB, user.id, passwordHash, stamp),
      env.DB.prepare('DELETE FROM session WHERE user_id = ? AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)').bind(user.id, user.id, stamp),
      env.DB.prepare('INSERT INTO user_revisions (user_id, revision_date) SELECT ?, ? WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?) ON CONFLICT(user_id) DO UPDATE SET revision_date = excluded.revision_date').bind(user.id, now, user.id, stamp),
      env.DB.prepare(event.sql).bind(...event.params),
    ]);
  } catch (error) {
    if (error instanceof Error && /UNIQUE constraint failed: users\.email/i.test(error.message)) return errorResponse('Email already in use.', 400);
    throw error;
  }
  if (!result[0].meta.changes) return errorResponse('User verification failed.', 400);
  AuthService.invalidateUserCache(user.id);
  notifyUserLogout(env, user.id, null);
  notifyMail(env, user.email, 'emailChanged', { utc: now, ip: getClientIdentifier(request) ?? 'Unknown' });
  await syncVaultAdminRoles(env);
  return new Response(null, { status: 200 });
}

export async function handleDeleteRecover(request: Request, env: Env): Promise<Response> {
  const body = await readRequestBody(request, z.object({ email: emailAddress('Invalid email address') }));
  if (body instanceof Response) return body;
  const { email } = body;
  const clientId = getClientIdentifier(request);
  if (!clientId) return errorResponse('Client IP is required', 403);
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(`delete-recover:${clientId}`, LIMITS.rateLimit.deleteRecoverPerIpPerHour, 3600);
  if (!budget.allowed) return errorResponse('Too many requests', 429, { 'Retry-After': String(budget.retryAfterSeconds ?? 3600) });
  const origin = configuredVaultOrigin(request, env);
  if (readMailConfig(env).kind !== 'enabled' || !origin) return errorResponse('Email sending is not configured', 503);
  runInBackground('delete-recover', async () => {
    const user = await userRepo.getUser(env.DB, email);
    if (!user || user.status !== 'active') return;
    const token = await createDeleteRecoverToken(env, user);
    const params = new URLSearchParams({ userId: user.id, token, email: user.email });
    await sendMail(env, user.email, 'verifyDelete', { url: toSafeUrl(new URL(`${origin}/#/verify-recover-delete?${params}`)) });
  });
  return jsonResponse('');
}

export async function handleDeleteRecoverToken(request: Request, env: Env): Promise<Response> {
  const invalid = () => errorResponse('Invalid token.', 400);
  const body = await readRequestBody(request, z.object({ userId: text, token: text }));
  if (body instanceof Response) return invalid();
  const user = body.userId ? await userRepo.getUserById(env.DB, body.userId) : null;
  if (!user || user.status !== 'active' || !await verifyDeleteRecoverToken(env, user, body.token)) return invalid();
  const result = await deleteUserAccount(env, user.id, {
    actorUserId: null, action: 'user.account.delete_recover', category: 'security', level: 'security',
    targetType: 'user', targetId: user.id, metadata: auditRequestMetadata(request),
  }, user.securityStamp);
  if (result.kind === 'not-found') return invalid();
  if (result.kind === 'blocked-by-orgs') return errorResponse('You cannot delete this member because they are the sole owner of at least one organization vault. Delete these organization vaults or make another member an owner.', 400);
  if (result.kind === 'last-vault-admin') return errorResponse('You cannot delete the last instance administrator.', 400);
  notifyUserLogout(env, user.id, null);
  return new Response(null, { status: 200 });
}

// GET /api/accounts/profile
export async function handleGetProfile(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(await buildProfileResponse(user, env));
}

// PUT /api/accounts/profile
export async function handleUpdateProfile(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await parseBody(request, z.object({ masterPasswordHint: MasterPasswordHint }));
  if (body instanceof Response) return body;

  user.masterPasswordHint = body.masterPasswordHint;
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, ['masterPasswordHint'])) return errorResponse('User verification failed.', 400);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: 'account.profile.update',
    category: 'security',
    level: 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedMasterPasswordHint: true,
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(await buildProfileResponse(user, env));
}

// PUT/POST /api/accounts/verify-devices
// Preferences are editable while opt-in new-device verification is active.
export async function handleSetVerifyDevices(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const mail = readMailConfig(env);
  if (mail.kind !== 'enabled' || !mail.newDeviceVerification) return errorResponse('New device verification is not available on this server. Enable TOTP or WebAuthn two-factor authentication instead.', 400);
  const body = await readRequestBody(request, VerifiedBody.extend({ verifyDevices: z.boolean({ error: 'verifyDevices must be true or false' }) }));
  if (body instanceof Response) return body;
  if (!await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash)) return errorResponse('User verification failed.', 400);
  const { verifyDevices } = body;
  user.verifyDevices = verifyDevices;
  if (!await userRepo.saveUser(env.DB, user, ['verifyDevices'])) return errorResponse('User verification failed.', 400);
  await revisionRepo.updateRevisionDate(env.DB, user.id);
  AuthService.invalidateUserCache(user.id);
  await writeAuditEvent(env.DB, { actorUserId: user.id, action: 'account.verify_devices.update', category: 'security', level: 'security', targetType: 'user', targetId: user.id, metadata: { verifyDevices, ...auditRequestMetadata(request) } });
  return new Response(null, { status: 200 });
}

export async function handleResendNewDeviceOtp(request: Request, env: Env): Promise<Response> {
  const mail = readMailConfig(env);
  if (mail.kind === 'disabled') return unsupportedResponse('Email delivery is not supported by this server.');
  if (mail.kind === 'misconfigured') return errorResponse('Email sending is not configured', 503);
  const body = await readRequestBody(request, VerifiedBody.extend({ email: z.string().trim().toLowerCase().catch(''), deviceType: text }));
  if (body instanceof Response) return body;
  if (mail.newDeviceVerification) runInBackground('new-device-resend', async () => {
    const user = body.email ? await userRepo.getUser(env.DB, body.email) : null;
    if (!user || user.status !== 'active' || !user.verifyDevices
      || !(Date.now() - Date.parse(user.createdAt) >= LIMITS.auth.newDeviceVerificationMinAccountAgeSeconds * 1000)) return;
    if (!await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash)) return;
    const hasPasskey = await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor') > 0;
    if (twoFactorProviders(user, hasPasskey).length || !await env.DB.prepare('SELECT 1 FROM devices WHERE user_id = ? LIMIT 1').bind(user.id).first()) return;
    const device = readAuthRequestDeviceInfo({ deviceType: body.deviceType }, request);
    notifyNewDeviceVerification(env, request, user, device.deviceType);
  });
  return jsonResponse('');
}

// GET /api/accounts/keys
export async function handleGetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const user = await userRepo.getUserById(env.DB, userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  return jsonResponse(keysResponse(user));
}

// GET /api/users/{id}/public-key: upstream UsersController.GetPublicKeyAsync. Official clients
// wrap keys for another account (emergency access and org member confirm) with it, so any
// logged-in caller may read it.
export async function handleGetUserPublicKey(env: Env, id: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, id);
  if (!user?.publicKey) return errorResponse('Resource not found.', 404);
  return jsonResponse({ userId: user.id, publicKey: user.publicKey, object: 'userKey' });
}

// POST /api/accounts/keys
export async function handleSetKeys(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  const body = await parseBody(request, z.object({ masterPasswordHash: text, key: text, encryptedPrivateKey: text, publicKey: text }));

  if (body instanceof Response) return body;

  // Require password verification before allowing key replacement.
  if (!body.masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const passwordValid = await auth.verifyPassword(body.masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  if (body.key && !looksLikeEncString(body.key)) {
    return errorResponse('key is not a valid encrypted string', 400);
  }
  if (body.encryptedPrivateKey && !looksLikeEncString(body.encryptedPrivateKey)) {
    return errorResponse('encryptedPrivateKey is not a valid encrypted string', 400);
  }

  if (body.key) user.key = body.key;
  if (body.encryptedPrivateKey) user.privateKey = body.encryptedPrivateKey;
  if (body.publicKey) user.publicKey = body.publicKey;
  user.updatedAt = new Date().toISOString();

  if (!await userRepo.saveUser(env.DB, user, [
    ...(body.key ? ['key' as const] : []),
    ...(body.encryptedPrivateKey ? ['privateKey' as const] : []),
    ...(body.publicKey ? ['publicKey' as const] : []),
  ])) return errorResponse('User verification failed.', 400);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: 'account.keys.update',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: {
      updatedKey: !!body.key,
      updatedPrivateKey: !!body.encryptedPrivateKey,
      updatedPublicKey: !!body.publicKey,
      ...auditRequestMetadata(request),
    },
  });

  return jsonResponse(keysResponse(user));
}

// POST/PUT /api/accounts/password
export async function handleChangePassword(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await parseBody(request, MasterPasswordFields.extend({
    masterPasswordHash: text,
    currentPasswordHash: text,
    masterPasswordHint: MasterPasswordHint.optional(),
    encryptedPrivateKey: text,
    newEncryptedPrivateKey: text,
    publicKey: text,
    newPublicKey: text,
    ...unchangedKdf(user, 'password'),
  }));

  if (body instanceof Response) return body;

  const currentHash = body.currentPasswordHash || body.masterPasswordHash;
  if (!currentHash) return errorResponse('Current password hash is required', 400);
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  const update = masterPasswordUpdate(body, user);
  if (update instanceof Response) return update;

  const nextPrivateKey = body.newEncryptedPrivateKey || body.encryptedPrivateKey;
  const nextPublicKey = body.newPublicKey || body.publicKey;
  if (nextPrivateKey && !looksLikeEncString(nextPrivateKey)) {
    return errorResponse('new encryptedPrivateKey is not a valid encrypted string', 400);
  }
  const shouldUpdateHint = 'masterPasswordHint' in body;

  user.masterPasswordHash = await auth.hashPasswordServer(update.masterPasswordHash, user.email);
  user.key = update.key;
  if (nextPrivateKey) user.privateKey = nextPrivateKey;
  if (nextPublicKey) user.publicKey = nextPublicKey;
  if (shouldUpdateHint) {
    user.masterPasswordHint = body.masterPasswordHint ?? null;
  }
  const originalSecurityStamp = user.securityStamp;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, [
    'masterPasswordHash', 'key', 'securityStamp',
    ...(nextPrivateKey ? ['privateKey' as const] : []),
    ...(nextPublicKey ? ['publicKey' as const] : []),
    ...(shouldUpdateHint ? ['masterPasswordHint' as const] : []),
  ], originalSecurityStamp)) return errorResponse('User verification failed.', 400);
  AuthService.invalidateUserCache(user.id);
  if (!await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash, user.securityStamp)) return errorResponse('User verification failed.', 400);
  await sessionRepo.deleteRefreshTokensByUserId(env.DB, user.id);
  await recordUserEvent(env, request, user.id, EventType.UserChangedPassword);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: 'user.password.change',
    targetType: 'user',
    targetId: user.id,
    category: 'security',
    level: 'security',
    metadata: { email: user.email, ...auditRequestMetadata(request) },
  });

  return new Response(null, { status: 200 });
}

function twoFactorProviderResponse(type: number, enabled: boolean): Record<string, unknown> {
  return {
    Enabled: enabled,
    Type: type,
    Object: 'twoFactorProvider',
  };
}

function twoFactorAuthenticatorResponse(
  enabled: boolean,
  key: string,
  userVerificationToken?: string
): Record<string, unknown> {
  return {
    Enabled: enabled,
    Key: key,
    UserVerificationToken: userVerificationToken ?? null,
    Authenticator: { Enabled: enabled, Key: key },
    Object: userVerificationToken ? 'twoFactorAuthenticator' : 'twoFactorAuthenticatorUpdate',
  };
}

function yubiKeyResponse(user: User): Record<string, unknown> {
  const provider = {
    Enabled: isYubiKeyEnabled(user),
    Key1: user.yubikeyKey1,
    Key2: user.yubikeyKey2,
    Key3: user.yubikeyKey3,
    Key4: user.yubikeyKey4,
    Key5: user.yubikeyKey5,
    Nfc: !!user.yubikeyNfc,
  };
  return { ...provider, YubiKey: provider, Object: 'twoFactorYubiKey' };
}

// This obsolete two-factor surface stays disabled; /accounts/verify-devices owns the preference.
function deviceVerificationSettingsResponse(): Record<string, unknown> {
  return { isDeviceVerificationSectionEnabled: false, unknownDeviceVerificationEnabled: false, object: 'deviceVerificationSettings' };
}

async function yubiKeySettingsResponse(env: Env, user: User): Promise<Record<string, unknown>> {
  const credentials = await getYubicoCredentials(env.DB);
  const canManageCredentials = user.role === 'admin' && user.status === 'active';
  return {
    ...yubiKeyResponse(user),
    YubicoConfigured: !!credentials?.clientId,
    YubicoCanManage: canManageCredentials,
    ...(canManageCredentials
      ? {
          YubicoClientId: credentials?.clientId ?? '',
          YubicoSecretKey: credentials?.secretKey ?? '',
        }
      : {}),
  };
}

// GET /api/two-factor
export async function handleGetTwoFactorProviders(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const hasTwoFactorPasskey = await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor') > 0;
  const data = twoFactorProviders(user, hasTwoFactorPasskey).map(type => twoFactorProviderResponse(type, true));

  return jsonResponse({
    Data: data,
    ContinuationToken: null,
    Object: 'list',
  });
}

// POST /api/two-factor/get-authenticator
export async function handleGetTwoFactorAuthenticator(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, VerifiedBody);
  if (body instanceof Response) return body;

  const verified = await verifyUserSecret(auth, user, verificationSecret(body));
  if (!verified) return errorResponse('User verification failed.', 400);

  const key = normalizeTotpSecret(user.totpSecret || '') || new Secret().base32;
  const userVerificationToken = await createTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_AUTHENTICATOR, key);
  return jsonResponse(twoFactorAuthenticatorResponse(!!user.totpSecret, key, userVerificationToken));
}

// POST /api/two-factor/get-yubikey
export async function handleGetTwoFactorYubiKey(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, VerifiedBody);
  if (body instanceof Response) return body;

  const verified = await verifyUserSecret(auth, user, verificationSecret(body));
  if (!verified) return errorResponse('User verification failed.', 400);

  return jsonResponse({
    ...await yubiKeySettingsResponse(env, user),
    UserVerificationToken: await createTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_YUBIKEY),
  });
}

// Upstream binds this model case-insensitively, so keys are compared lower-cased.
const optionalText = z.string().nullish().transform((value) => value?.trim() ?? '');
const TwoFactorEmailLoginBody = z.preprocess(
  (body) => Object.fromEntries(Object.entries(body ?? {}).map(([name, value]) => [name.toLowerCase(), value])),
  z.object({
    email: optionalText,
    authrequestid: optionalText,
    authrequestaccesscode: optionalText,
    ssoemail2fasessiontoken: optionalText,
    masterpasswordhash: optionalText,
    devicetype: text,
  }),
);

export async function handleSendTwoFactorEmailLogin(request: Request, env: Env): Promise<Response> {
  const rejected = () => errorResponse('Cannot send two-factor email.', 400);
  const body = await readRequestBody(request, TwoFactorEmailLoginBody);
  if (body instanceof Response) return rejected();
  const email = body.email.toLowerCase();
  const user = email ? await userRepo.getUser(env.DB, email) : null;
  if (!user || user.status !== 'active' || !user.twoFactorEmail) return rejected();
  const accessCode = body.authrequestaccesscode;
  const sessionToken = body.ssoemail2fasessiontoken;
  let verified: boolean;
  if (accessCode) {
    const authRequest = await authRequestRepo.getAuthRequestByIdForUser(env.DB, body.authrequestid, user.id);
    verified = isAuthRequestLoginApproved(authRequest, user.id, accessCode);
  } else if (sessionToken) {
    verified = await verifySsoEmail2faSessionToken(env, user, sessionToken);
  } else {
    verified = await verifyUserSecret(new AuthService(env), user, body.masterpasswordhash);
  }
  if (!verified) return rejected();
  if (readMailConfig(env).kind !== 'enabled') return errorResponse('Email sending is not configured', 503);
  const device = readAuthRequestDeviceInfo({ deviceType: body.devicetype }, request);
  const outcome = await issueEmailOtp(env, { purpose: 'two-factor-login', subject: user.id, binding: user.securityStamp },
    code => sendMail(env, user.twoFactorEmail!, 'signInCode', { code, reason: 'two-factor', ip: getClientIdentifier(request) ?? 'Unknown', deviceTypeName: deviceTypeName(device.deviceType), utc: new Date().toISOString() }));
  const check = mailStatusCheck(outcome);
  return check.ok ? new Response(null, { status: 200 }) : errorResponse(check.message, check.status, check.headers);
}

function twoFactorEmailResponse(email: string | null, userVerificationToken?: string): Record<string, unknown> {
  return {
    Email: { Enabled: !!email, Email: email },
    ...(userVerificationToken ? { UserVerificationToken: userVerificationToken } : {}),
    Object: userVerificationToken ? 'twoFactorEmail' : 'twoFactorEmailUpdate',
  };
}

const EmailTwoFactorBody = VerifiedBody.extend({ userVerificationToken: text, email: emailAddress('Invalid email address'), token: text });

async function verifyEmailTwoFactorUser(env: Env, user: User, body: z.output<typeof EmailTwoFactorBody>): Promise<boolean> {
  return await verifyTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_EMAIL, body.userVerificationToken)
    || await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash || body.secret);
}

export async function handleGetTwoFactorEmail(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, VerifiedBody);
  if (body instanceof Response) return body;
  if (!await verifyUserSecret(new AuthService(env), user, body.masterPasswordHash || body.secret)) return errorResponse('User verification failed.', 400);
  return jsonResponse(twoFactorEmailResponse(user.twoFactorEmail, await createTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_EMAIL)));
}

export async function handleSendTwoFactorEmail(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, EmailTwoFactorBody);
  if (body instanceof Response) return body;
  if (!await verifyEmailTwoFactorUser(env, user, body)) return errorResponse('User verification failed.', 400);
  const { email } = body;
  if (readMailConfig(env).kind !== 'enabled') return errorResponse('Email sending is not configured', 503);
  const outcome = await issueEmailOtp(env, { purpose: 'two-factor-setup', subject: user.id, binding: `${user.securityStamp}:${email}` },
    code => sendMail(env, email, 'verificationCode', { code, reason: 'two-factor-setup' }));
  const check = mailStatusCheck(outcome);
  if (!check.ok) return errorResponse(check.message, check.status, check.headers);
  return new Response(null, { status: 200 });
}

export async function handlePutTwoFactorEmail(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  const body = await readRequestBody(request, EmailTwoFactorBody);
  if (body instanceof Response) return body;
  if (!await verifyEmailTwoFactorUser(env, user, body)) return errorResponse('User verification failed.', 400);
  const { email } = body;
  if (!await redeemEmailOtp(env, { purpose: 'two-factor-setup', subject: user.id, binding: `${user.securityStamp}:${email}` }, body.token)) {
    return errorResponse('Invalid token.', 400, {}, { Token: ['Invalid token.'] });
  }
  const changed = await env.DB.prepare("UPDATE users SET two_factor_email = ?, totp_recovery_code = COALESCE(NULLIF(totp_recovery_code, ''), ?), updated_at = ? WHERE id = ? AND security_stamp = ? RETURNING id")
    .bind(email, createRecoveryCode(), new Date().toISOString(), user.id, user.securityStamp).first();
  if (!changed) return errorResponse('User verification failed.', 400);
  await revisionRepo.updateRevisionDate(env.DB, user.id);
  AuthService.invalidateUserCache(user.id);
  if (user.twoFactorEmail !== email) await recordUserEvent(env, request, user.id, EventType.UserUpdated2fa);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id, action: 'account.two_factor.email.enable', category: 'security', level: 'security',
    targetType: 'user', targetId: user.id, metadata: auditRequestMetadata(request),
  });
  return jsonResponse(twoFactorEmailResponse(email));
}

// POST /api/two-factor/get-device-verification-settings
export async function handleGetDeviceVerificationSettings(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  return jsonResponse(deviceVerificationSettingsResponse());
}

// Obsolete upstream compatibility route; the real account preference is separate.
export async function handlePutDeviceVerificationSettings(request: Request, env: Env, userId: string): Promise<Response> {
  return handleGetDeviceVerificationSettings(request, env, userId);
}

// PUT/POST /api/two-factor/authenticator
// Every factor change revokes refresh tokens and cached auth state, then records the event and audit row.
async function finalizeTwoFactorChange(request: Request, env: Env, user: User, action: string, eventType: number | null): Promise<void> {
  await sessionRepo.deleteRefreshTokensByUserId(env.DB, user.id);
  AuthService.invalidateUserCache(user.id);
  if (eventType) await recordUserEvent(env, request, user.id, eventType);
  await writeAuditEvent(env.DB, {
    actorUserId: user.id, action, category: 'security', level: 'security', targetType: 'user', targetId: user.id,
    metadata: auditRequestMetadata(request),
  });
}

export async function handlePutTwoFactorAuthenticator(request: Request, env: Env, userId: string): Promise<Response> {
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, z.object({ key: text, token: trimmed, userVerificationToken: text }));
  if (body instanceof Response) return body;

  const key = normalizeTotpSecret(body.key);
  const { token, userVerificationToken } = body;
  if (!key || !token || !userVerificationToken) {
    return errorResponse('Key, token and userVerificationToken are required', 400);
  }
  if (!await verifyTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_AUTHENTICATOR, userVerificationToken, key)) {
    return errorResponse('User verification failed.', 400);
  }
  if (!isTotpEnabled(key)) return errorResponse('Invalid TOTP secret', 400);
  const matchedCounter = await findMatchingTotpCounter(key, token);
  if (matchedCounter == null || !await totpReplayRepo.consumeTotpLoginCounter(env.DB, user.id, matchedCounter)) {
    return errorResponse('Invalid token.', 400);
  }

  const factorChanged = user.totpSecret !== key;
  user.totpSecret = key;
  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse('User verification failed.', 400);
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, ['totpSecret'])) return errorResponse('User verification failed.', 400);
  await finalizeTwoFactorChange(request, env, user, 'account.totp.enable', factorChanged ? EventType.UserUpdated2fa : null);

  return jsonResponse(twoFactorAuthenticatorResponse(true, key));
}

// PUT/POST /api/two-factor/yubikey
export async function handlePutTwoFactorYubiKey(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, VerifiedBody.extend({
    userVerificationToken: text, key1: text, key2: text, key3: text, key4: text, key5: text, nfc: z.unknown().optional(),
  }));
  if (body instanceof Response) return body;

  const verified = await verifyTwoFactorUserVerificationToken(env, user, TWO_FACTOR_PROVIDER_YUBIKEY, body.userVerificationToken)
    || await verifyUserSecret(auth, user, verificationSecret(body));
  if (!verified) return errorResponse('User verification failed.', 400);

  const keys = [body.key1, body.key2, body.key3, body.key4, body.key5];
  const publicIds: Array<string | null> = [];
  let credentials = await getYubicoCredentials(env.DB);
  let apiKeyBootstrapOtpIndex: number | null = null;
  for (const key of keys) {
    const trimmed = key.trim();
    if (!trimmed) {
      publicIds.push(null);
      continue;
    }
    const publicId = yubiKeyPublicIdFromOtp(trimmed);
    if (!publicId) return errorResponse('Invalid YubiKey OTP.', 400);
    if (isYubiKeyPublicId(trimmed)) {
      publicIds.push(publicId);
      continue;
    }
    if (!credentials) {
      const initialized = await initializeYubicoCredentialsOnce(env.DB, user.email, trimmed);
      if (!initialized) return errorResponse('Unable to initialize Yubico validation credentials.', 400);
      credentials = initialized.credentials;
      if (initialized.created) apiKeyBootstrapOtpIndex = publicIds.length;
    }
    if (apiKeyBootstrapOtpIndex !== publicIds.length && !await verifyYubicoOtp(env, trimmed, credentials)) {
      return errorResponse('Invalid YubiKey OTP.', 400);
    }
    publicIds.push(publicId);
  }
  if (!publicIds.some(Boolean)) return errorResponse('At least one YubiKey OTP is required.', 400);

  const factorChanged = [user.yubikeyKey1, user.yubikeyKey2, user.yubikeyKey3, user.yubikeyKey4, user.yubikeyKey5].some((key, index) => key !== (publicIds[index] ?? null)) || user.yubikeyNfc !== !!(body.nfc);
  user.yubikeyKey1 = publicIds[0] ?? null;
  user.yubikeyKey2 = publicIds[1] ?? null;
  user.yubikeyKey3 = publicIds[2] ?? null;
  user.yubikeyKey4 = publicIds[3] ?? null;
  user.yubikeyKey5 = publicIds[4] ?? null;
  user.yubikeyNfc = !!(body.nfc);
  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse('User verification failed.', 400);
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, ['yubikeyKey1', 'yubikeyKey2', 'yubikeyKey3', 'yubikeyKey4', 'yubikeyKey5', 'yubikeyNfc'])) return errorResponse('User verification failed.', 400);
  await finalizeTwoFactorChange(request, env, user, 'account.yubikey.enable', factorChanged ? EventType.UserUpdated2fa : null);

  return jsonResponse({ ...await yubiKeySettingsResponse(env, user), Object: 'twoFactorYubiKeyUpdate' });
}

// PUT/POST /api/two-factor/yubikey/config
export async function handlePutTwoFactorYubiKeyConfig(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);
  if (user.role !== 'admin' || user.status !== 'active') return errorResponse('Forbidden', 403);

  const body = await readRequestBody(request, VerifiedBody.extend({ yubicoClientId: trimmed, clientId: trimmed, yubicoSecretKey: trimmed, secretKey: trimmed }));
  if (body instanceof Response) return body;

  const verified = await verifyUserSecret(auth, user, verificationSecret(body));
  if (!verified) return errorResponse('User verification failed.', 400);

  const clientId = body.yubicoClientId || body.clientId;
  const secretKey = body.yubicoSecretKey || body.secretKey;
  if (!clientId || !secretKey) return errorResponse('Yubico Client ID and Secret Key are required.', 400);

  await replaceYubicoCredentials(env.DB, { clientId, secretKey });
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: 'system.yubico.credentials.update',
    category: 'security',
    level: 'security',
    targetType: 'system',
    targetId: 'yubico',
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse(await yubiKeySettingsResponse(env, user));
}

// POST /api/two-factor/yubikey/bootstrap
export async function handleBootstrapTwoFactorYubiKeyConfig(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, VerifiedBody.extend({ token: text }));
  if (body instanceof Response) return body;

  const verified = await verifyUserSecret(auth, user, body.masterPasswordHash || body.secret);
  if (!verified) return errorResponse('User verification failed.', 400);

  const otp = (body.otp || body.OTP || body.token).trim();
  if (!yubiKeyPublicIdFromOtp(otp)) return errorResponse('Invalid YubiKey OTP.', 400);
  const existing = await getYubicoCredentials(env.DB);
  if (user.role !== 'admin' && existing) {
    return errorResponse('Yubico validation credentials are already configured.', 403);
  }

  let credentials;
  if (user.role === 'admin') {
    credentials = await requestYubicoApiCredentials(user.email, otp);
    if (!credentials?.clientId || !credentials.secretKey) {
      return errorResponse('Unable to initialize Yubico validation credentials.', 400);
    }
    await replaceYubicoCredentials(env.DB, credentials);
  } else {
    const initialized = await initializeYubicoCredentialsOnce(env.DB, user.email, otp);
    if (!initialized?.created) {
      return errorResponse(
        initialized?.credentials
          ? 'Yubico validation credentials are already configured.'
          : 'Unable to initialize Yubico validation credentials.',
        initialized?.credentials ? 403 : 400
      );
    }
    credentials = initialized.credentials;
  }

  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: user.role === 'admin'
      ? 'system.yubico.credentials.reconfigure'
      : 'system.yubico.credentials.initialize',
    category: 'security',
    level: 'security',
    targetType: 'system',
    targetId: 'yubico',
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse(await yubiKeySettingsResponse(env, user));
}

// DELETE /api/two-factor/authenticator and PUT/POST /api/two-factor/disable
export async function handleDisableTwoFactorProvider(request: Request, env: Env, userId: string, routeType?: number): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await readRequestBody(request, VerifiedBody.extend({ type: z.unknown().optional(), userVerificationToken: text, key: text }));
  if (body instanceof Response) return body;

  const typeRaw = routeType ?? body.type ?? TWO_FACTOR_PROVIDER_AUTHENTICATOR;
  const type = typeof typeRaw === 'number' ? typeRaw : Number.parseInt(String(typeRaw), 10);
  if (![TWO_FACTOR_PROVIDER_AUTHENTICATOR, TWO_FACTOR_PROVIDER_EMAIL, TWO_FACTOR_PROVIDER_YUBIKEY, TWO_FACTOR_PROVIDER_WEBAUTHN].includes(type)) {
    return errorResponse('Two-factor provider is not supported by this server.', 400);
  }

  const verified = (routeType !== undefined && await verifyTwoFactorUserVerificationToken(env, user, type, body.userVerificationToken, normalizeTotpSecret(body.key)))
    || await verifyUserSecret(auth, user, verificationSecret(body));
  if (!verified) return errorResponse('User verification failed.', 400);

  const wasEnabled = twoFactorProviders(user, type === TWO_FACTOR_PROVIDER_WEBAUTHN && await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor') > 0).some(provider => provider === type);
  if (type === TWO_FACTOR_PROVIDER_AUTHENTICATOR) {
    user.totpSecret = null;
  } else if (type === TWO_FACTOR_PROVIDER_YUBIKEY) {
    user.yubikeyKey1 = null;
    user.yubikeyKey2 = null;
    user.yubikeyKey3 = null;
    user.yubikeyKey4 = null;
    user.yubikeyKey5 = null;
    user.yubikeyNfc = false;
  }
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, type === TWO_FACTOR_PROVIDER_AUTHENTICATOR ? ['totpSecret']
    : type === TWO_FACTOR_PROVIDER_YUBIKEY ? ['yubikeyKey1', 'yubikeyKey2', 'yubikeyKey3', 'yubikeyKey4', 'yubikeyKey5', 'yubikeyNfc'] : [])) return errorResponse('User verification failed.', 400);
  if (type === TWO_FACTOR_PROVIDER_EMAIL) {
    const updated = await env.DB.prepare('UPDATE users SET two_factor_email = NULL WHERE id = ? AND security_stamp = ? RETURNING id').bind(user.id, user.securityStamp).first();
    if (!updated) return errorResponse('User verification failed.', 400);
  }
  if (type === TWO_FACTOR_PROVIDER_WEBAUTHN) {
    await env.DB.prepare("DELETE FROM webauthn_credentials WHERE user_id = ? AND purpose = 'twoFactor' AND EXISTS (SELECT 1 FROM users WHERE id = ? AND security_stamp = ?)").bind(user.id, user.id, user.securityStamp).run();
  }
  await finalizeTwoFactorChange(request, env, user, type === TWO_FACTOR_PROVIDER_AUTHENTICATOR ? 'account.totp.disable' : type === TWO_FACTOR_PROVIDER_EMAIL ? 'account.two_factor.email.disable' : type === TWO_FACTOR_PROVIDER_YUBIKEY ? 'account.yubikey.disable' : 'account.webauthn_2fa.disable', wasEnabled ? EventType.UserDisabled2fa : null);

  await revisionRepo.updateRevisionDate(env.DB, user.id);
  return routeType === undefined ? jsonResponse(twoFactorProviderResponse(type, false)) : new Response(null, { status: 204 });
}

// POST /api/two-factor/get-recover
export async function handleGetTotpRecoveryCode(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const currentHash = await readRequestBody(request, CurrentPasswordHash);
  if (currentHash instanceof Response) return currentHash;
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  user.totpRecoveryCode = await ensureTwoFactorRecoveryCode(env.DB, user.id, user.securityStamp);
  if (!user.totpRecoveryCode) return errorResponse('User verification failed.', 400);

  return jsonResponse({
    Code: user.totpRecoveryCode,
    code: user.totpRecoveryCode,
    Object: 'twoFactorRecover',
    object: 'twoFactorRecover',
  });
}

// Recovery posts the login form's field names or the API model's; codes compare as upper-case base32.
const RecoverTwoFactorBody = z.object({
  email: text, username: text, masterPasswordHash: text, password: text, recoveryCode: text, twoFactorToken: text, recovery_code: text,
}).transform((body) => ({
  email: (body.email || body.username).trim().toLowerCase(),
  masterPasswordHash: (body.masterPasswordHash || body.password).trim(),
  recoveryCode: (body.recoveryCode || body.twoFactorToken || body.recovery_code).toUpperCase().replace(/[^A-Z2-7]/g, ''),
}));

// POST /identity/accounts/recover-2fa
// Disable TOTP by recovery code + password, then rotate recovery code.
export async function handleRecoverTwoFactor(request: Request, env: Env): Promise<Response> {
  const auth = new AuthService(env);
  const rateLimit = new RateLimitService(env);

  const body = await readRequestBody(request, RecoverTwoFactorBody);
  if (body instanceof Response) return body;
  const { email, masterPasswordHash, recoveryCode } = body;
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) {
    return errorResponse('Client IP is required', 403);
  }
  const recoverLimitKey = `${clientIdentifier}:recover-2fa`;

  const recoverAttemptCheck = await rateLimit.checkLoginAttempt(recoverLimitKey);
  if (!recoverAttemptCheck.allowed) {
    return errorResponse(
      `Too many failed recovery attempts. Try again in ${Math.ceil((recoverAttemptCheck.retryAfterSeconds || 60) / 60)} minutes.`,
      429
    );
  }

  if (!email || !masterPasswordHash || !recoveryCode) {
    return errorResponse('Email, masterPasswordHash and recoveryCode are required', 400);
  }

  const user = await userRepo.getUser(env.DB, email);
  if (!user || user.status !== 'active') {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  const validPassword = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!validPassword) {
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  if (!recoveryCodeEquals(recoveryCode, user.totpRecoveryCode)) {
    notifyFailedTwoFactor(env, request, user, 8);
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }

  const nextRecoveryCode = createRecoveryCode();
  const [cleared] = await env.DB.batch(twoFactorClearStatements(env.DB, user.id, {
    recoveryCode: nextRecoveryCode,
    securityStamp: generateUUID(),
  }, user));
  if (!cleared.meta.changes) {
    notifyFailedTwoFactor(env, request, user, 8);
    await rateLimit.recordFailedLogin(recoverLimitKey);
    return errorResponse('Invalid credentials or recovery code', 400);
  }
  AuthService.invalidateUserCache(user.id);
  await recordUserEvent(env, request, user.id, EventType.UserRecovered2fa);
  notifyMail(env, user.email, 'twoFactorRecovered', { time: new Date().toISOString(), ip: getClientIdentifier(request) ?? 'Unknown' });
  await rateLimit.clearLoginAttempts(recoverLimitKey);
  await safeWriteAuditEvent(env, {
    actorUserId: user.id,
    action: 'account.totp.recover',
    category: 'security',
    level: 'security',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    success: true,
    twoFactorEnabled: false,
    newRecoveryCode: nextRecoveryCode,
    object: 'twoFactorRecovery',
  });
}

// GET /api/accounts/revision-date
export async function handleGetRevisionDate(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const revisionDate = await revisionRepo.getRevisionDate(env.DB, userId);

  // Return as milliseconds timestamp (Bitwarden format)
  const timestamp = new Date(revisionDate).getTime();
  return jsonResponse(timestamp);
}

// Upstream KeyId: exactly 16 bytes as lowercase hex. The SDK rejects a whole sync whose
// UserKeyId is malformed, so uppercase is refused rather than normalized.
const USER_KEY_ID_PATTERN = /^[0-9a-f]{32}$/;
const UserKeyIdBody = z.object({
  userKeyId: z.string({ error: (issue) => issue.input == null ? 'The UserKeyId field is required.' : 'UserKeyId is not a valid key id.' })
    .min(1, { error: 'The UserKeyId field is required.', abort: true })
    .regex(USER_KEY_ID_PATTERN, { error: 'UserKeyId is not a valid key id.' }),
});

// POST /api/accounts/key-management/user-key-id
// 2026.9 clients report their user key id once, then clear it and re-post on every unlock
// unless /api/sync echoes it. The revision bump is what evicts the cached pre-backfill sync.
export async function handleSetUserKeyId(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, UserKeyIdBody);
  if (body instanceof Response) return body;

  if (!await userRepo.setUserKeyIdIfUnset(env.DB, userId, body.userKeyId)) {
    return errorResponse('User key id is already set.', 400);
  }
  await revisionRepo.updateRevisionDate(env.DB, userId);
  return new Response(null, { status: 200 });
}

// POST /api/accounts/verify-password
export async function handleVerifyPassword(request: Request, env: Env, userId: string): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);

  if (!user) {
    return errorResponse('User not found', 404);
  }

  const body = await parseBody(request, MasterPasswordFields.pick({ authenticationData: true }).extend({ masterPasswordHash: text }));
  if (body instanceof Response) return body;

  const masterPasswordHash = body.masterPasswordHash || body.authenticationData?.masterPasswordAuthenticationHash;
  if (!masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }

  const valid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!valid) {
    return errorResponse('Invalid password', 400);
  }

  return jsonResponse(masterPasswordPolicyResponse());
}

// POST /api/accounts/api-key
export async function handleGetApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, false);
}

// POST /api/accounts/rotate-api-key
export async function handleRotateApiKey(request: Request, env: Env, userId: string): Promise<Response> {
  return apiKey(request, env, userId, true);
}

async function apiKey(request: Request, env: Env, userId: string, rotate: boolean): Promise<Response> {
  const auth = new AuthService(env);
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const currentHash = await readRequestBody(request, CurrentPasswordHash);
  if (currentHash instanceof Response) return currentHash;
  const valid = await auth.verifyPassword(currentHash, user.masterPasswordHash, user.email);
  if (!valid) return errorResponse('Invalid password', 400);

  if (!rotate && isStoredApiKeyHash(user.apiKey)) {
    return errorResponse(
      'This API key was created by an older NodeWarden version and cannot be displayed. Rotate it once to use the Bitwarden-compatible readable format.',
      409
    );
  }

  let auditAction = 'account.api_key.view';
  if (rotate || !user.apiKey) {
    user.apiKey = randomStringAlphanum(LIMITS.auth.clientSecretLength);
    user.updatedAt = new Date().toISOString();
    if (!await userRepo.saveUser(env.DB, user, ['apiKey'])) return errorResponse('User verification failed.', 400);
    AuthService.invalidateUserCache(user.id);
    auditAction = rotate ? 'account.api_key.rotate' : 'account.api_key.create';
  }
  await writeAuditEvent(env.DB, {
    actorUserId: user.id,
    action: auditAction,
    category: 'security',
    level: rotate ? 'security' : 'info',
    targetType: 'user',
    targetId: user.id,
    metadata: auditRequestMetadata(request),
  });

  return jsonResponse({
    apiKey: user.apiKey,
    revisionDate: user.updatedAt,
    object: 'apiKey',
  });
}
