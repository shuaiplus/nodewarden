import { sign, verify } from 'hono/jwt';
import type { Env, JWTPayload, User } from '../types';
import type { TwoFactorProviderType } from '../services/two-factor-providers';
import { sha256Base64Url } from './account-passkeys';
import { bytesToBase64Url } from './passkey';
import { LIMITS } from '../config/limits';

// A CryptoKey, not the raw string: hono sniffs string secrets for "PRIVATE"/"PUBLIC" and would
// parse such a JWT_SECRET as a PEM key.
function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function hmacSha256Base64Url(secret: string, data: string): Promise<string> {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret), new TextEncoder().encode(data))));
}

export async function signHs256Jwt(payload: Record<string, unknown>, secret: string): Promise<string> {
  return sign(payload, await hmacKey(secret), 'HS256');
}

// Every token we mint sets iat/nbf to its own "now"; checking them against another isolate's clock
// could only reject fresh tokens on skew, so, as before, exp is the only time claim enforced.
const HS256_VERIFY_OPTIONS = { alg: 'HS256', iat: false, nbf: false } as const;

// The claim type is the caller's promise about what it signed; only our own secret can mint one.
// hono throws on a bad signature, header or exp; callers only need valid or not.
export async function verifyHs256Jwt<T extends object = Record<string, unknown>>(token: string, secret: string): Promise<T | null> {
  return verify(token, await hmacKey(secret), HS256_VERIFY_OPTIONS).then((payload) => payload as T, () => null);
}

const TWO_FACTOR_USER_VERIFICATION_ISSUER = 'nodewarden|two_factor_uv';

export async function createTwoFactorUserVerificationToken(
  env: Env,
  user: User,
  providerType: TwoFactorProviderType,
  totpKey?: string,
): Promise<string> {
  return signHs256Jwt({
    iss: TWO_FACTOR_USER_VERIFICATION_ISSUER,
    sub: user.id,
    ptype: providerType,
    ...(providerType === 0 ? { key: totpKey } : {}),
    sst: await sha256Base64Url(user.securityStamp),
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.twoFactorUserVerificationTtlSeconds,
  }, env.JWT_SECRET);
}

export async function verifyTwoFactorUserVerificationToken(
  env: Env,
  user: User,
  providerType: number,
  token: string,
  totpKey?: string,
): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
  return !!payload
    && payload.iss === TWO_FACTOR_USER_VERIFICATION_ISSUER
    && payload.sub === user.id
    && payload.ptype === providerType
    && typeof payload.exp === 'number' && Number.isFinite(payload.exp)
    && payload.exp > Math.floor(Date.now() / 1000)
    && (providerType !== 0 || (!!totpKey && payload.key === totpKey))
    && payload.sst === await sha256Base64Url(user.securityStamp);
}

const SSO_EMAIL_TWO_FACTOR_ISSUER = 'nodewarden|sso_email_2fa';

export async function createSsoEmail2faSessionToken(env: Env, user: User): Promise<string> {
  return signHs256Jwt({
    iss: SSO_EMAIL_TWO_FACTOR_ISSUER, sub: user.id, email: user.email,
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.ssoEmail2faSessionTtlSeconds,
  }, env.JWT_SECRET);
}

export async function verifySsoEmail2faSessionToken(env: Env, user: User, token: string): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
  return !!payload && payload.iss === SSO_EMAIL_TWO_FACTOR_ISSUER && payload.sub === user.id && payload.email === user.email
    && typeof payload.exp === 'number' && Number.isFinite(payload.exp) && payload.exp > Math.floor(Date.now() / 1000);
}

const DELETE_RECOVER_ISSUER = 'nodewarden|delete_recover';

export async function createDeleteRecoverToken(env: Env, user: User): Promise<string> {
  return signHs256Jwt({
    iss: DELETE_RECOVER_ISSUER, sub: user.id, sst: await sha256Base64Url(user.securityStamp),
    exp: Math.floor(Date.now() / 1000) + LIMITS.auth.deleteRecoverTokenTtlSeconds,
  }, env.JWT_SECRET);
}

export async function verifyDeleteRecoverToken(env: Env, user: User, token: string): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
  return !!payload && payload.iss === DELETE_RECOVER_ISSUER && payload.sub === user.id
    && typeof payload.exp === 'number' && Number.isFinite(payload.exp) && payload.exp > Math.floor(Date.now() / 1000)
    && payload.sst === await sha256Base64Url(user.securityStamp);
}

export const REGISTER_VERIFY_ISSUER = 'nodewarden|register_verify';

export async function createRegisterVerifyToken(
  secret: string,
  email: string,
  name: string | null
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt({
    nbf: now,
    exp: now + 30 * 60,
    iss: REGISTER_VERIFY_ISSUER,
    sub: email,
    name,
    verified: false,
  }, secret);
}

export async function verifyRegisterVerifyToken(
  token: string,
  secret: string
): Promise<{ email: string; name: string | null } | null> {
  const payload = await verifyHs256Jwt(token, secret);
  if (!payload || payload.iss !== REGISTER_VERIFY_ISSUER) return null;
  const email = String(payload.sub || '').trim().toLowerCase();
  if (!email) return null;
  const name = typeof payload.name === 'string' && payload.name.trim() ? payload.name.trim() : null;
  return { email, name };
}

const ORG_INVITE_ISSUER = 'nodewarden|org_invite';
const SECONDS_PER_DAY = 24 * 60 * 60;
// Upstream OrgUserInviteTokenable.GetTokenLifetime(). The invite email quotes it too.
export const ORG_INVITE_TTL_DAYS = 5;
const ORG_INVITE_TTL_SECONDS = ORG_INVITE_TTL_DAYS * SECONDS_PER_DAY;

// Upstream TokenableValidationError messages; official web's accept page branches on them.
export type OrgInviteTokenCheck = { ok: true } | { ok: false; message: 'Expired token.' | 'Invalid token.' };

// Binds an emailed invite to one membership row and the address it was sent to, as upstream
// OrgUserInviteTokenable does, so only that mailbox's owner can accept the row.
export async function createOrgInviteToken(secret: string, orgUserId: string, email: string, expiresAt = Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_SECONDS): Promise<string> {
  return signHs256Jwt({
    exp: expiresAt,
    iss: ORG_INVITE_ISSUER,
    sub: orgUserId,
    email: email.toLowerCase(),
  }, secret);
}

export async function verifyOrgInviteToken(
  token: string,
  secret: string,
  orgUserId: string,
  email: string | null
): Promise<OrgInviteTokenCheck> {
  // Signature only: hono checks exp before the signature, so its expiry error cannot tell an
  // expired invite from a forged one. Upstream OrgUserInviteTokenable.ValidateOrgUserInvite
  // reports expiry before the row binding.
  const payload = await verify(token, await hmacKey(secret), { ...HS256_VERIFY_OPTIONS, exp: false }).catch(() => null);
  if (payload?.iss === ORG_INVITE_ISSUER && typeof payload.exp === 'number' && payload.exp <= Math.floor(Date.now() / 1000)) {
    return { ok: false, message: 'Expired token.' };
  }
  const bound = !!payload && !!email
    && payload.iss === ORG_INVITE_ISSUER
    && payload.sub === orgUserId
    && payload.email === email.toLowerCase();
  return bound ? { ok: true } : { ok: false, message: 'Invalid token.' };
}

const EMERGENCY_ACCESS_INVITE_ISSUER = 'nodewarden|emergency_access_invite';

export async function createEmergencyAccessInviteToken(secret: string, id: string, email: string): Promise<string> {
  return signHs256Jwt({
    exp: Math.floor(Date.now() / 1000) + ORG_INVITE_TTL_SECONDS,
    iss: EMERGENCY_ACCESS_INVITE_ISSUER,
    sub: id,
    email: email.toLowerCase(),
  }, secret);
}

export async function verifyEmergencyAccessInviteToken(token: string, secret: string, id: string, email: string): Promise<boolean> {
  const payload = await verifyHs256Jwt(token, secret);
  return !!payload && payload.iss === EMERGENCY_ACCESS_INVITE_ISSUER && payload.sub === id
    && payload.email === email.toLowerCase() && typeof payload.exp === 'number'
    && payload.exp > Math.floor(Date.now() / 1000);
}


// Access tokens carry the profile claims official clients read plus the flags mobile requires.
export async function createJWT(payload: Omit<JWTPayload, 'iat' | 'exp' | 'iss' | 'premium' | 'email_verified' | 'amr'>, secret: string, expiresIn: number = LIMITS.auth.accessTokenTtlSeconds): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt({
    ...payload,
    email_verified: true,  // required by mobile client
    amr: ['Application'],  // authentication methods reference - required by mobile client
    iat: now,
    exp: now + expiresIn,
    iss: 'nodewarden',
    premium: true,
  }, secret);
}

export async function verifyJWT(token: string, secret: string): Promise<JWTPayload | null> {
  return verifyHs256Jwt<JWTPayload>(token, secret);
}

// Create refresh token (simple random string)
export function createRefreshToken(): string {
  const bytes = new Uint8Array(LIMITS.auth.refreshTokenRandomBytes);
  crypto.getRandomValues(bytes);
  return bytesToBase64Url(bytes);
}

// Upload and download tokens for attachments and Send files live only as long as one transfer.
function fileTokenExp(): number {
  return Math.floor(Date.now() / 1000) + LIMITS.auth.fileDownloadTokenTtlSeconds;
}

export interface FileDownloadClaims {
  cipherId: string;
  attachmentId: string;
  jti: string;
  exp: number;
}

export interface AttachmentUploadClaims {
  userId: string;
  cipherId: string;
  attachmentId: string;
  exp: number;
}

export async function createFileDownloadToken(cipherId: string, attachmentId: string, secret: string): Promise<string> {
  return signHs256Jwt({ cipherId, attachmentId, jti: createRefreshToken(), exp: fileTokenExp() }, secret);
}

export async function verifyFileDownloadToken(token: string, secret: string): Promise<FileDownloadClaims | null> {
  return verifyHs256Jwt<FileDownloadClaims>(token, secret);
}

export async function createAttachmentUploadToken(userId: string, cipherId: string, attachmentId: string, secret: string): Promise<string> {
  return signHs256Jwt({ userId, cipherId, attachmentId, exp: fileTokenExp() }, secret);
}

export async function verifyAttachmentUploadToken(token: string, secret: string): Promise<AttachmentUploadClaims | null> {
  const payload = await verifyHs256Jwt<AttachmentUploadClaims>(token, secret);
  return payload && payload.userId && payload.cipherId && payload.attachmentId ? payload : null;
}

export interface SendFileDownloadClaims {
  sendId: string;
  fileId: string;
  jti: string;
  exp: number;
}

export interface SendFileUploadClaims {
  userId: string;
  sendId: string;
  fileId: string;
  exp: number;
}

export async function createSendFileDownloadToken(sendId: string, fileId: string, secret: string): Promise<string> {
  return signHs256Jwt({ sendId, fileId, jti: createRefreshToken(), exp: fileTokenExp() }, secret);
}

export async function verifySendFileDownloadToken(token: string, secret: string): Promise<SendFileDownloadClaims | null> {
  const payload = await verifyHs256Jwt<SendFileDownloadClaims>(token, secret);
  return payload && typeof payload.sendId === 'string' && typeof payload.fileId === 'string'
    && typeof payload.jti === 'string' && payload.jti && typeof payload.exp === 'number' ? payload : null;
}

export async function createSendFileUploadToken(userId: string, sendId: string, fileId: string, secret: string): Promise<string> {
  return signHs256Jwt({ userId, sendId, fileId, exp: fileTokenExp() }, secret);
}

export async function verifySendFileUploadToken(token: string, secret: string): Promise<SendFileUploadClaims | null> {
  const payload = await verifyHs256Jwt<SendFileUploadClaims>(token, secret);
  return payload && payload.userId && payload.sendId && payload.fileId ? payload : null;
}

export interface SendAccessTokenClaims {
  sub: string; // send id
  typ: 'send_access';
  iat: number;
  exp: number;
}

export async function createSendAccessToken(sendId: string, secret: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt({ sub: sendId, typ: 'send_access', iat: now, exp: now + LIMITS.auth.sendAccessTokenTtlSeconds }, secret);
}

export async function verifySendAccessToken(token: string, secret: string): Promise<SendAccessTokenClaims | null> {
  const payload = await verifyHs256Jwt<SendAccessTokenClaims>(token, secret);
  return payload && payload.typ === 'send_access' && payload.sub ? payload : null;
}
