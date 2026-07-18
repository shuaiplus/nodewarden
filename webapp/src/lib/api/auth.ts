import { bytesToBase64, decryptBw, encryptBw, hkdfExpand, pbkdf2 } from '../crypto';
import { t, translateServerError } from '../i18n';
import type { AuthorizedDevice } from '../types';
import type {
  AccountPasskeyCredential,
  Profile,
  SessionState,
  TokenError,
  TokenSuccess,
  TwoFactorPasskeySettings,
  YubiKeyOtpSettings,
} from '../types';
import type { AccountPasskeyAssertion, AccountPasskeyPrfKeySet } from '../account-passkeys';
import { recordNodeWardenReachable, recordNodeWardenUnreachable } from '../network-status';
import { parseJson, type AuthedFetch, type SessionSetter } from './shared';

const SESSION_KEY = 'nodewarden.web.session.v4';
const PROFILE_SNAPSHOT_KEY = 'nodewarden.web.profile-snapshot.v1';
const DEVICE_IDENTIFIER_KEY = 'nodewarden.web.device.identifier.v1';
const TOTP_REMEMBER_TOKEN_KEY = 'nodewarden.web.totp.remember-token.v1';
const WEB_SESSION_HEADER = 'X-NodeWarden-Web-Session';

export interface PreloginResult {
  hash: string;
  masterKey: Uint8Array;
  kdfIterations: number;
}

export interface PreloginKdfConfig {
  kdfType: number;
  kdfIterations: number;
  kdfMemory: number | null;
  kdfParallelism: number | null;
}

interface PersistedSessionState {
  email: string;
  authMode: 'token' | 'web-cookie';
}

interface RefreshFailure {
  ok: false;
  transient: boolean;
  error: string;
  retryAfterMs?: number;
}

interface RefreshSuccess {
  ok: true;
  token: TokenSuccess;
}

type RefreshResult = RefreshFailure | RefreshSuccess;

const pendingRefreshes = new Map<string, Promise<RefreshResult>>();

function randomHex(length: number): string {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.max(1, Math.ceil(length / 2))));
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, length);
}

function getOrCreateDeviceIdentifier(): string {
  const current = (localStorage.getItem(DEVICE_IDENTIFIER_KEY) || '').trim();
  if (current) return current;
  const next = `${randomHex(8)}-${randomHex(4)}-${randomHex(4)}-${randomHex(4)}-${randomHex(12)}`;
  localStorage.setItem(DEVICE_IDENTIFIER_KEY, next);
  return next;
}

function guessDeviceName(): string {
  const ua = (typeof navigator !== 'undefined' ? navigator.userAgent : '').toLowerCase();
  const platform = (typeof navigator !== 'undefined' ? navigator.platform : '').trim();
  const browser = ua.includes('edg/') ? 'Edge' : ua.includes('chrome/') ? 'Chrome' : ua.includes('firefox/') ? 'Firefox' : ua.includes('safari/') ? 'Safari' : 'Browser';
  const os = ua.includes('windows') ? 'Windows' : ua.includes('mac os') ? 'macOS' : ua.includes('linux') ? 'Linux' : ua.includes('android') ? 'Android' : ua.includes('iphone') || ua.includes('ipad') ? 'iOS' : platform || 'Unknown OS';
  return `${browser} on ${os}`.slice(0, 128);
}

function getRememberTwoFactorToken(): string | null {
  const token = (localStorage.getItem(TOTP_REMEMBER_TOKEN_KEY) || '').trim();
  return token || null;
}

function saveRememberTwoFactorToken(token: string | undefined): void {
  const normalized = String(token || '').trim();
  if (!normalized) return;
  localStorage.setItem(TOTP_REMEMBER_TOKEN_KEY, normalized);
}

function clearRememberTwoFactorToken(): void {
  localStorage.removeItem(TOTP_REMEMBER_TOKEN_KEY);
}

function hasTwoFactorChallenge(error: TokenError): boolean {
  const providers = error.TwoFactorProviders ?? error.CustomResponse?.TwoFactorProviders;
  const providers2 = error.TwoFactorProviders2 ?? error.CustomResponse?.TwoFactorProviders2;
  if (Array.isArray(providers)) return providers.length > 0;
  if (providers && typeof providers === 'object') return Object.keys(providers as Record<string, unknown>).length > 0;
  if (Array.isArray(providers2)) return providers2.length > 0;
  if (providers2 && typeof providers2 === 'object') return Object.keys(providers2 as Record<string, unknown>).length > 0;
  return providers != null || providers2 != null;
}

export function loadSession(): SessionState | null {
  try {
    const raw = localStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<SessionState> & Partial<PersistedSessionState>;
    if (parsed.email && (parsed.accessToken || parsed.refreshToken)) {
      const authMode = parsed.authMode === 'web-cookie' ? 'web-cookie' : 'token';
      saveSession({ email: parsed.email, authMode });
      return {
        email: parsed.email,
        authMode,
      };
    }
    if (parsed.authMode === 'web-cookie' && parsed.email) {
      return {
        email: parsed.email,
        authMode: 'web-cookie',
      };
    }
    if (parsed.authMode === 'token' && parsed.email && !parsed.accessToken && !parsed.refreshToken) {
      return {
        email: parsed.email,
        authMode: 'token',
      };
    }
    return null;
  } catch {
    return null;
  }
}

export function saveSession(session: SessionState | null): void {
  if (!session) {
    localStorage.removeItem(SESSION_KEY);
    return;
  }
  const persisted: PersistedSessionState = {
    email: session.email,
    authMode: session.authMode === 'token' ? 'token' : 'web-cookie',
  };
  localStorage.setItem(SESSION_KEY, JSON.stringify(persisted));
}

export function loadProfileSnapshot(email?: string | null): Profile | null {
  try {
    const raw = localStorage.getItem(PROFILE_SNAPSHOT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Profile;
    if (!parsed?.email) return null;
    if (email && parsed.email !== email) return null;
    const snapshot = stripProfileSecrets(parsed);
    localStorage.setItem(PROFILE_SNAPSHOT_KEY, JSON.stringify(snapshot));
    return snapshot;
  } catch {
    return null;
  }
}

export function saveProfileSnapshot(profile: Profile | null): void {
  if (!profile) return;
  const nextSnapshot = stripProfileSecrets(profile);
  try {
    const rawExisting = localStorage.getItem(PROFILE_SNAPSHOT_KEY);
    if (rawExisting) {
      const existing = stripProfileSecrets(JSON.parse(rawExisting) as Profile);
      if (
        existing
        && existing.email === nextSnapshot?.email
        && existing.role === 'admin'
        && nextSnapshot?.role !== 'admin'
      ) {
        localStorage.setItem(PROFILE_SNAPSHOT_KEY, JSON.stringify({
          ...nextSnapshot,
          role: 'admin',
        }));
        return;
      }
    }
  } catch {
    // Fall back to writing the normalized snapshot below.
  }
  localStorage.setItem(PROFILE_SNAPSHOT_KEY, JSON.stringify(nextSnapshot));
}

export function clearProfileSnapshot(): void {
  localStorage.removeItem(PROFILE_SNAPSHOT_KEY);
}

export function stripProfileSecrets(profile: Profile | null): Profile | null {
  if (!profile) return null;
  return {
    id: String(profile.id || ''),
    email: String(profile.email || ''),
    name: String(profile.name || ''),
    role: profile.role === 'admin' ? 'admin' : 'user',
    masterPasswordHint: profile.masterPasswordHint ?? null,
    publicKey: profile.publicKey ?? null,
    key: '',
    privateKey: null,
  };
}

export function getCurrentDeviceIdentifier(): string {
  return (localStorage.getItem(DEVICE_IDENTIFIER_KEY) || '').trim();
}

export async function deriveLoginHash(email: string, password: string, fallbackIterations: number): Promise<PreloginResult> {
  const pre = await fetch('/identity/accounts/prelogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.toLowerCase() }),
  });
  if (!pre.ok) throw new Error('prelogin failed');
  const data = (await parseJson<{ kdfIterations?: number }>(pre)) || {};
  const iterations = Number(data.kdfIterations || fallbackIterations);
  const masterKey = await pbkdf2(password, email.toLowerCase(), iterations, 32);
  const hash = await pbkdf2(masterKey, password, 1, 32);
  return { hash: bytesToBase64(hash), masterKey, kdfIterations: iterations };
}

export async function deriveLoginHashLocally(
  email: string,
  password: string,
  fallbackIterations: number
): Promise<PreloginResult> {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const iterations = Number(fallbackIterations || 600000);
  const masterKey = await pbkdf2(password, normalizedEmail, iterations, 32);
  const hash = await pbkdf2(masterKey, password, 1, 32);
  return { hash: bytesToBase64(hash), masterKey, kdfIterations: iterations };
}

export async function getPreloginKdfConfig(email: string, fallbackIterations: number): Promise<PreloginKdfConfig> {
  const normalized = String(email || '').trim().toLowerCase();
  if (!normalized) throw new Error('Email is required');
  const pre = await fetch('/identity/accounts/prelogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: normalized }),
  });
  if (!pre.ok) throw new Error('prelogin failed');
  const data = (await parseJson<{ kdf?: number; kdfIterations?: number; kdfMemory?: number | null; kdfParallelism?: number | null }>(pre)) || {};
  return {
    kdfType: Number(data.kdf ?? 0) || 0,
    kdfIterations: Number(data.kdfIterations || fallbackIterations),
    kdfMemory: data.kdfMemory == null ? null : Number(data.kdfMemory),
    kdfParallelism: data.kdfParallelism == null ? null : Number(data.kdfParallelism),
  };
}

export async function loginWithPassword(
  email: string,
  passwordHash: string,
  options?: {
    totpCode?: string;
    twoFactorProvider?: number;
    rememberDevice?: boolean;
    useRememberToken?: boolean;
    signal?: AbortSignal;
  }
): Promise<TokenSuccess | TokenError> {
  const body = new URLSearchParams();
  body.set('grant_type', 'password');
  body.set('username', email.toLowerCase());
  body.set('password', passwordHash);
  body.set('scope', 'api offline_access');
  body.set('deviceIdentifier', getOrCreateDeviceIdentifier());
  body.set('deviceName', guessDeviceName());
  body.set('deviceType', '14');

  const rememberedToken = options?.useRememberToken ? getRememberTwoFactorToken() : null;
  if (rememberedToken) {
    body.set('twoFactorProvider', '5');
    body.set('twoFactorToken', rememberedToken);
  } else if (options?.totpCode) {
    body.set('twoFactorProvider', String(options.twoFactorProvider ?? 0));
    body.set('twoFactorToken', options.totpCode);
    if (options.rememberDevice) {
      body.set('twoFactorRemember', '1');
    }
  }
  const resp = await fetch('/identity/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      [WEB_SESSION_HEADER]: '1',
    },
    body: body.toString(),
    signal: options?.signal,
  });
  const json = (await parseJson<TokenSuccess & TokenError>(resp)) || {};
  if (resp.ok) {
    saveRememberTwoFactorToken((json as TokenSuccess).TwoFactorToken);
  } else if (rememberedToken && hasTwoFactorChallenge(json)) {
    clearRememberTwoFactorToken();
  }
  if (!resp.ok) return json;
  return json;
}

export async function getAccountPasskeyAssertionOptions(): Promise<{ options: unknown; token: string }> {
  const resp = await fetch('/identity/accounts/webauthn/assertion-options');
  if (!resp.ok) {
    const json = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(json?.error_description || json?.error, t('txt_login_failed')));
  }
  const body = (await parseJson<{ options?: unknown; token?: string }>(resp)) || {};
  if (!body.options || !body.token) throw new Error('Invalid passkey assertion options');
  return { options: body.options, token: body.token };
}

export async function loginWithAccountPasskeyAssertion(assertion: AccountPasskeyAssertion): Promise<TokenSuccess | TokenError> {
  const body = new URLSearchParams();
  body.set('grant_type', 'webauthn');
  body.set('token', assertion.token);
  body.set('deviceResponse', JSON.stringify(assertion.deviceResponse));
  body.set('scope', 'api offline_access');
  body.set('deviceIdentifier', getOrCreateDeviceIdentifier());
  body.set('deviceName', guessDeviceName());
  body.set('deviceType', '14');

  const resp = await fetch('/identity/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      [WEB_SESSION_HEADER]: '1',
    },
    body: body.toString(),
  });
  const json = (await parseJson<TokenSuccess & TokenError>(resp)) || {};
  if (!resp.ok) return json;
  return json;
}

function isPermanentRefreshFailure(status: number, errorCode: string | undefined): boolean {
  return status === 400 && (errorCode === 'invalid_grant' || errorCode === 'invalid_request');
}

export async function refreshAccessToken(session: SessionState): Promise<RefreshResult> {
  const body = new URLSearchParams();
  body.set('grant_type', 'refresh_token');
  if (session.authMode !== 'web-cookie' && session.refreshToken) {
    body.set('refresh_token', session.refreshToken);
  }
  try {
    const resp = await fetch('/identity/connect/token', {
      method: 'POST',
      cache: 'no-store',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        ...(session.authMode === 'web-cookie' ? { [WEB_SESSION_HEADER]: '1' } : {}),
      },
      body: body.toString(),
    });
    if (!resp.ok) {
      const json = await parseJson<TokenError>(resp);
      const retryAfterSeconds = Number(resp.headers.get('Retry-After') || 0);
      return {
        ok: false,
        transient: !isPermanentRefreshFailure(resp.status, json?.error),
        error: translateServerError(json?.error_description || json?.error, t('txt_session_refresh_temporarily_unavailable')),
        ...(Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
          ? { retryAfterMs: retryAfterSeconds * 1000 }
          : {}),
      };
    }
    const json = await parseJson<TokenSuccess>(resp);
    if (!json?.access_token) {
      return { ok: false, transient: true, error: t('txt_session_refresh_temporarily_unavailable') };
    }
    return { ok: true, token: json };
  } catch (error) {
    return {
      ok: false,
      transient: true,
      error: error instanceof Error ? error.message : 'Network error',
    };
  }
}

function refreshKey(session: SessionState): string {
  if (session.authMode === 'web-cookie') return `web-cookie:${session.email || ''}`;
  return `token:${session.refreshToken || ''}`;
}

function refreshAccessTokenOnce(session: SessionState): Promise<RefreshResult> {
  const key = refreshKey(session);
  const existing = pendingRefreshes.get(key);
  if (existing) return existing;

  const request = refreshAccessToken(session).finally(() => {
    if (pendingRefreshes.get(key) === request) {
      pendingRefreshes.delete(key);
    }
  });
  pendingRefreshes.set(key, request);
  return request;
}

export async function revokeCurrentSession(session: SessionState | null): Promise<void> {
  const body = new URLSearchParams();
  if (session?.authMode !== 'web-cookie' && session?.refreshToken) {
    body.set('token', session.refreshToken);
  }
  await fetch('/identity/connect/revocation', {
    method: 'POST',
    cache: 'no-store',
    credentials: 'same-origin',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      ...(session?.accessToken ? { Authorization: `Bearer ${session.accessToken}` } : {}),
      ...(session?.authMode === 'web-cookie' ? { [WEB_SESSION_HEADER]: '1' } : {}),
    },
    body: body.toString(),
  }).catch(() => undefined);
}

export async function registerAccount(args: {
  email: string;
  name: string;
  password: string;
  masterPasswordHint?: string;
  inviteCode?: string;
  fallbackIterations: number;
}): Promise<{ ok: true } | { ok: false; message: string }> {
  try {
    const { email, name, password, masterPasswordHint, inviteCode, fallbackIterations } = args;
    const masterKey = await pbkdf2(password, email, fallbackIterations, 32);
    const masterHash = await pbkdf2(masterKey, password, 1, 32);
    const encKey = await hkdfExpand(masterKey, 'enc', 32);
    const macKey = await hkdfExpand(masterKey, 'mac', 32);
    const sym = crypto.getRandomValues(new Uint8Array(64));
    const encryptedVaultKey = await encryptBw(sym, encKey, macKey);

    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-1',
      },
      true,
      ['encrypt', 'decrypt']
    );
    const publicKey = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
    const privateKey = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
    const encryptedPrivateKey = await encryptBw(privateKey, sym.slice(0, 32), sym.slice(32, 64));

    const resp = await fetch('/api/accounts/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: email.toLowerCase(),
        name,
        masterPasswordHint: String(masterPasswordHint || '').trim() || undefined,
        masterPasswordHash: bytesToBase64(masterHash),
        key: encryptedVaultKey,
        kdf: 0,
        kdfIterations: fallbackIterations,
        inviteCode: inviteCode || undefined,
        keys: {
          publicKey: bytesToBase64(publicKey),
          encryptedPrivateKey,
        },
      }),
    });

    if (!resp.ok) {
      const json = await parseJson<TokenError>(resp);
      return { ok: false, message: translateServerError(json?.error_description || json?.error, t('txt_register_failed')) };
    }
    return { ok: true };
  } catch (error) {
    return { ok: false, message: error instanceof Error ? translateServerError(error.message, error.message) : t('txt_register_failed') };
  }
}

export async function getPasswordHint(email: string): Promise<{ masterPasswordHint: string | null }> {
  const resp = await fetch('/api/accounts/password-hint', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email.trim().toLowerCase() }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_password_hint_load_failed')));
  }
  const body = (await parseJson<{ masterPasswordHint?: string | null }>(resp)) || {};
  return { masterPasswordHint: body.masterPasswordHint ?? null };
}

export function createAuthedFetch(getSession: () => SessionState | null, setSession: SessionSetter) {
  return async function authedFetch(input: string, init: RequestInit = {}): Promise<Response> {
    const retryableRequest = async (headers: Headers): Promise<Response> => {
      const maxAttempts = 3;
      let lastError: unknown;
      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        try {
          const response = await fetch(input, { ...init, headers });
          recordNodeWardenReachable();
          if (response.status !== 429 && (response.status < 500 || response.status >= 600)) {
            return response;
          }
          lastError = new Error(`HTTP ${response.status}`);
          if (attempt === maxAttempts - 1) {
            return response;
          }
        } catch (error) {
          lastError = error;
          if (attempt === maxAttempts - 1) {
            recordNodeWardenUnreachable();
            throw error;
          }
        }
        const delayMs = 250 * (2 ** attempt) + Math.floor(Math.random() * 120);
        await new Promise((resolve) => window.setTimeout(resolve, delayMs));
      }
      throw lastError instanceof Error ? lastError : new Error('Request failed');
    };

    const session = getSession();
    if (!session?.accessToken) throw new Error(t('txt_offline_vault_readonly'));
    const headers = new Headers(init.headers || {});
    headers.set('Authorization', `Bearer ${session.accessToken}`);

    let resp = await retryableRequest(headers);
    if (resp.status !== 401 || (!session.refreshToken && session.authMode !== 'web-cookie')) return resp;

    const latest = getSession();
    if (latest?.accessToken && latest.accessToken !== session.accessToken) {
      const latestHeaders = new Headers(init.headers || {});
      latestHeaders.set('Authorization', `Bearer ${latest.accessToken}`);
      resp = await retryableRequest(latestHeaders);
      if (resp.status !== 401) return resp;
    }

    const refreshSource = latest || session;
    const refreshed = await refreshAccessTokenOnce(refreshSource);
    if (!refreshed.ok) {
      if (refreshed.transient) {
        throw new Error(refreshed.error || t('txt_session_refresh_failed'));
      }
      setSession(null);
      throw new Error(t('txt_session_refresh_failed'));
    }

    const nextSession: SessionState = {
      ...refreshSource,
      accessToken: refreshed.token.access_token,
      refreshToken: refreshed.token.refresh_token || refreshSource.refreshToken,
      authMode: refreshed.token.web_session ? 'web-cookie' : (refreshSource.authMode || 'token'),
    };
    setSession(nextSession);
    saveSession(nextSession);

    const retryHeaders = new Headers(init.headers || {});
    retryHeaders.set('Authorization', `Bearer ${nextSession.accessToken}`);
    resp = await retryableRequest(retryHeaders);
    return resp;
  };
}

export async function getProfile(authedFetch: AuthedFetch): Promise<Profile> {
  const resp = await authedFetch('/api/accounts/profile');
  if (!resp.ok) throw new Error('Failed to load profile');
  const body = await parseJson<Profile>(resp);
  if (!body) throw new Error('Invalid profile');
  return body;
}

export async function updateProfile(
  authedFetch: AuthedFetch,
  payload: { masterPasswordHint: string }
): Promise<Profile> {
  const resp = await authedFetch('/api/accounts/profile', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      masterPasswordHint: String(payload.masterPasswordHint || '').trim() || null,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_save_profile_failed')));
  }
  const body = await parseJson<Profile>(resp);
  if (!body) throw new Error('Invalid profile');
  return body;
}

export async function unlockVaultKey(profileKey: string, masterKey: Uint8Array): Promise<{ symEncKey: string; symMacKey: string }> {
  const encKey = await hkdfExpand(masterKey, 'enc', 32);
  const macKey = await hkdfExpand(masterKey, 'mac', 32);
  const keyBytes = await decryptBw(profileKey, encKey, macKey);
  if (!keyBytes || keyBytes.length < 64) throw new Error('Invalid profile key');
  return {
    symEncKey: bytesToBase64(keyBytes.slice(0, 32)),
    symMacKey: bytesToBase64(keyBytes.slice(32, 64)),
  };
}

export async function changeMasterPassword(
  authedFetch: AuthedFetch,
  args: {
    email: string;
    currentPassword: string;
    newPassword: string;
    currentIterations: number;
    profileKey: string;
  }
): Promise<void> {
  const current = await deriveLoginHash(args.email, args.currentPassword, args.currentIterations);
  const oldEnc = await hkdfExpand(current.masterKey, 'enc', 32);
  const oldMac = await hkdfExpand(current.masterKey, 'mac', 32);
  const userSym = await decryptBw(args.profileKey, oldEnc, oldMac);
  if (userSym.length !== 64) {
    throw new Error('Invalid profile key');
  }
  const nextMasterKey = await pbkdf2(args.newPassword, args.email, current.kdfIterations, 32);
  const nextHash = await pbkdf2(nextMasterKey, args.newPassword, 1, 32);
  const nextEnc = await hkdfExpand(nextMasterKey, 'enc', 32);
  const nextMac = await hkdfExpand(nextMasterKey, 'mac', 32);
  const newKey = await encryptBw(userSym, nextEnc, nextMac);
  const newMasterPasswordHash = bytesToBase64(nextHash);

  const resp = await authedFetch('/api/accounts/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      masterPasswordHash: current.hash,
      authenticationData: {
        kdf: {
          kdfType: 0,
          iterations: current.kdfIterations,
          memory: null,
          parallelism: null,
        },
        masterPasswordAuthenticationHash: newMasterPasswordHash,
        salt: args.email.trim().toLowerCase(),
      },
      unlockData: {
        kdf: {
          kdfType: 0,
          iterations: current.kdfIterations,
          memory: null,
          parallelism: null,
        },
        masterKeyWrappedUserKey: newKey,
        salt: args.email.trim().toLowerCase(),
      },
    }),
  });
  if (!resp.ok) throw new Error('Change master password failed');
}

export async function setTotp(
  authedFetch: AuthedFetch,
  payload: { enabled: boolean; token?: string; secret?: string; masterPasswordHash?: string }
): Promise<void> {
  const resp = await authedFetch('/api/accounts/totp', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_totp_update_failed')));
  }
}

function normalizeYubiKeySettings(raw: any): YubiKeyOtpSettings {
  return {
    enabled: !!(raw?.enabled ?? raw?.Enabled),
    keys: [
      String(raw?.key1 ?? raw?.Key1 ?? ''),
      String(raw?.key2 ?? raw?.Key2 ?? ''),
      String(raw?.key3 ?? raw?.Key3 ?? ''),
      String(raw?.key4 ?? raw?.Key4 ?? ''),
      String(raw?.key5 ?? raw?.Key5 ?? ''),
    ],
    nfc: !!(raw?.nfc ?? raw?.Nfc),
    yubicoConfigured: !!(raw?.yubicoConfigured ?? raw?.YubicoConfigured),
    yubicoCanManage: !!(raw?.yubicoCanManage ?? raw?.YubicoCanManage),
    yubicoClientId: String(raw?.yubicoClientId ?? raw?.YubicoClientId ?? ''),
    yubicoSecretKey: String(raw?.yubicoSecretKey ?? raw?.YubicoSecretKey ?? ''),
  };
}

export async function getYubiKeyOtpSettings(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<YubiKeyOtpSettings> {
  const resp = await authedFetch('/api/two-factor/get-yubikey', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_master_password_verify_failed')));
  }
  return normalizeYubiKeySettings(await parseJson<unknown>(resp));
}

export async function saveYubiKeyOtpSettings(
  authedFetch: AuthedFetch,
  payload: { keys: string[]; nfc: boolean; masterPasswordHash: string }
): Promise<YubiKeyOtpSettings> {
  const resp = await authedFetch('/api/two-factor/yubikey', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key1: payload.keys[0] || '',
      key2: payload.keys[1] || '',
      key3: payload.keys[2] || '',
      key4: payload.keys[3] || '',
      key5: payload.keys[4] || '',
      nfc: payload.nfc,
      masterPasswordHash: payload.masterPasswordHash,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_yubikey_update_failed')));
  }
  return normalizeYubiKeySettings(await parseJson<unknown>(resp));
}

export async function saveYubiKeyOtpApiCredentials(
  authedFetch: AuthedFetch,
  payload: { masterPasswordHash: string; yubicoClientId: string; yubicoSecretKey: string }
): Promise<YubiKeyOtpSettings> {
  const resp = await authedFetch('/api/two-factor/yubikey/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_yubikey_config_update_failed')));
  }
  return normalizeYubiKeySettings(await parseJson<unknown>(resp));
}

export async function bootstrapYubiKeyOtpApiCredentials(
  authedFetch: AuthedFetch,
  payload: { masterPasswordHash: string; otp: string }
): Promise<YubiKeyOtpSettings> {
  const resp = await authedFetch('/api/two-factor/yubikey/bootstrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_yubikey_auto_config_failed')));
  }
  return normalizeYubiKeySettings(await parseJson<unknown>(resp));
}

export async function disableYubiKeyOtp(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<void> {
  const resp = await authedFetch('/api/two-factor/disable', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 3, masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_disable_yubikey_failed')));
  }
}

function normalizeTwoFactorPasskeySettings(raw: any): TwoFactorPasskeySettings {
  const keys = Array.isArray(raw?.keys) ? raw.keys : Array.isArray(raw?.Keys) ? raw.Keys : [];
  return {
    enabled: !!(raw?.enabled ?? raw?.Enabled),
    keys: keys
      .map((item: any) => ({
        id: Number(item?.id ?? item?.Id),
        name: String(item?.name || item?.Name || ''),
        migrated: !!(item?.migrated ?? item?.Migrated),
      }))
      .filter((item: { id: number }) => Number.isInteger(item.id) && item.id > 0),
  };
}

export async function getTwoFactorPasskeySettings(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<TwoFactorPasskeySettings> {
  const resp = await authedFetch('/api/two-factor/get-webauthn', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_master_password_verify_failed')));
  }
  return normalizeTwoFactorPasskeySettings(await parseJson<unknown>(resp));
}

export async function getTwoFactorPasskeyChallenge(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<unknown> {
  const resp = await authedFetch('/api/two-factor/get-webauthn-challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_passkey_setup_failed')));
  }
  return parseJson<unknown>(resp);
}

export async function saveTwoFactorPasskey(
  authedFetch: AuthedFetch,
  payload: { id?: number; name: string; masterPasswordHash: string; deviceResponse: unknown }
): Promise<TwoFactorPasskeySettings> {
  const resp = await authedFetch('/api/two-factor/webauthn', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_passkey_setup_failed')));
  }
  return normalizeTwoFactorPasskeySettings(await parseJson<unknown>(resp));
}

export async function deleteTwoFactorPasskey(
  authedFetch: AuthedFetch,
  payload: { id: number; masterPasswordHash: string }
): Promise<TwoFactorPasskeySettings> {
  const resp = await authedFetch('/api/two-factor/webauthn', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_delete_item_failed')));
  }
  return normalizeTwoFactorPasskeySettings(await parseJson<unknown>(resp));
}

export async function disableTwoFactorPasskeys(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<void> {
  const resp = await authedFetch('/api/two-factor/disable', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ type: 7, masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_disable_passkey_two_step_failed')));
  }
}

export async function verifyMasterPassword(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<void> {
  const resp = await authedFetch('/api/accounts/verify-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_master_password_verify_failed')));
  }
}

function normalizeAccountPasskeyCredential(raw: any): AccountPasskeyCredential {
  return {
    id: String(raw?.id || raw?.Id || ''),
    name: String(raw?.name || raw?.Name || ''),
    prfStatus: Number(raw?.prfStatus ?? raw?.PrfStatus ?? 2) as 0 | 1 | 2,
    encryptedPublicKey: raw?.encryptedPublicKey ?? raw?.EncryptedPublicKey ?? null,
    encryptedUserKey: raw?.encryptedUserKey ?? raw?.EncryptedUserKey ?? null,
    creationDate: raw?.creationDate ?? raw?.CreationDate,
    revisionDate: raw?.revisionDate ?? raw?.RevisionDate,
  };
}

export async function listAccountPasskeys(authedFetch: AuthedFetch): Promise<AccountPasskeyCredential[]> {
  const resp = await authedFetch('/api/webauthn');
  if (!resp.ok) throw new Error('Failed to load account passkeys');
  const body = (await parseJson<{ data?: unknown[]; Data?: unknown[] }>(resp)) || {};
  const rows = Array.isArray(body.data) ? body.data : Array.isArray(body.Data) ? body.Data : [];
  return rows.map(normalizeAccountPasskeyCredential).filter((item) => item.id);
}

export async function getAccountPasskeyAttestationOptions(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<{ options: unknown; token: string }> {
  const resp = await authedFetch('/api/webauthn/attestation-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_master_password_verify_failed')));
  }
  const body = (await parseJson<{ options?: unknown; token?: string }>(resp)) || {};
  if (!body.options || !body.token) throw new Error('Invalid passkey creation options');
  return { options: body.options, token: body.token };
}

export async function getAccountPasskeyUpdateAssertionOptions(
  authedFetch: AuthedFetch,
  masterPasswordHash: string,
  credentialId?: string
): Promise<{ options: unknown; token: string }> {
  const resp = await authedFetch('/api/webauthn/assertion-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash, credentialId }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_master_password_verify_failed')));
  }
  const body = (await parseJson<{ options?: unknown; token?: string }>(resp)) || {};
  if (!body.options || !body.token) throw new Error('Invalid passkey assertion options');
  return { options: body.options, token: body.token };
}

export async function saveAccountPasskey(
  authedFetch: AuthedFetch,
  payload: {
    name: string;
    token: string;
    deviceResponse: unknown;
    supportsPrf: boolean;
    keySet?: AccountPasskeyPrfKeySet | null;
  }
): Promise<AccountPasskeyCredential> {
  const resp = await authedFetch('/api/webauthn', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: payload.name,
      token: payload.token,
      deviceResponse: payload.deviceResponse,
      supportsPrf: payload.supportsPrf,
      encryptedUserKey: payload.keySet?.encryptedUserKey,
      encryptedPublicKey: payload.keySet?.encryptedPublicKey,
      encryptedPrivateKey: payload.keySet?.encryptedPrivateKey,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_save_profile_failed')));
  }
  const body = await parseJson<unknown>(resp);
  return normalizeAccountPasskeyCredential(body);
}

export async function enableAccountPasskeyDirectUnlock(
  authedFetch: AuthedFetch,
  payload: {
    token: string;
    deviceResponse: unknown;
    keySet: AccountPasskeyPrfKeySet;
  }
): Promise<void> {
  const resp = await authedFetch('/api/webauthn', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: payload.token,
      deviceResponse: payload.deviceResponse,
      encryptedUserKey: payload.keySet.encryptedUserKey,
      encryptedPublicKey: payload.keySet.encryptedPublicKey,
      encryptedPrivateKey: payload.keySet.encryptedPrivateKey,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_save_profile_failed')));
  }
}

export async function deleteAccountPasskey(
  authedFetch: AuthedFetch,
  id: string,
  masterPasswordHash: string
): Promise<void> {
  const resp = await authedFetch(`/api/webauthn/${encodeURIComponent(id)}/delete`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_delete_item_failed')));
  }
}

export async function getVaultRevisionDate(authedFetch: AuthedFetch): Promise<number> {
  const resp = await authedFetch('/api/accounts/revision-date');
  if (!resp.ok) {
    throw new Error('Failed to load revision date');
  }
  const body = await parseJson<number>(resp);
  const stamp = Number(body);
  if (!Number.isFinite(stamp) || stamp <= 0) {
    throw new Error('Invalid revision date');
  }
  return stamp;
}

export async function getTwoFactorProviderStatus(authedFetch: AuthedFetch): Promise<{ totpEnabled: boolean; yubikeyEnabled: boolean; passkeyEnabled: boolean }> {
  const resp = await authedFetch('/api/two-factor');
  if (!resp.ok) throw new Error('Failed to load two-factor status');
  const body = (await parseJson<{ data?: unknown[]; Data?: unknown[] }>(resp)) || {};
  const providers = Array.isArray(body.data) ? body.data : Array.isArray(body.Data) ? body.Data : [];
  const enabledTypes = new Set(
    providers
      .map((provider: any) => Number(provider?.type ?? provider?.Type))
      .filter((type) => Number.isFinite(type))
  );
  return {
    totpEnabled: enabledTypes.has(0),
    yubikeyEnabled: enabledTypes.has(3),
    passkeyEnabled: enabledTypes.has(7),
  };
}

export async function getTotpRecoveryCode(
  authedFetch: AuthedFetch,
  masterPasswordHash: string
): Promise<string> {
  const resp = await authedFetch('/api/accounts/totp/recovery-code', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_get_recovery_code_failed')));
  }
  const body = (await parseJson<{ code?: string }>(resp)) || {};
  return String(body.code || '');
}

export async function recoverTwoFactor(
  email: string,
  masterPasswordHash: string,
  recoveryCode: string
): Promise<{ newRecoveryCode?: string }> {
  const resp = await fetch('/identity/accounts/recover-2fa', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: email.toLowerCase().trim(),
      masterPasswordHash,
      recoveryCode,
    }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_recover_2fa_failed')));
  }
  return (await parseJson<{ newRecoveryCode?: string }>(resp)) || {};
}

export async function getAuthorizedDevices(authedFetch: AuthedFetch): Promise<AuthorizedDevice[]> {
  const resp = await authedFetch('/api/devices/authorized');
  if (!resp.ok) throw new Error(t('txt_load_devices_failed'));
  const body = await parseJson<{ object: 'list'; data: AuthorizedDevice[] }>(resp);
  return body?.data || [];
}

export async function revokeAuthorizedDeviceTrust(
  authedFetch: AuthedFetch,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/authorized/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_revoke_device_trust_failed'));
}

export async function trustAuthorizedDevicePermanently(
  authedFetch: AuthedFetch,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/authorized/${encodeURIComponent(deviceIdentifier)}/permanent`, { method: 'POST' });
  if (!resp.ok) throw new Error(t('txt_trust_device_permanently_failed'));
}

export async function revokeAllAuthorizedDeviceTrust(authedFetch: AuthedFetch): Promise<void> {
  const resp = await authedFetch('/api/devices/authorized', { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_revoke_all_device_trust_failed'));
}

export async function deleteAuthorizedDevice(
  authedFetch: AuthedFetch,
  deviceIdentifier: string
): Promise<void> {
  const resp = await authedFetch(`/api/devices/${encodeURIComponent(deviceIdentifier)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(t('txt_remove_device_failed'));
}

export async function deleteAuthorizedDevices(
  authedFetch: AuthedFetch,
  devices: Array<Pick<AuthorizedDevice, 'identifier' | 'hasStoredDevice'>>
): Promise<void> {
  const uniqueDevices = Array.from(
    new Map(devices.map((device) => [String(device.identifier || '').trim(), device])).values()
  ).filter((device) => String(device.identifier || '').trim());
  await Promise.all(uniqueDevices.map((device) => (
    device.hasStoredDevice === false
      ? revokeAuthorizedDeviceTrust(authedFetch, device.identifier)
      : deleteAuthorizedDevice(authedFetch, device.identifier)
  )));
}

export async function updateAuthorizedDeviceName(
  authedFetch: AuthedFetch,
  deviceIdentifier: string,
  name: string
): Promise<void> {
  const normalized = String(name || '').trim();
  if (!normalized) throw new Error(t('txt_device_note_required'));
  const resp = await authedFetch(`/api/devices/${encodeURIComponent(deviceIdentifier)}/name`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: normalized }),
  });
  if (!resp.ok) throw new Error(t('txt_update_device_note_failed'));
}

export async function deleteAllAuthorizedDevices(authedFetch: AuthedFetch, masterPasswordHash: string): Promise<void> {
  const resp = await authedFetch('/api/devices', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) throw new Error(t('txt_remove_all_devices_failed'));
}

export async function getApiKey(authedFetch: AuthedFetch, masterPasswordHash: string): Promise<string> {
  const resp = await authedFetch('/api/accounts/api-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_get_api_key_failed')));
  }
  const body = (await parseJson<{ apiKey?: string }>(resp)) || {};
  return String(body.apiKey || '');
}

export async function rotateApiKey(authedFetch: AuthedFetch, masterPasswordHash: string): Promise<string> {
  const resp = await authedFetch('/api/accounts/rotate-api-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash }),
  });
  if (!resp.ok) {
    const body = await parseJson<TokenError>(resp);
    throw new Error(translateServerError(body?.error_description || body?.error, t('txt_rotate_api_key_failed')));
  }
  const body = (await parseJson<{ apiKey?: string }>(resp)) || {};
  return String(body.apiKey || '');
}
