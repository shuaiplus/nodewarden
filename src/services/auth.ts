import { getAccessTokenWithAccount } from './storage-secret-repo';
import { getRefreshTokenSlidingTtlMs, LIMITS } from '../config/limits';
import { Device, Env, JWTPayload, User } from '../types';
import { createJWT, createRefreshToken, verifyJWT } from '../utils/jwt';
import { hashPassword, verifyPassword } from './auth-password';
import * as deviceRepo from './storage-device-repo';
import * as sessionRepo from './storage-session-repo';
import * as userRepo from './storage-user-repo';

const AUTH_CONTEXT_CACHE_TTL_MS = 15 * 1000;

interface CachedUserEntry {
  user: User | null;
  expiresAt: number;
}

interface CachedDeviceEntry {
  device: Device | null;
  expiresAt: number;
}

export interface VerifiedAccessContext {
  payload: JWTPayload;
  user: User;
}

export type Principal =
  | { kind: 'user'; payload: JWTPayload; user: User }
  | { kind: 'serviceAccount'; serviceAccountId: string; orgId: string; accessTokenId: string };

type AccessClaims = JWTPayload & { type?: unknown; scope?: unknown; organization?: unknown; client_id?: unknown; nbf?: unknown };

export type RefreshAccessTokenFailureReason =
  | 'token_not_found_or_expired'
  | 'user_missing'
  | 'user_inactive'
  | 'security_stamp_mismatch'
  | 'device_missing'
  | 'device_session_mismatch';

export type RefreshAccessTokenResult =
  | { ok: true; accessToken: string; user: User; device: { identifier: string; sessionStamp: string } | null; expiresAt: number }
  | {
      ok: false;
      reason: RefreshAccessTokenFailureReason;
      userId?: string | null;
      deviceIdentifier?: string | null;
    };

export class AuthService {
  private static userCache = new Map<string, CachedUserEntry>();
  private static deviceCache = new Map<string, CachedDeviceEntry>();

  constructor(private env: Env) {
  }

  static invalidateUserCache(userId: string): void {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) return;
    AuthService.userCache.delete(normalizedUserId);
    const prefix = `${normalizedUserId}:`;
    for (const key of AuthService.deviceCache.keys()) {
      if (key.startsWith(prefix)) {
        AuthService.deviceCache.delete(key);
      }
    }
  }

  static invalidateDeviceCache(userId: string, deviceId: string): void {
    const normalizedUserId = String(userId || '').trim();
    const normalizedDeviceId = String(deviceId || '').trim();
    if (!normalizedUserId || !normalizedDeviceId) return;
    AuthService.deviceCache.delete(`${normalizedUserId}:${normalizedDeviceId}`);
  }

  private readCachedUser(userId: string): User | null | undefined {
    const cached = AuthService.userCache.get(userId);
    if (!cached) return undefined;
    if (cached.expiresAt <= Date.now()) {
      AuthService.userCache.delete(userId);
      return undefined;
    }
    return cached.user;
  }

  private writeCachedUser(userId: string, user: User | null): void {
    AuthService.userCache.set(userId, {
      user,
      expiresAt: Date.now() + AUTH_CONTEXT_CACHE_TTL_MS,
    });
  }

  private async getCachedUser(userId: string): Promise<User | null> {
    const cached = this.readCachedUser(userId);
    if (cached !== undefined) return cached;
    const user = await userRepo.getUserById(this.env.DB, userId);
    this.writeCachedUser(userId, user);
    return user;
  }

  private async getFreshUser(userId: string): Promise<User | null> {
    const user = await userRepo.getUserById(this.env.DB, userId);
    this.writeCachedUser(userId, user);
    return user;
  }

  private readCachedDevice(userId: string, deviceId: string) {
    const cacheKey = `${userId}:${deviceId}`;
    const cached = AuthService.deviceCache.get(cacheKey);
    if (!cached) return undefined;
    if (cached.expiresAt <= Date.now()) {
      AuthService.deviceCache.delete(cacheKey);
      return undefined;
    }
    return cached.device;
  }

  private writeCachedDevice(userId: string, deviceId: string, device: Device | null): void {
    const cacheKey = `${userId}:${deviceId}`;
    AuthService.deviceCache.set(cacheKey, {
      device,
      expiresAt: Date.now() + AUTH_CONTEXT_CACHE_TTL_MS,
    });
  }

  private async getCachedDevice(userId: string, deviceId: string) {
    const cached = this.readCachedDevice(userId, deviceId);
    if (cached !== undefined) return cached;
    const device = await deviceRepo.getDevice(this.env.DB, userId, deviceId);
    this.writeCachedDevice(userId, deviceId, device);
    return device;
  }

  private async getFreshDevice(userId: string, deviceId: string) {
    const device = await deviceRepo.getDevice(this.env.DB, userId, deviceId);
    this.writeCachedDevice(userId, deviceId, device);
    return device;
  }

  // Second-layer hash of the client hash (random salt, see auth-password.ts), so database contents alone
  // cannot be used to authenticate (pass-the-hash defense).
  async hashPasswordServer(clientHash: string): Promise<string> {
    return hashPassword(clientHash);
  }

  async verifyPassword(inputHash: string, storedHash: string, email: string): Promise<boolean> {
    return verifyPassword(inputHash, storedHash, email);
  }

  // Generate access token
  async generateAccessToken(user: User, device?: { identifier: string; sessionStamp: string } | null): Promise<string> {
    return createJWT(
      {
        sub: user.id,
        email: user.email,
        name: user.name,
        sstamp: user.securityStamp,
        ...(device?.identifier ? { did: device.identifier, dstamp: device.sessionStamp } : {}),
      },
      this.env.JWT_SECRET
    );
  }

  // Generate refresh token
  async generateRefreshToken(
    user: User,
    device?: { identifier: string; sessionStamp: string } | null,
    clientType: string = 'other'
  ): Promise<string> {
    const token = createRefreshToken();
    const now = Date.now();
    await sessionRepo.saveRefreshToken(
      this.env.DB,
      token,
      user.id,
      now + getRefreshTokenSlidingTtlMs(clientType),
      device?.identifier ?? null,
      device?.sessionStamp ?? null,
      user.securityStamp,
      clientType,
      now + LIMITS.auth.refreshTokenAbsoluteTtlMs
    );
    return token;
  }

  private async bearerPayload(authHeader: string | null): Promise<AccessClaims | null> {
    const parts = authHeader?.split(' ');
    return parts?.length === 2 && parts[0].toLowerCase() === 'bearer' ? verifyJWT(parts[1], this.env.JWT_SECRET) : null;
  }

  async verifyPrincipal(authHeader: string | null): Promise<Principal | null> {
    const payload = await this.bearerPayload(authHeader);
    if (!payload) return null;
    if (payload.type === 'ServiceAccount') {
      const now = Math.floor(Date.now() / 1000);
      if (!Array.isArray(payload.scope) || !payload.scope.includes('api.secrets') || typeof payload.organization !== 'string' || typeof payload.client_id !== 'string' || typeof payload.sub !== 'string' || typeof payload.exp !== 'number' || !Number.isFinite(payload.exp) || payload.exp <= now || typeof payload.nbf !== 'number' || payload.nbf > now || payload.iss !== 'nodewarden') return null;
      const token = await getAccessTokenWithAccount(this.env.DB, payload.client_id);
      if (!token || !token.key || token.serviceAccountId !== payload.sub || token.orgId !== payload.organization || (token.expireAt && !(Date.parse(token.expireAt) > Date.now()))) return null;
      return { kind: 'serviceAccount', serviceAccountId: token.serviceAccountId, orgId: token.orgId, accessTokenId: token.id };
    }
    const verified = await this.verifyUserPayload(payload);
    return verified ? { kind: 'user', ...verified } : null;
  }

  async verifyAccessTokenWithUser(authHeader: string | null): Promise<VerifiedAccessContext | null> {
    const payload = await this.bearerPayload(authHeader);
    if (!payload || payload.type === 'ServiceAccount') return null;
    return this.verifyUserPayload(payload);
  }

  private async verifyUserPayload(payload: JWTPayload): Promise<VerifiedAccessContext | null> {
    let user = await this.getCachedUser(payload.sub);
    if (!user || user.status !== 'active' || payload.sstamp !== user.securityStamp) {
      user = await this.getFreshUser(payload.sub);
    }
    if (!user) return null;
    if (user.status !== 'active') return null;

    if (payload.sstamp !== user.securityStamp) {
      return null;
    }

    if (payload.did) {
      let device = await this.getCachedDevice(user.id, payload.did);
      if (!device || !payload.dstamp || payload.dstamp !== device.sessionStamp) {
        device = await this.getFreshDevice(user.id, payload.did);
      }
      if (!device) return null;
      if (!payload.dstamp || payload.dstamp !== device.sessionStamp) return null;
    }

    return { payload, user };
  }

  // Verify access token from Authorization header
  async verifyAccessToken(authHeader: string | null): Promise<JWTPayload | null> {
    const verified = await this.verifyAccessTokenWithUser(authHeader);
    return verified?.payload ?? null;
  }

  // Refresh access token
  async refreshAccessTokenDetailed(refreshToken: string): Promise<RefreshAccessTokenResult> {
    const record = await sessionRepo.getRefreshTokenRecord(this.env.DB, refreshToken);
    if (!record?.userId) return { ok: false, reason: 'token_not_found_or_expired' };

    const user = await userRepo.getUserById(this.env.DB, record.userId);
    if (!user) {
      await sessionRepo.deleteRefreshToken(this.env.DB, refreshToken);
      return { ok: false, reason: 'user_missing', userId: record.userId, deviceIdentifier: record.deviceIdentifier };
    }
    if (user.status !== 'active') {
      await sessionRepo.deleteRefreshToken(this.env.DB, refreshToken);
      return { ok: false, reason: 'user_inactive', userId: user.id, deviceIdentifier: record.deviceIdentifier };
    }

    if (record.securityStamp && record.securityStamp !== user.securityStamp) {
      await sessionRepo.deleteRefreshToken(this.env.DB, refreshToken);
      return { ok: false, reason: 'security_stamp_mismatch', userId: user.id, deviceIdentifier: record.deviceIdentifier };
    }
    if (!record.securityStamp) {
      await sessionRepo.bindRefreshTokenSecurityStamp(this.env.DB, refreshToken, user.securityStamp);
    }

    let device: { identifier: string; sessionStamp: string } | null = null;
    if (record.deviceIdentifier) {
      const boundDevice = await deviceRepo.getDevice(this.env.DB, user.id, record.deviceIdentifier);
      if (!boundDevice) {
        await sessionRepo.deleteRefreshToken(this.env.DB, refreshToken);
        return { ok: false, reason: 'device_missing', userId: user.id, deviceIdentifier: record.deviceIdentifier };
      }
      if (record.deviceSessionStamp && boundDevice.sessionStamp !== record.deviceSessionStamp) {
        await sessionRepo.deleteRefreshToken(this.env.DB, refreshToken);
        return { ok: false, reason: 'device_session_mismatch', userId: user.id, deviceIdentifier: record.deviceIdentifier };
      }
      if (!record.deviceSessionStamp) {
        await sessionRepo.bindRefreshTokenDeviceStamp(this.env.DB, refreshToken, boundDevice.sessionStamp);
      }
      device = { identifier: boundDevice.deviceIdentifier, sessionStamp: boundDevice.sessionStamp };
    }

    const now = Date.now();
    const expiresAt = Math.min(
      now + getRefreshTokenSlidingTtlMs(record.clientType),
      record.absoluteExpiresAt || (now + LIMITS.auth.refreshTokenAbsoluteTtlMs)
    );
    const extended = await sessionRepo.extendRefreshTokenExpiry(this.env.DB, refreshToken, expiresAt, now);
    if (!extended) {
      return { ok: false, reason: 'token_not_found_or_expired', userId: user.id, deviceIdentifier: record.deviceIdentifier };
    }
    const accessToken = await this.generateAccessToken(user, device);
    return { ok: true, accessToken, user, device, expiresAt };
  }

  async refreshAccessToken(
    refreshToken: string
  ): Promise<{ accessToken: string; user: User; device: { identifier: string; sessionStamp: string } | null } | null> {
    const result = await this.refreshAccessTokenDetailed(refreshToken);
    return result.ok ? result : null;
  }
}
