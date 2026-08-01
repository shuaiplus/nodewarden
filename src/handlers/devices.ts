import type { Device, DevicePendingAuthRequest, DeviceResponse, ProtectedDeviceResponse as ProtectedDeviceWireResponse } from '../types';
import { Env } from '../types';
import { getOnlineUserDevices, notifyUserLogout } from '../durable/notifications-hub';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { registerMobilePushDevice, unregisterMobilePushDevice } from '../services/push-relay';
import { StorageService } from '../services/storage';
import { errorResponse, jsonResponse } from '../utils/response';
import { readAuthRequestDeviceInfo, readKnownDeviceProbe } from '../utils/device';
import { generateUUID } from '../utils/uuid';

const PERMANENT_TRUST_EXPIRES_AT_MS = Date.UTC(2099, 11, 31, 23, 59, 59);

function normalizeIdentifier(value: string | null | undefined): string {
  return String(value || '').trim();
}

function buildDevicePendingAuthRequest(value?: { id?: string | null; creationDate?: string | null } | null): DevicePendingAuthRequest | null {
  if (!value?.id || !value.creationDate) return null;
  return {
    id: String(value.id),
    creationDate: String(value.creationDate),
  };
}

function isTrustedDevice(device: Pick<Device, 'encryptedUserKey' | 'encryptedPublicKey'>): boolean {
  return !!(device.encryptedUserKey && device.encryptedPublicKey);
}

function buildDeviceResponse(device: Device): DeviceResponse {
  const displayName = String(device.deviceNote || '').trim() || device.name;
  const response = {
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    UserId: device.userId,
    userId: device.userId,
    Name: displayName,
    name: displayName,
    SystemName: device.name,
    systemName: device.name,
    DeviceNote: device.deviceNote,
    deviceNote: device.deviceNote,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    RevisionDate: device.updatedAt,
    revisionDate: device.updatedAt,
    LastActivityDate: device.lastSeenAt,
    lastActivityDate: device.lastSeenAt,
    LastSeenAt: device.lastSeenAt,
    lastSeenAt: device.lastSeenAt,
    HasStoredDevice: true,
    hasStoredDevice: true,
    IsTrusted: isTrustedDevice(device),
    isTrusted: isTrustedDevice(device),
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    DevicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    devicePendingAuthRequest: buildDevicePendingAuthRequest(device.devicePendingAuthRequest),
    object: 'device',
  };
  return response as DeviceResponse;
}

function buildProtectedDeviceResponse(device: Device): ProtectedDeviceWireResponse {
  const response = {
    Id: device.deviceIdentifier,
    id: device.deviceIdentifier,
    Name: String(device.deviceNote || '').trim() || device.name,
    name: String(device.deviceNote || '').trim() || device.name,
    SystemName: device.name,
    systemName: device.name,
    DeviceNote: device.deviceNote,
    deviceNote: device.deviceNote,
    Identifier: device.deviceIdentifier,
    identifier: device.deviceIdentifier,
    Type: device.type,
    type: device.type,
    CreationDate: device.createdAt,
    creationDate: device.createdAt,
    EncryptedUserKey: device.encryptedUserKey,
    encryptedUserKey: device.encryptedUserKey,
    EncryptedPublicKey: device.encryptedPublicKey,
    encryptedPublicKey: device.encryptedPublicKey,
    object: 'protectedDevice',
  };
  return response as ProtectedDeviceWireResponse;
}

function parseKeysBody(body: any, fallback?: Device): {
  encryptedUserKey?: string | null;
  encryptedPublicKey?: string | null;
  encryptedPrivateKey?: string | null;
} {
  return {
    encryptedUserKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedUserKey')
        ? body?.encryptedUserKey ?? null
        : fallback?.encryptedUserKey ?? null,
    encryptedPublicKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedPublicKey')
        ? body?.encryptedPublicKey ?? null
        : fallback?.encryptedPublicKey ?? null,
    encryptedPrivateKey:
      Object.prototype.hasOwnProperty.call(body || {}, 'encryptedPrivateKey')
        ? body?.encryptedPrivateKey ?? null
        : fallback?.encryptedPrivateKey ?? null,
  };
}

async function readJsonBody(request: Request): Promise<any> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function parseDeviceName(value: unknown): string {
  return String(value || '').trim().slice(0, 128);
}

function parseDeviceType(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return Math.max(0, Math.floor(value));
  const parsed = Number.parseInt(String(value ?? ''), 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

// POST /api/devices
export async function handleRegisterDevice(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);

  const identifier = normalizeIdentifier(body.identifier ?? body.Identifier ?? body.deviceIdentifier ?? body.DeviceIdentifier);
  const name = parseDeviceName(body.name ?? body.Name ?? body.deviceName ?? body.DeviceName) || 'Unknown device';
  const type = parseDeviceType(body.type ?? body.Type ?? body.deviceType ?? body.DeviceType);
  if (!identifier || type == null) return errorResponse('Device identifier and type are required', 400);

  const storage = new StorageService(env.DB);
  await storage.upsertDevice(userId, identifier, name, type, undefined, parseKeysBody(body));

  const pushToken = String(body.pushToken ?? body.PushToken ?? '').trim();
  if (pushToken) {
    const device = await storage.getDevice(userId, identifier);
    const pushUuid = device?.pushUuid || generateUUID();
    const updated = await storage.updateDevicePushToken(userId, identifier, pushUuid, pushToken);
    if (updated) {
      await registerMobilePushDevice(env, {
        userId,
        deviceIdentifier: identifier,
        type,
        pushUuid,
        pushToken,
      });
    }
  }

  const device = await storage.getDevice(userId, identifier);
  if (!device) return errorResponse('Device registration failed', 500);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.register',
    category: 'device',
    level: 'info',
    targetType: 'device',
    targetId: identifier,
    metadata: auditRequestMetadata(request),
  });
  return jsonResponse(buildDeviceResponse(device));
}

// POST /api/devices/lost-trust
export async function handleReportLostTrust(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await readJsonBody(request) || {};
  const deviceInfo = readAuthRequestDeviceInfo(
    {
      deviceIdentifier: String(body.identifier ?? body.Identifier ?? body.deviceIdentifier ?? body.DeviceIdentifier ?? ''),
      deviceName: String(body.name ?? body.Name ?? body.deviceName ?? body.DeviceName ?? ''),
      deviceType: String(body.type ?? body.Type ?? body.deviceType ?? body.DeviceType ?? ''),
    },
    request
  );
  if (!deviceInfo.deviceIdentifier) return errorResponse('Please provide a device identifier', 400);

  const storage = new StorageService(env.DB);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.lost_trust',
    category: 'device',
    level: 'warn',
    targetType: 'device',
    targetId: deviceInfo.deviceIdentifier,
    metadata: {
      deviceIdentifier: deviceInfo.deviceIdentifier,
      deviceType: deviceInfo.deviceType,
      ...auditRequestMetadata(request),
    },
  });
  return new Response(null, { status: 200 });
}

// GET /api/devices/knowndevice
// Compatible with Bitwarden/Vaultwarden behavior:
// - X-Request-Email: base64url(email) without padding
// - X-Device-Identifier: client device identifier
export async function handleKnownDevice(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const { email, deviceIdentifier } = readKnownDeviceProbe(request);

  if (!email || !deviceIdentifier) {
    return jsonResponse(false);
  }

  const known = await storage.isKnownDeviceByEmail(email, deviceIdentifier);
  return jsonResponse(known);
}

// GET /api/devices
export async function handleGetDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const devices = await storage.getDevicesByUserId(userId);

  return jsonResponse({
    data: devices.map((device) => buildDeviceResponse(device)),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/devices/identifier/:deviceIdentifier
export async function handleGetDeviceByIdentifier(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  return jsonResponse(buildDeviceResponse(device));
}

// GET /api/devices/:deviceIdentifier
export async function handleGetDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  return handleGetDeviceByIdentifier(request, env, userId, deviceIdentifier);
}

// GET /api/devices/authorized
// Returns known devices together with active 2FA remember-token expiry.
export async function handleGetAuthorizedDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const [devices, trusted, onlineDeviceIdentifiers] = await Promise.all([
    storage.getDevicesByUserId(userId),
    storage.getTrustedDeviceTokenSummariesByUserId(userId),
    getOnlineUserDevices(env, userId),
  ]);
  const onlineSet = new Set(onlineDeviceIdentifiers);

  const trustedByIdentifier = new Map<string, { expiresAt: number; tokenCount: number }>();
  for (const row of trusted) {
    trustedByIdentifier.set(row.deviceIdentifier, { expiresAt: row.expiresAt, tokenCount: row.tokenCount });
  }

  const knownIdentifiers = new Set<string>();
  const data = devices.map(device => {
    knownIdentifiers.add(device.deviceIdentifier);
    const trustedInfo = trustedByIdentifier.get(device.deviceIdentifier);
    return {
      ...buildDeviceResponse(device),
      online: onlineSet.has(device.deviceIdentifier),
      trusted: !!trustedInfo,
      trustedTokenCount: trustedInfo?.tokenCount || 0,
      trustedUntil: trustedInfo?.expiresAt ? new Date(trustedInfo.expiresAt).toISOString() : null,
      object: 'device',
    };
  });

  for (const row of trusted) {
    if (knownIdentifiers.has(row.deviceIdentifier)) continue;
    const placeholderDevice: Device = {
      userId,
      deviceIdentifier: row.deviceIdentifier,
      name: 'Unknown device',
      type: 14,
      sessionStamp: '',
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      pushUuid: null,
      pushToken: null,
      devicePendingAuthRequest: null,
      deviceNote: null,
      lastSeenAt: null,
      createdAt: '',
      updatedAt: '',
    };
    data.push({
      ...buildDeviceResponse(placeholderDevice),
      isTrusted: true,
      hasStoredDevice: false,
      online: onlineSet.has(row.deviceIdentifier),
      trusted: true,
      trustedTokenCount: row.tokenCount,
      trustedUntil: row.expiresAt ? new Date(row.expiresAt).toISOString() : null,
      object: 'device',
    });
  }

  return jsonResponse({
    data,
    object: 'list',
    continuationToken: null,
  });
}

// DELETE /api/devices/authorized
export async function handleRevokeAllTrustedDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const removed = await storage.deleteTrustedTwoFactorTokensByUserId(userId);
  return jsonResponse({ success: true, removed });
}

// DELETE /api/devices/authorized/:deviceIdentifier
export async function handleRevokeTrustedDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const removed = await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.trust.revoke',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { removed, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ success: true, removed });
}

// POST /api/devices/authorized/:deviceIdentifier/permanent
// Upgrades an existing active 2FA remember-token record to permanent trust.
export async function handleTrustDevicePermanently(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const updated = await storage.updateTrustedTwoFactorTokensExpiryByDevice(userId, normalized, PERMANENT_TRUST_EXPIRES_AT_MS);
  if (!updated) return errorResponse('Device is not currently trusted', 409);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.trust.permanent',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { updated, ...auditRequestMetadata(request) },
  });

  return jsonResponse({
    success: true,
    updated,
    trustedUntil: new Date(PERMANENT_TRUST_EXPIRES_AT_MS).toISOString(),
  });
}

// DELETE /api/devices/:deviceIdentifier
export async function handleDeleteDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await storage.deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await storage.deleteDevice(userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(env, userId, normalized);
  }
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.delete',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { deleted, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ success: deleted });
}

// PUT /api/devices/:deviceIdentifier/name
export async function handleUpdateDeviceName(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  const normalized = String(deviceIdentifier || '').trim();
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const body = await readJsonBody(request);
  const name = parseDeviceName(body?.name);
  if (!name) return errorResponse('Device name is required', 400);

  const storage = new StorageService(env.DB);
  const updated = await storage.updateDeviceName(userId, normalized, name);
  if (!updated) return errorResponse('Device not found', 404);

  const device = await storage.getDevice(userId, normalized);
  if (!device) return errorResponse('Device not found', 404);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.name.update',
    category: 'device',
    level: 'info',
    targetType: 'device',
    targetId: normalized,
    metadata: { name, ...auditRequestMetadata(request) },
  });
  return jsonResponse(buildDeviceResponse(device));
}

// DELETE /api/devices
export async function handleDeleteAllDevices(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const user = await storage.getUserById(userId);
  if (!user) return errorResponse('User not found', 404);

  let masterPasswordHash = '';
  try {
    const body = await request.json() as { masterPasswordHash?: string };
    masterPasswordHash = String(body?.masterPasswordHash || '').trim();
  } catch {
    masterPasswordHash = '';
  }
  if (!masterPasswordHash) {
    return errorResponse('masterPasswordHash is required', 400);
  }
  const auth = new AuthService(env);
  const passwordValid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  const [removedTrusted, removedSessions, removedDevices] = await Promise.all([
    storage.deleteTrustedTwoFactorTokensByUserId(userId),
    storage.deleteRefreshTokensByUserId(userId),
    storage.deleteDevicesByUserId(userId),
  ]);
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  await storage.saveUser(user);
  AuthService.invalidateUserCache(userId);
  notifyUserLogout(env, userId, null);
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.delete_all',
    category: 'device',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: { removedTrusted, removedSessions, removedDevices, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ success: true, removedTrusted, removedSessions: removedSessions ?? 0, removedDevices });
}

// PUT/POST /api/devices/identifier/:deviceIdentifier/keys
export async function handleUpdateDeviceKeys(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  const updated = await storage.updateDeviceKeys(userId, normalized, parseKeysBody(body, device));
  if (!updated) {
    return errorResponse('Device not found', 404);
  }

  const nextDevice = await storage.getDevice(userId, normalized);
  return jsonResponse(buildDeviceResponse(nextDevice || device));
}

// POST /api/devices/update-trust
export async function handleUpdateDeviceTrust(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const currentDeviceIdentifier =
    normalizeIdentifier(request.headers.get('Device-Identifier')) ||
    normalizeIdentifier(request.headers.get('X-Device-Identifier'));

  const updates: Array<{
    deviceIdentifier: string;
    keys: {
      encryptedUserKey?: string | null;
      encryptedPublicKey?: string | null;
      encryptedPrivateKey?: string | null;
    };
  }> = [];

  if (currentDeviceIdentifier && body?.currentDevice) {
    updates.push({
      deviceIdentifier: currentDeviceIdentifier,
      keys: parseKeysBody(body.currentDevice, await storage.getDevice(userId, currentDeviceIdentifier) || undefined),
    });
  }

  if (Array.isArray(body?.otherDevices)) {
    for (const item of body.otherDevices) {
      const deviceIdentifier = normalizeIdentifier(item?.deviceId);
      if (!deviceIdentifier) continue;
      updates.push({
        deviceIdentifier,
        keys: parseKeysBody(item, await storage.getDevice(userId, deviceIdentifier) || undefined),
      });
    }
  }

  let updatedCount = 0;
  for (const update of updates) {
    const ok = await storage.updateDeviceKeys(userId, update.deviceIdentifier, update.keys);
    if (ok) updatedCount++;
  }

  return jsonResponse({ success: true, updated: updatedCount });
}

// POST /api/devices/untrust
export async function handleUntrustDevices(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await readJsonBody(request);
  const storage = new StorageService(env.DB);
  const devices = Array.isArray(body?.devices) ? body.devices.map((id: unknown) => normalizeIdentifier(String(id))) : [];
  const removed = await storage.clearDeviceKeys(userId, devices);
  for (const deviceIdentifier of devices) {
    if (!deviceIdentifier) continue;
    await storage.deleteTrustedTwoFactorTokensByDevice(userId, deviceIdentifier);
  }
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.trust.revoke_batch',
    category: 'device',
    level: 'security',
    targetType: 'user',
    targetId: userId,
    metadata: { requested: devices.length, removed, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ success: true, removed });
}

// POST /api/devices/:deviceIdentifier/retrieve-keys
export async function handleRetrieveDeviceKeys(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  return jsonResponse(buildProtectedDeviceResponse(device));
}

// POST /api/devices/:id/deactivate
export async function handleDeactivateDevice(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  await storage.deleteTrustedTwoFactorTokensByDevice(userId, normalized);
  await storage.deleteRefreshTokensByDevice(userId, normalized);
  const deleted = await storage.deleteDevice(userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(env, userId, normalized);
  }
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action: 'device.deactivate',
    category: 'device',
    level: 'security',
    targetType: 'device',
    targetId: normalized,
    metadata: { deleted, ...auditRequestMetadata(request) },
  });
  return jsonResponse({ success: deleted });
}

// PUT /api/devices/identifier/{deviceIdentifier}/token
// Bitwarden mobile reports APNs/FCM push token updates to this endpoint.
export async function handleUpdateDeviceToken(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const body = await readJsonBody(request);
  const pushToken = String(body?.pushToken ?? body?.PushToken ?? '').trim();
  if (!pushToken) return errorResponse('Invalid push token', 400);

  const storage = new StorageService(env.DB);
  const device = await storage.getDevice(userId, normalized);
  if (!device) return errorResponse('Device not found', 404);

  const pushUuid = device.pushUuid || generateUUID();
  const updated = await storage.updateDevicePushToken(userId, normalized, pushUuid, pushToken);
  if (updated) {
    await registerMobilePushDevice(env, {
      userId,
      deviceIdentifier: normalized,
      type: device.type,
      pushUuid,
      pushToken,
    });
  }

  return new Response(null, { status: 200 });
}

// PUT/POST /api/devices/:deviceIdentifier/web-push-auth
export async function handleUpdateDeviceWebPushAuth(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  void env;
  void userId;
  void deviceIdentifier;
  return new Response(null, { status: 200 });
}

// PUT/POST /api/devices/:deviceIdentifier/clear-token
export async function handleClearDeviceToken(
  request: Request,
  env: Env,
  userId: string,
  deviceIdentifier: string
): Promise<Response> {
  void request;
  const normalized = normalizeIdentifier(deviceIdentifier);
  if (!normalized) return errorResponse('Invalid device identifier', 400);

  const storage = new StorageService(env.DB);
  const cleared = await storage.clearDevicePushToken(userId, normalized);
  if (cleared?.pushUuid) {
    await unregisterMobilePushDevice(env, cleared.pushUuid);
  }

  return new Response(null, { status: 200 });
}

