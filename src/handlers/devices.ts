import type { Device, DevicePendingAuthRequest, DeviceResponse, ProtectedDeviceResponse as ProtectedDeviceWireResponse } from '../types';
import { Env } from '../types';
import { getOnlineUserDevices, notifyUserLogout } from '../durable/notifications-hub';
import { AuthService } from '../services/auth';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';
import { registerMobilePushDevice, unregisterMobilePushDevice } from '../services/push-relay';
import { z } from 'zod';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { DeviceInfoSchema, deviceText, readAuthRequestDeviceInfo, readKnownDeviceProbe } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import * as deviceRepo from '../services/storage-device-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

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

const storedKey = z.string().nullable().optional();
const DeviceKeysSchema = z.object({ encryptedUserKey: storedKey, encryptedPublicKey: storedKey, encryptedPrivateKey: storedKey });

// A key the body leaves out keeps the stored value; an explicit null clears it.
function withStoredKeys(keys: z.output<typeof DeviceKeysSchema>, stored?: Device) {
  return {
    encryptedUserKey: stored?.encryptedUserKey ?? null,
    encryptedPublicKey: stored?.encryptedPublicKey ?? null,
    encryptedPrivateKey: stored?.encryptedPrivateKey ?? null,
    ...keys,
  };
}

// Official clients name the device fields identifier/name/type; NodeWarden's own callers use the device* spelling.
const DeviceFieldsSchema = z.looseObject({}).transform((body) => ({
  ...body,
  deviceIdentifier: body.identifier ?? body.deviceIdentifier,
  deviceName: body.name ?? body.deviceName,
  deviceType: body.type ?? body.deviceType,
}));

const DEVICE_REQUIRED = { error: 'Device identifier and type are required' };
const RegisterDeviceSchema = DeviceFieldsSchema.pipe(DeviceKeysSchema.extend({
  deviceIdentifier: z.string(DEVICE_REQUIRED).trim().min(1, DEVICE_REQUIRED),
  deviceName: DeviceInfoSchema.shape.deviceName,
  deviceType: z.coerce.number(DEVICE_REQUIRED).int(DEVICE_REQUIRED).min(0, DEVICE_REQUIRED),
  pushToken: z.string().trim().catch(''),
}));

const NAME_REQUIRED = { error: 'Device name is required' };
const DeviceNameSchema = z.object({ name: z.string(NAME_REQUIRED).trim().min(1, NAME_REQUIRED).pipe(deviceText) });

const UpdateTrustSchema = z.object({
  currentDevice: DeviceKeysSchema.nullish(),
  otherDevices: z.array(DeviceKeysSchema.extend({ deviceId: z.string().trim().catch('') })).optional(),
});

const PASSWORD_REQUIRED = { error: 'masterPasswordHash is required' };
const MasterPasswordSchema = z.object({ masterPasswordHash: z.string(PASSWORD_REQUIRED).trim().min(1, PASSWORD_REQUIRED) });

const PUSH_TOKEN_INVALID = { error: 'Invalid push token' };
const PushTokenSchema = z.object({ pushToken: z.string(PUSH_TOKEN_INVALID).trim().min(1, PUSH_TOKEN_INVALID) });

// POST /api/devices
export async function handleRegisterDevice(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, RegisterDeviceSchema, 'Invalid request payload');
  if (body instanceof Response) return body;
  const { deviceIdentifier: identifier, deviceName: name, deviceType: type, pushToken, ...keys } = body;

  await deviceRepo.upsertDevice(env.DB, userId, identifier, name, type, undefined, keys);

  if (pushToken) {
    const device = await deviceRepo.getDevice(env.DB, userId, identifier);
    const pushUuid = device?.pushUuid || generateUUID();
    const updated = await deviceRepo.updateDevicePushToken(env.DB, userId, identifier, pushUuid, pushToken);
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

  const device = await deviceRepo.getDevice(env.DB, userId, identifier);
  if (!device) return errorResponse('Device registration failed', 500);
  await writeAuditEvent(env.DB, {
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
  // Official clients post no body and send the device in the Device-Identifier header.
  const deviceInfo = readAuthRequestDeviceInfo({}, request);
  if (!deviceInfo.deviceIdentifier) return errorResponse('Please provide a device identifier', 400);

  await writeAuditEvent(env.DB, {
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
  const { email, deviceIdentifier } = readKnownDeviceProbe(request);

  if (!email || !deviceIdentifier) {
    return jsonResponse(false);
  }

  const known = await deviceRepo.isKnownDeviceByEmail(env.DB, email, deviceIdentifier);
  return jsonResponse(known);
}

// GET /api/devices
export async function handleGetDevices(request: Request, env: Env, userId: string): Promise<Response> {
  void request;
  const devices = await deviceRepo.getDevicesByUserId(env.DB, userId);

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

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
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
  const [devices, trusted, onlineDeviceIdentifiers] = await Promise.all([
    deviceRepo.getDevicesByUserId(env.DB, userId),
    deviceRepo.getTrustedDeviceTokenSummariesByUserId(env.DB, userId),
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
  const removed = await deviceRepo.deleteTrustedTwoFactorTokensByUserId(env.DB, userId);
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

  const removed = await deviceRepo.deleteTrustedTwoFactorTokensByDevice(env.DB, userId, normalized);
  await writeAuditEvent(env.DB, {
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

  const updated = await deviceRepo.updateTrustedTwoFactorTokensExpiryByDevice(env.DB, userId, normalized, PERMANENT_TRUST_EXPIRES_AT_MS);
  if (!updated) return errorResponse('Device is not currently trusted', 409);
  await writeAuditEvent(env.DB, {
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

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
  await deviceRepo.deleteTrustedTwoFactorTokensByDevice(env.DB, userId, normalized);
  await sessionRepo.deleteRefreshTokensByDevice(env.DB, userId, normalized);
  const deleted = await deviceRepo.deleteDevice(env.DB, userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(env, userId, normalized);
  }
  await writeAuditEvent(env.DB, {
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

  const body = await parseBody(request, DeviceNameSchema, NAME_REQUIRED.error);
  if (body instanceof Response) return body;
  const { name } = body;

  const updated = await deviceRepo.updateDeviceName(env.DB, userId, normalized, name);
  if (!updated) return errorResponse('Device not found', 404);

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
  if (!device) return errorResponse('Device not found', 404);
  await writeAuditEvent(env.DB, {
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
  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) return errorResponse('User not found', 404);

  const body = await parseBody(request, MasterPasswordSchema, PASSWORD_REQUIRED.error);
  if (body instanceof Response) return body;
  const { masterPasswordHash } = body;
  const auth = new AuthService(env);
  const passwordValid = await auth.verifyPassword(masterPasswordHash, user.masterPasswordHash, user.email);
  if (!passwordValid) {
    return errorResponse('Invalid password', 400);
  }

  const originalSecurityStamp = user.securityStamp;
  user.securityStamp = generateUUID();
  user.updatedAt = new Date().toISOString();
  if (!await userRepo.saveUser(env.DB, user, ['securityStamp'], originalSecurityStamp)) return errorResponse('User verification failed.', 400);
  const [removedTrusted, removedSessions, removedDevices] = await Promise.all([
    deviceRepo.deleteTrustedTwoFactorTokensByUserId(env.DB, userId),
    sessionRepo.deleteRefreshTokensByUserId(env.DB, userId),
    deviceRepo.deleteDevicesByUserId(env.DB, userId),
  ]);
  AuthService.invalidateUserCache(userId);
  notifyUserLogout(env, userId, null);
  await writeAuditEvent(env.DB, {
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

  const keys = await parseBody(request, DeviceKeysSchema);
  if (keys instanceof Response) return keys;
  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
  if (!device) {
    return errorResponse('Device not found', 404);
  }

  const updated = await deviceRepo.updateDeviceKeys(env.DB, userId, normalized, withStoredKeys(keys, device));
  if (!updated) {
    return errorResponse('Device not found', 404);
  }

  const nextDevice = await deviceRepo.getDevice(env.DB, userId, normalized);
  return jsonResponse(buildDeviceResponse(nextDevice || device));
}

// POST /api/devices/update-trust
export async function handleUpdateDeviceTrust(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await parseBody(request, UpdateTrustSchema);
  if (body instanceof Response) return body;
  const currentDeviceIdentifier =
    normalizeIdentifier(request.headers.get('Device-Identifier')) ||
    normalizeIdentifier(request.headers.get('X-Device-Identifier'));
  const requested = [
    ...(currentDeviceIdentifier && body.currentDevice ? [{ ...body.currentDevice, deviceId: currentDeviceIdentifier }] : []),
    ...(body.otherDevices ?? []).filter((item) => item.deviceId),
  ];

  let updatedCount = 0;
  for (const { deviceId, ...keys } of requested) {
    const stored = await deviceRepo.getDevice(env.DB, userId, deviceId) || undefined;
    if (await deviceRepo.updateDeviceKeys(env.DB, userId, deviceId, withStoredKeys(keys, stored))) updatedCount++;
  }

  return jsonResponse({ success: true, updated: updatedCount });
}

// POST /api/devices/untrust
export async function handleUntrustDevices(
  request: Request,
  env: Env,
  userId: string
): Promise<Response> {
  const body = await parseBody(request, z.object({ devices: z.array(z.coerce.string().trim()).default([]) }));
  if (body instanceof Response) return body;
  const { devices } = body;
  const removed = await deviceRepo.clearDeviceKeys(env.DB, userId, devices);
  for (const deviceIdentifier of devices) {
    if (!deviceIdentifier) continue;
    await deviceRepo.deleteTrustedTwoFactorTokensByDevice(env.DB, userId, deviceIdentifier);
  }
  await writeAuditEvent(env.DB, {
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

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
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

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
  await deviceRepo.deleteTrustedTwoFactorTokensByDevice(env.DB, userId, normalized);
  await sessionRepo.deleteRefreshTokensByDevice(env.DB, userId, normalized);
  const deleted = await deviceRepo.deleteDevice(env.DB, userId, normalized);
  if (deleted) {
    await unregisterMobilePushDevice(env, device?.pushUuid);
    AuthService.invalidateDeviceCache(userId, normalized);
    notifyUserLogout(env, userId, normalized);
  }
  await writeAuditEvent(env.DB, {
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

  const body = await parseBody(request, PushTokenSchema, PUSH_TOKEN_INVALID.error);
  if (body instanceof Response) return body;
  const { pushToken } = body;

  const device = await deviceRepo.getDevice(env.DB, userId, normalized);
  if (!device) return errorResponse('Device not found', 404);

  const pushUuid = device.pushUuid || generateUUID();
  const updated = await deviceRepo.updateDevicePushToken(env.DB, userId, normalized, pushUuid, pushToken);
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
