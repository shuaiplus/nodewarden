import type { AuthRequestRecord, AuthRequestType, Env } from '../types';
import { StorageService } from '../services/storage';
import { generateUUID } from '../utils/uuid';
import { readAuthRequestDeviceInfo, readActingDeviceIdentifier } from '../utils/device';
import { errorResponse, jsonResponse } from '../utils/response';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import { notifyAuthRequestResponse, notifyUserAuthRequest } from '../durable/notifications-hub';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { LIMITS } from '../config/limits';

const AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK = 0;
const AUTH_REQUEST_TYPE_UNLOCK = 1;
const AUTH_REQUEST_TYPE_ADMIN_APPROVAL = 2;

function normalizeText(value: unknown, maxLength: number): string {
  return String(value ?? '').trim().slice(0, maxLength);
}

function isSerializedEncString(value: unknown): value is string {
  const text = String(value || '').trim();
  if (!text) return false;
  const parts = text.split('.');
  if (parts.length !== 2) return false;
  const type = Number(parts[0]);
  const bodyParts = parts[1].split('|');
  if (type === 2) return bodyParts.length === 3 && bodyParts.every(Boolean);
  if (type === 3 || type === 4) return bodyParts.length === 1 && !!bodyParts[0];
  if (type === 5 || type === 6) return bodyParts.length === 2 && bodyParts.every(Boolean);
  return false;
}

function getClientIp(request: Request): string | null {
  return (
    request.headers.get('CF-Connecting-IP') ||
    request.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() ||
    null
  );
}

function getCountryName(request: Request): string | null {
  return request.headers.get('CF-IPCountry') || null;
}

function deviceTypeName(type: number): string {
  const names: Record<number, string> = {
    0: 'Android',
    1: 'iOS',
    2: 'Chrome Extension',
    3: 'Firefox Extension',
    4: 'Opera Extension',
    5: 'Edge Extension',
    6: 'Windows Desktop',
    7: 'macOS Desktop',
    8: 'Linux Desktop',
    9: 'Chrome',
    10: 'Firefox',
    11: 'Opera',
    12: 'Edge',
    13: 'Internet Explorer',
    14: 'Unknown Browser',
    15: 'Android',
    16: 'Windows UWP',
    17: 'Safari',
    18: 'Vivaldi',
    19: 'Vivaldi Extension',
    20: 'Safari Extension',
    21: 'SDK',
    22: 'Server',
    23: 'Windows CLI',
    24: 'macOS CLI',
    25: 'Linux CLI',
    26: 'DuckDuckGo',
  };
  return names[type] || `Device ${type}`;
}

function buildOrigin(request: Request): string {
  return new URL(request.url).host;
}

function toAuthRequestResponse(request: Request, authRequest: AuthRequestRecord, requestDeviceId?: string | null) {
  return {
    id: authRequest.id,
    Id: authRequest.id,
    publicKey: authRequest.publicKey,
    PublicKey: authRequest.publicKey,
    requestDeviceIdentifier: authRequest.requestDeviceIdentifier,
    RequestDeviceIdentifier: authRequest.requestDeviceIdentifier,
    requestDeviceTypeValue: authRequest.requestDeviceType,
    RequestDeviceTypeValue: authRequest.requestDeviceType,
    requestDeviceType: deviceTypeName(authRequest.requestDeviceType),
    RequestDeviceType: deviceTypeName(authRequest.requestDeviceType),
    requestIpAddress: authRequest.requestIpAddress,
    RequestIpAddress: authRequest.requestIpAddress,
    requestCountryName: authRequest.requestCountryName,
    RequestCountryName: authRequest.requestCountryName,
    key: authRequest.key,
    Key: authRequest.key,
    masterPasswordHash: null,
    MasterPasswordHash: null,
    creationDate: authRequest.creationDate,
    CreationDate: authRequest.creationDate,
    responseDate: authRequest.responseDate,
    ResponseDate: authRequest.responseDate,
    requestApproved: authRequest.approved ?? false,
    RequestApproved: authRequest.approved ?? false,
    requestDeviceId: requestDeviceId ?? null,
    RequestDeviceId: requestDeviceId ?? null,
    origin: buildOrigin(request),
    Origin: buildOrigin(request),
    object: 'auth-request',
    Object: 'auth-request',
  };
}

function listResponse<T>(data: T[]) {
  return {
    data,
    Data: data,
    object: 'list',
    Object: 'list',
    continuationToken: null,
    ContinuationToken: null,
  };
}

async function readJsonBody(request: Request): Promise<Record<string, any> | null> {
  try {
    const body = await request.json();
    return body && typeof body === 'object' ? body as Record<string, any> : null;
  } catch {
    return null;
  }
}

async function enforceAuthRequestCreateRateLimit(
  request: Request,
  env: Env,
  email: string,
  deviceIdentifier: string
): Promise<Response | null> {
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) return errorResponse('Client IP is required', 403);

  const rateLimit = new RateLimitService(env.DB);
  const limit = LIMITS.rateLimit.authRequestRequestsPerMinute;
  const encodedEmail = encodeURIComponent(email || 'missing');
  const encodedDevice = encodeURIComponent(deviceIdentifier || 'missing');
  const budgets = await Promise.all([
    rateLimit.consumeStrictBudget(`auth-request:ip:${clientIdentifier}`, limit),
    rateLimit.consumeStrictBudget(`auth-request:email:${encodedEmail}`, limit),
    rateLimit.consumeStrictBudget(`auth-request:device:${encodedDevice}`, limit),
  ]);
  const blocked = budgets.find((budget) => !budget.allowed);
  if (!blocked) return null;

  return errorResponse('Too many authentication requests. Try again later.', 429);
}

function readBodyValue(body: Record<string, any>, names: string[]): unknown {
  for (const name of names) {
    if (body[name] !== undefined) return body[name];
  }
  return undefined;
}

function isSupportedAuthRequestType(value: number): value is AuthRequestType {
  return value === AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK || value === AUTH_REQUEST_TYPE_UNLOCK || value === AUTH_REQUEST_TYPE_ADMIN_APPROVAL;
}

export async function handleCreateAuthRequest(request: Request, env: Env): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);

  const email = normalizeText(readBodyValue(body, ['email', 'Email']), 320).toLowerCase();
  const publicKey = normalizeText(readBodyValue(body, ['publicKey', 'PublicKey']), 8192);
  const accessCode = normalizeText(readBodyValue(body, ['accessCode', 'AccessCode']), 25);
  const requestedType = Number(readBodyValue(body, ['type', 'Type']));
  const type = Number.isFinite(requestedType) ? requestedType : AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK;
  const deviceInfo = readAuthRequestDeviceInfo(
    {
      deviceIdentifier: normalizeText(readBodyValue(body, ['deviceIdentifier', 'DeviceIdentifier']), 128),
      deviceName: normalizeText(readBodyValue(body, ['deviceName', 'DeviceName']), 128),
      deviceType: String(readBodyValue(body, ['deviceType', 'DeviceType']) ?? ''),
    },
    request
  );

  if (!email || !publicKey || !accessCode || !deviceInfo.deviceIdentifier) {
    return errorResponse('Email, public key, device identifier, and access code are required.', 400);
  }
  const rateLimitResponse = await enforceAuthRequestCreateRateLimit(request, env, email, deviceInfo.deviceIdentifier);
  if (rateLimitResponse) return rateLimitResponse;
  if (!isSupportedAuthRequestType(type) || type === AUTH_REQUEST_TYPE_ADMIN_APPROVAL) {
    return errorResponse('Invalid auth request type.', 400);
  }

  const user = await storage.getUser(email);
  if (!user || user.status !== 'active') {
    return errorResponse('User or known device not found.', 400);
  }

  await storage.pruneExpiredAuthRequests();
  const now = new Date().toISOString();
  const authRequest: AuthRequestRecord = {
    id: generateUUID(),
    userId: user.id,
    organizationId: null,
    type,
    requestDeviceIdentifier: deviceInfo.deviceIdentifier,
    requestDeviceType: deviceInfo.deviceType,
    requestIpAddress: getClientIp(request),
    requestCountryName: getCountryName(request),
    responseDeviceIdentifier: null,
    accessCode,
    publicKey,
    key: null,
    masterPasswordHash: null,
    approved: null,
    creationDate: now,
    responseDate: null,
    authenticationDate: null,
  };
  await storage.createAuthRequest(authRequest);
  notifyUserAuthRequest(env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleCreateAdminAuthRequest(
  request: Request,
  env: Env,
  userId: string,
  userEmail: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);

  const email = normalizeText(readBodyValue(body, ['email', 'Email']), 320).toLowerCase() || userEmail.toLowerCase();
  const publicKey = normalizeText(readBodyValue(body, ['publicKey', 'PublicKey']), 8192);
  const accessCode = normalizeText(readBodyValue(body, ['accessCode', 'AccessCode']), 25);
  const requestedType = Number(readBodyValue(body, ['type', 'Type']));
  const deviceInfo = readAuthRequestDeviceInfo(
    {
      deviceIdentifier: normalizeText(readBodyValue(body, ['deviceIdentifier', 'DeviceIdentifier']), 128),
      deviceName: normalizeText(readBodyValue(body, ['deviceName', 'DeviceName']), 128),
      deviceType: String(readBodyValue(body, ['deviceType', 'DeviceType']) ?? ''),
    },
    request
  );

  if (requestedType !== AUTH_REQUEST_TYPE_ADMIN_APPROVAL) {
    return errorResponse('Invalid AuthRequestType. Expected AdminApproval.', 400);
  }
  if (email !== userEmail.toLowerCase()) {
    return errorResponse('Email does not match authenticated user.', 400);
  }
  if (!publicKey || !accessCode || !deviceInfo.deviceIdentifier) {
    return errorResponse('Public key, device identifier, and access code are required.', 400);
  }
  const rateLimitResponse = await enforceAuthRequestCreateRateLimit(request, env, email, deviceInfo.deviceIdentifier);
  if (rateLimitResponse) return rateLimitResponse;

  const user = await storage.getUserById(userId);
  if (!user || user.status !== 'active') {
    return errorResponse('User not found.', 404);
  }

  await storage.pruneExpiredAuthRequests();
  const now = new Date().toISOString();
  const authRequest: AuthRequestRecord = {
    id: generateUUID(),
    userId: user.id,
    organizationId: null,
    type: AUTH_REQUEST_TYPE_ADMIN_APPROVAL,
    requestDeviceIdentifier: deviceInfo.deviceIdentifier,
    requestDeviceType: deviceInfo.deviceType,
    requestIpAddress: getClientIp(request),
    requestCountryName: getCountryName(request),
    responseDeviceIdentifier: null,
    accessCode,
    publicKey,
    key: null,
    masterPasswordHash: null,
    approved: null,
    creationDate: now,
    responseDate: null,
    authenticationDate: null,
  };
  await storage.createAuthRequest(authRequest);
  notifyUserAuthRequest(env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleGetAuthRequest(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const authRequest = await storage.getAuthRequestByIdForUser(id, userId);
  if (!authRequest || authRequest.userId !== userId) return errorResponse('Not found', 404);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleGetAuthRequestResponse(request: Request, env: Env, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const accessCode = normalizeText(url.searchParams.get('code'), 25);
  const authRequest = await storage.getAuthRequestById(id);
  if (!authRequest || authRequest.accessCode !== accessCode || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleListAuthRequests(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const authRequests = await storage.listAuthRequestsByUserId(userId);
  return jsonResponse(listResponse(authRequests.map((authRequest) => toAuthRequestResponse(request, authRequest))));
}

export async function handleListPendingAuthRequests(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  await storage.pruneExpiredAuthRequests();
  const authRequests = await storage.listPendingAuthRequestsByUserId(userId);
  const rows = await Promise.all(authRequests.map(async (authRequest) => {
    const device = await storage.getDevice(userId, authRequest.requestDeviceIdentifier);
    return toAuthRequestResponse(request, authRequest, device?.deviceIdentifier ?? authRequest.requestDeviceIdentifier);
  }));
  return jsonResponse(listResponse(rows));
}

export async function handleUpdateAuthRequest(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid request payload', 400);

  const authRequest = await storage.getAuthRequestByIdForUser(id, userId);
  if (!authRequest || authRequest.userId !== userId || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }
  if (authRequest.approved !== null || authRequest.responseDate || authRequest.authenticationDate) {
    return errorResponse('Auth request has already been answered.', 409);
  }

  const latestForUser = await storage.listPendingAuthRequestsByUserId(userId);
  const latestForDevice = latestForUser.find((item) => item.requestDeviceIdentifier === authRequest.requestDeviceIdentifier);
  if (latestForDevice?.id !== authRequest.id) {
    return errorResponse('This request is no longer valid. Make sure to approve the most recent request.', 400);
  }

  const approved = Boolean(readBodyValue(body, ['requestApproved', 'RequestApproved']));
  const key = normalizeText(readBodyValue(body, ['key', 'Key']), 20000);
  const responseDeviceIdentifier =
    normalizeText(readBodyValue(body, ['deviceIdentifier', 'DeviceIdentifier']), 128) ||
    readActingDeviceIdentifier(request) ||
    'web';

  if (approved && !key) {
    return errorResponse('Encrypted key is required to approve the request.', 400);
  }
  if (approved && !isSerializedEncString(key)) {
    return errorResponse('Encrypted key is not a valid encrypted string.', 400);
  }

  const updated = await storage.updateAuthRequestResponse(id, userId, {
    approved,
    responseDeviceIdentifier,
    key,
    masterPasswordHash: null,
  });
  if (!updated) return errorResponse('Auth request has already been answered.', 409);
  const updatedRequest = await storage.getAuthRequestByIdForUser(id, userId);
  // Match Bitwarden upstream behavior: only approval wakes the originating anonymous
  // client. Denials are not pushed to avoid leaking that a login attempt was rejected.
  if (approved) {
    await notifyAuthRequestResponse(env, userId, id);
  }
  return jsonResponse(toAuthRequestResponse(request, updatedRequest || authRequest));
}
