import type { AuthRequestRecord, AuthRequestType, Env } from '../types';
import { generateUUID } from '../utils/uuid';
import { z } from 'zod';
import { deviceTypeName, readAuthRequestDeviceInfo, readActingDeviceIdentifier } from '../utils/device';
import { isSerializedEncString } from '../utils/account-passkeys';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import { notifyAuthRequestResponse, notifyUserAuthRequest } from '../durable/notifications-hub';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { LIMITS } from '../config/limits';
import * as authRequestRepo from '../services/storage-auth-request-repo';
import * as deviceRepo from '../services/storage-device-repo';
import * as userRepo from '../services/storage-user-repo';

const AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK = 0;
const AUTH_REQUEST_TYPE_UNLOCK = 1;
const AUTH_REQUEST_TYPE_ADMIN_APPROVAL = 2;

// Fields are clipped to their column widths; a value of the wrong type reads as empty.
const clippedText = (maxLength: number) => z.string().trim().transform((text) => text.slice(0, maxLength)).catch('');

const AuthRequestCreateSchema = z.looseObject({
  email: clippedText(320).transform((email) => email.toLowerCase()),
  publicKey: clippedText(8192),
  accessCode: clippedText(25),
  type: z.coerce.number().catch(AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK),
});

const AuthRequestUpdateSchema = z.object({
  requestApproved: z.coerce.boolean(),
  key: clippedText(20000),
  deviceIdentifier: clippedText(128),
});

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

async function enforceAuthRequestCreateRateLimit(
  request: Request,
  env: Env,
  email: string,
  deviceIdentifier: string
): Promise<Response | null> {
  const clientIdentifier = getClientIdentifier(request);
  if (!clientIdentifier) return errorResponse('Client IP is required', 403);

  const rateLimit = new RateLimitService(env);
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


function isSupportedAuthRequestType(value: number): value is AuthRequestType {
  return value === AUTH_REQUEST_TYPE_AUTHENTICATE_AND_UNLOCK || value === AUTH_REQUEST_TYPE_UNLOCK || value === AUTH_REQUEST_TYPE_ADMIN_APPROVAL;
}

export async function handleCreateAuthRequest(request: Request, env: Env): Promise<Response> {
  const body = await parseBody(request, AuthRequestCreateSchema, 'Invalid request payload');
  if (body instanceof Response) return body;
  const { email, publicKey, accessCode, type } = body;
  const deviceInfo = readAuthRequestDeviceInfo(body, request);

  if (!email || !publicKey || !accessCode || !deviceInfo.deviceIdentifier) {
    return errorResponse('Email, public key, device identifier, and access code are required.', 400);
  }
  const rateLimitResponse = await enforceAuthRequestCreateRateLimit(request, env, email, deviceInfo.deviceIdentifier);
  if (rateLimitResponse) return rateLimitResponse;
  if (!isSupportedAuthRequestType(type) || type === AUTH_REQUEST_TYPE_ADMIN_APPROVAL) {
    return errorResponse('Invalid auth request type.', 400);
  }

  const user = await userRepo.getUser(env.DB, email);
  if (!user || user.status !== 'active') {
    return errorResponse('User or known device not found.', 400);
  }

  await authRequestRepo.pruneExpiredAuthRequests(env.DB);
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
  await authRequestRepo.createAuthRequest(env.DB, authRequest);
  notifyUserAuthRequest(env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleCreateAdminAuthRequest(
  request: Request,
  env: Env,
  userId: string,
  userEmail: string
): Promise<Response> {
  const body = await parseBody(request, AuthRequestCreateSchema, 'Invalid request payload');
  if (body instanceof Response) return body;
  const { publicKey, accessCode, type: requestedType } = body;
  const email = body.email || userEmail.toLowerCase();
  const deviceInfo = readAuthRequestDeviceInfo(body, request);

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

  const user = await userRepo.getUserById(env.DB, userId);
  if (!user || user.status !== 'active') {
    return errorResponse('User not found.', 404);
  }

  await authRequestRepo.pruneExpiredAuthRequests(env.DB);
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
  await authRequestRepo.createAuthRequest(env.DB, authRequest);
  notifyUserAuthRequest(env, user.id, authRequest.id, deviceInfo.deviceIdentifier);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleGetAuthRequest(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const authRequest = await authRequestRepo.getAuthRequestByIdForUser(env.DB, id, userId);
  if (!authRequest || authRequest.userId !== userId) return errorResponse('Not found', 404);
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleGetAuthRequestResponse(request: Request, env: Env, id: string): Promise<Response> {
  const url = new URL(request.url);
  const accessCode = clippedText(25).parse(url.searchParams.get('code'));
  const authRequest = await authRequestRepo.getAuthRequestById(env.DB, id);
  if (!authRequest || authRequest.accessCode !== accessCode || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }
  return jsonResponse(toAuthRequestResponse(request, authRequest));
}

export async function handleListAuthRequests(request: Request, env: Env, userId: string): Promise<Response> {
  const authRequests = await authRequestRepo.listAuthRequestsByUserId(env.DB, userId);
  return jsonResponse(listResponse(authRequests.map((authRequest) => toAuthRequestResponse(request, authRequest))));
}

export async function handleListPendingAuthRequests(request: Request, env: Env, userId: string): Promise<Response> {
  await authRequestRepo.pruneExpiredAuthRequests(env.DB);
  const authRequests = await authRequestRepo.listPendingAuthRequestsByUserId(env.DB, userId);
  const rows = await Promise.all(authRequests.map(async (authRequest) => {
    const device = await deviceRepo.getDevice(env.DB, userId, authRequest.requestDeviceIdentifier);
    return toAuthRequestResponse(request, authRequest, device?.deviceIdentifier ?? authRequest.requestDeviceIdentifier);
  }));
  return jsonResponse(listResponse(rows));
}

export async function handleUpdateAuthRequest(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const body = await parseBody(request, AuthRequestUpdateSchema, 'Invalid request payload');
  if (body instanceof Response) return body;

  const authRequest = await authRequestRepo.getAuthRequestByIdForUser(env.DB, id, userId);
  if (!authRequest || authRequest.userId !== userId || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }
  if (authRequest.approved !== null || authRequest.responseDate || authRequest.authenticationDate) {
    return errorResponse('Auth request has already been answered.', 409);
  }

  const latestForUser = await authRequestRepo.listPendingAuthRequestsByUserId(env.DB, userId);
  const latestForDevice = latestForUser.find((item) => item.requestDeviceIdentifier === authRequest.requestDeviceIdentifier);
  if (latestForDevice?.id !== authRequest.id) {
    return errorResponse('This request is no longer valid. Make sure to approve the most recent request.', 400);
  }

  const { requestApproved: approved, key } = body;
  const responseDeviceIdentifier =
    body.deviceIdentifier ||
    readActingDeviceIdentifier(request) ||
    'web';

  if (approved && !key) {
    return errorResponse('Encrypted key is required to approve the request.', 400);
  }
  if (approved && !isSerializedEncString(key)) {
    return errorResponse('Encrypted key is not a valid encrypted string.', 400);
  }

  const updated = await authRequestRepo.updateAuthRequestResponse(env.DB, id, userId, {
    approved,
    responseDeviceIdentifier,
    key,
    masterPasswordHash: null,
  });
  if (!updated) return errorResponse('Auth request has already been answered.', 409);
  const updatedRequest = await authRequestRepo.getAuthRequestByIdForUser(env.DB, id, userId);
  // Match Bitwarden upstream behavior: only approval wakes the originating anonymous
  // client. Denials are not pushed to avoid leaking that a login attempt was rejected.
  if (approved) {
    await notifyAuthRequestResponse(env, userId, id);
  }
  return jsonResponse(toAuthRequestResponse(request, updatedRequest || authRequest));
}
