import type { Env, User } from '../types';
import { StorageService } from '../services/storage';
import { AuthService } from '../services/auth';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { verifyRegisterVerifyToken } from '../utils/jwt';
import { cipherToResponse } from './ciphers';
import * as emergencyRepo from '../services/storage-emergency-repo';
import { EmergencyAccessStatus, EmergencyAccessType } from '../services/storage-emergency-repo';
import * as cipherRepo from '../services/storage-cipher-repo';

function asNumber(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function emergencyJson(record: emergencyRepo.EmergencyAccessRecord) {
  return {
    id: record.id,
    status: record.status,
    type: record.type,
    waitTimeDays: record.waitTimeDays,
    object: 'emergencyAccess',
  };
}

async function userSummary(storage: StorageService, userId: string | null, email: string | null) {
  const user = userId ? await storage.getUserById(userId) : email ? await storage.getUser(email) : null;
  return {
    id: user?.id || null,
    email: user?.email || email,
    name: user?.name || null,
    avatarColor: null,
  };
}

async function granteeDetails(storage: StorageService, record: emergencyRepo.EmergencyAccessRecord) {
  const user = await userSummary(storage, record.granteeId, record.email);
  return {
    ...emergencyJson(record),
    granteeId: user.id,
    email: user.email,
    name: user.name,
    avatarColor: null,
    object: 'emergencyAccessGranteeDetails',
  };
}

async function grantorDetails(storage: StorageService, record: emergencyRepo.EmergencyAccessRecord) {
  const user = await userSummary(storage, record.grantorId, null);
  return {
    ...emergencyJson(record),
    grantorId: user.id,
    email: user.email,
    name: user.name,
    avatarColor: null,
    object: 'emergencyAccessGrantorDetails',
  };
}

function canAct(record: emergencyRepo.EmergencyAccessRecord, userId: string, type: number): boolean {
  if (record.granteeId !== userId || record.type !== type) return false;
  if (record.status === EmergencyAccessStatus.RecoveryApproved) return true;
  if (record.status !== EmergencyAccessStatus.RecoveryInitiated || !record.recoveryInitiatedAt) return false;
  const started = Date.parse(record.recoveryInitiatedAt);
  return Number.isFinite(started) && Date.now() - started >= record.waitTimeDays * 24 * 60 * 60 * 1000;
}

export async function handleEmergencyAccessRoute(
  request: Request,
  env: Env,
  user: User,
  path: string,
  method: string
): Promise<Response | null> {
  const normalized = path.replace(/^\/api/, '');
  if (!normalized.startsWith('/emergency-access')) return null;
  const storage = new StorageService(env.DB);

  if (normalized === '/emergency-access/trusted' && method === 'GET') {
    const rows = await emergencyRepo.listByGrantor(env.DB, user.id);
    const data = [];
    for (const row of rows) data.push(await granteeDetails(storage, row));
    return jsonResponse({ data, object: 'list', continuationToken: null });
  }
  if (normalized === '/emergency-access/granted' && method === 'GET') {
    const rows = await emergencyRepo.listByGrantee(env.DB, user.id);
    const data = [];
    for (const row of rows) data.push(await grantorDetails(storage, row));
    return jsonResponse({ data, object: 'list', continuationToken: null });
  }
  if (normalized === '/emergency-access/invite' && method === 'POST') {
    const body = await request.json() as Record<string, unknown>;
    const email = String(body.email || '').trim().toLowerCase();
    if (!email.includes('@')) return errorResponse('Email is required', 400);
    if (email === user.email.toLowerCase()) return errorResponse('Cannot invite yourself', 400);
    const existing = await emergencyRepo.findInvite(env.DB, user.id, email);
    if (existing) return errorResponse('User already invited', 400);
    const grantee = await storage.getUser(email);
    const now = new Date().toISOString();
    const record: emergencyRepo.EmergencyAccessRecord = {
      id: generateUUID(),
      grantorId: user.id,
      granteeId: grantee?.id || null,
      email,
      keyEncrypted: null,
      type: asNumber(body.type, EmergencyAccessType.View),
      status: grantee ? EmergencyAccessStatus.Accepted : EmergencyAccessStatus.Invited,
      waitTimeDays: Math.max(0, asNumber(body.waitTimeDays, 7)),
      recoveryInitiatedAt: null,
      lastNotificationAt: null,
      createdAt: now,
      updatedAt: now,
    };
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return new Response(null, { status: 200 });
  }

  const match = normalized.match(/^\/emergency-access\/([a-f0-9-]+)(?:\/([a-z]+))?$/i);
  if (!match) return errorResponse('Not found', 404);
  const id = match[1];
  const action = match[2] || '';
  const record = await emergencyRepo.getEmergencyAccess(env.DB, id);
  if (!record) return errorResponse('Emergency access not valid', 404);

  if (!action && method === 'GET') {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    return jsonResponse(await granteeDetails(storage, record));
  }
  if ((method === 'PUT' || method === 'POST') && !action) {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    const body = await request.json() as Record<string, unknown>;
    record.type = asNumber(body.type, record.type);
    record.waitTimeDays = Math.max(0, asNumber(body.waitTimeDays, record.waitTimeDays));
    if (typeof body.keyEncrypted === 'string') record.keyEncrypted = body.keyEncrypted;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return jsonResponse(emergencyJson(record));
  }
  if ((method === 'DELETE' || (method === 'POST' && action === 'delete'))) {
    if (record.grantorId !== user.id && record.granteeId !== user.id) {
      return errorResponse('Emergency access not valid', 404);
    }
    await emergencyRepo.deleteEmergencyAccess(env.DB, id);
    return new Response(null, { status: 200 });
  }
  if (action === 'reinvite' && method === 'POST') {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    if (record.email) {
      const grantee = await storage.getUser(record.email);
      if (grantee && record.status === EmergencyAccessStatus.Invited) {
        record.granteeId = grantee.id;
        record.status = EmergencyAccessStatus.Accepted;
        record.updatedAt = new Date().toISOString();
        await emergencyRepo.saveEmergencyAccess(env.DB, record);
      }
    }
    return new Response(null, { status: 200 });
  }
  if (action === 'accept' && method === 'POST') {
    // Only a pending invite may bind a grantee: later states drop `email` on confirm,
    // so without the status gate a guessed id could re-bind an already-confirmed record.
    if (record.status !== EmergencyAccessStatus.Invited) return errorResponse('Emergency access not valid', 400);
    const email = user.email.toLowerCase();
    if (!record.email || record.email.toLowerCase() !== email) {
      return errorResponse('Emergency access not valid', 404);
    }
    const body = await request.json() as Record<string, unknown>;
    const token = String(body.token || '');
    if (token) {
      const claims = await verifyRegisterVerifyToken(token, env.JWT_SECRET);
      if (!claims || claims.email !== email) {
        return errorResponse('Invite email does not match this account', 400);
      }
    }
    record.granteeId = user.id;
    record.status = EmergencyAccessStatus.Accepted;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return new Response(null, { status: 200 });
  }
  if (action === 'confirm' && method === 'POST') {
    if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.Accepted) {
      return errorResponse('Emergency access not valid', 400);
    }
    const body = await request.json() as Record<string, unknown>;
    record.keyEncrypted = String(body.key || '');
    record.status = EmergencyAccessStatus.Confirmed;
    record.email = null;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'initiate' && method === 'POST') {
    if (record.granteeId !== user.id || record.status !== EmergencyAccessStatus.Confirmed) {
      return errorResponse('Emergency access not valid', 400);
    }
    const now = new Date().toISOString();
    record.recoveryInitiatedAt = now;
    record.lastNotificationAt = now;
    record.status = record.waitTimeDays <= 0
      ? EmergencyAccessStatus.RecoveryApproved
      : EmergencyAccessStatus.RecoveryInitiated;
    record.updatedAt = now;
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'approve' && method === 'POST') {
    if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.RecoveryInitiated) {
      return errorResponse('Emergency access not valid', 400);
    }
    record.status = EmergencyAccessStatus.RecoveryApproved;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'reject' && method === 'POST') {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    record.status = EmergencyAccessStatus.Confirmed;
    record.recoveryInitiatedAt = null;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'view' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.View)) return errorResponse('Emergency access not valid', 400);
    const ciphers = await cipherRepo.getAllCiphers(env.DB, record.grantorId);
    const attachments = await storage.getAttachmentsByCipherIds(ciphers.map((cipher) => cipher.id));
    return jsonResponse({
      ciphers: ciphers.map((cipher) => cipherToResponse(cipher, attachments.get(cipher.id) || [])),
      keyEncrypted: record.keyEncrypted,
      object: 'emergencyAccessView',
    });
  }
  if (action === 'takeover' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.Takeover)) return errorResponse('Emergency access not valid', 400);
    const grantor = await storage.getUserById(record.grantorId);
    if (!grantor) return errorResponse('Grantor user not found', 404);
    return jsonResponse({
      kdf: grantor.kdfType,
      kdfIterations: grantor.kdfIterations,
      kdfMemory: grantor.kdfMemory ?? null,
      kdfParallelism: grantor.kdfParallelism ?? null,
      keyEncrypted: record.keyEncrypted,
      object: 'emergencyAccessTakeover',
    });
  }
  if (action === 'password' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.Takeover)) return errorResponse('Emergency access not valid', 400);
    const grantor = await storage.getUserById(record.grantorId);
    if (!grantor) return errorResponse('Grantor user not found', 404);
    const body = await request.json() as Record<string, unknown>;
    const auth = new AuthService(env);
    grantor.masterPasswordHash = await auth.hashPasswordServer(String(body.newMasterPasswordHash || ''), grantor.email);
    grantor.key = String(body.key || grantor.key);
    grantor.securityStamp = generateUUID();
    grantor.updatedAt = new Date().toISOString();
    await storage.saveUser(grantor);
    await storage.deleteRefreshTokensByUserId(grantor.id);
    AuthService.invalidateUserCache(grantor.id);
    return new Response(null, { status: 200 });
  }
  if (action === 'policies' && method === 'GET') {
    if (!canAct(record, user.id, EmergencyAccessType.Takeover)) return errorResponse('Emergency access not valid', 400);
    return jsonResponse({ data: [], object: 'list', continuationToken: null });
  }
  return errorResponse('Not found', 404);
}

export async function approveExpiredEmergencyAccess(env: Env): Promise<void> {
  const now = new Date().toISOString();
  const ready = await emergencyRepo.listRecoveryReady(env.DB, now);
  for (const record of ready) {
    record.status = EmergencyAccessStatus.RecoveryApproved;
    record.updatedAt = now;
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
  }
}


