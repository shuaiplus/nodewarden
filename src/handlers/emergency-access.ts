import { z } from 'zod';
import type { Env, User } from '../types';
import { AuthService } from '../services/auth';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { createEmergencyAccessInviteToken, verifyEmergencyAccessInviteToken } from '../utils/jwt';
import { LIMITS } from '../config/limits';
import { RateLimitService } from '../services/ratelimit';
import { configuredVaultOrigin, mailStatusCheck, readMailConfig, sendMail, type MailOutcome } from '../services/mail';
import { runInBackground } from '../services/mail-notify';
import { upsertCredentialAccount } from '../services/auth-accounts';
import { cipherToResponse } from './ciphers';
import { emailAddress, MasterPasswordFields, masterPasswordUpdate } from './accounts';
import * as emergencyRepo from '../services/storage-emergency-repo';
import { EmergencyAccessStatus, EmergencyAccessType } from '../services/storage-emergency-repo';
import * as cipherRepo from '../services/storage-cipher-repo';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

// Type and wait time coerce like Number(); anything non-finite keeps the current or default value.
const setting = z.coerce.number().optional().catch(undefined);
const EmergencyAccessSettings = z.object({ type: setting, waitTimeDays: setting, keyEncrypted: z.string().optional().catch(undefined) });
const text = z.string().catch('');

function emergencyJson(record: emergencyRepo.EmergencyAccessRecord) {
  return {
    id: record.id,
    status: record.status,
    type: record.type,
    waitTimeDays: record.waitTimeDays,
    object: 'emergencyAccess',
  };
}

async function userSummary(db: D1Database, userId: string | null, email: string | null) {
  const user = userId ? await userRepo.getUserById(db, userId) : email ? await userRepo.getUser(db, email) : null;
  return {
    id: user?.id || null,
    email: user?.email || email,
    name: user?.name || null,
    avatarColor: null,
  };
}

async function granteeDetails(db: D1Database, record: emergencyRepo.EmergencyAccessRecord) {
  const user = await userSummary(db, record.granteeId, record.email);
  return {
    ...emergencyJson(record),
    granteeId: user.id,
    email: user.email,
    name: user.name,
    avatarColor: null,
    object: 'emergencyAccessGranteeDetails',
  };
}

async function grantorDetails(db: D1Database, record: emergencyRepo.EmergencyAccessRecord) {
  const user = await userSummary(db, record.grantorId, null);
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

async function mailEmergencyAccessInvite(request: Request, env: Env, grantor: User, record: emergencyRepo.EmergencyAccessRecord): Promise<MailOutcome> {
  const config = readMailConfig(env);
  if (config.kind !== 'enabled') return config;
  const vaultOrigin = configuredVaultOrigin(request, env);
  if (!vaultOrigin) return { kind: 'disabled' };
  const budget = await new RateLimitService(env).consumeStrictBudgetWithWindow(
    `ea-invite-mail:${grantor.id}`, LIMITS.mail.emergencyAccessInvitesPerGrantorPerHour, 3600,
  );
  if (!budget.allowed) return { kind: 'throttled', retryAfterSeconds: budget.retryAfterSeconds ?? 3600 };
  return sendMail(env, record.email!, 'emergencyAccessInvite', {
    vaultOrigin, id: record.id, grantorName: grantor.name || grantor.email, grantorEmail: grantor.email,
    token: await createEmergencyAccessInviteToken(env.JWT_SECRET, record.id, record.email!),
  });
}

type EmergencyAccessNotice = 'emergencyAccessAccepted' | 'emergencyAccessConfirmed' | 'emergencyAccessRecoveryInitiated'
  | 'emergencyAccessApproved' | 'emergencyAccessRejected' | 'emergencyAccessTimedOut' | 'emergencyAccessReminder';

async function sendEmergencyAccessNotice(env: Env, record: emergencyRepo.EmergencyAccessRecord, name: EmergencyAccessNotice, recipient: 'grantor' | 'grantee', daysLeft = record.waitTimeDays): Promise<void> {
  const [grantor, grantee] = await Promise.all([
    userRepo.getUserById(env.DB, record.grantorId), record.granteeId ? userRepo.getUserById(env.DB, record.granteeId) : null,
  ]);
  if (!grantor || !grantee) return;
  const [to, other] = recipient === 'grantor' ? [grantor, grantee] : [grantee, grantor];
  await sendMail(env, to.email, name, {
    name: other.name || other.email,
    accessType: record.type === EmergencyAccessType.Takeover ? 'take over your account' : 'view your vault',
    daysLeft,
  });
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

  if (normalized === '/emergency-access/trusted' && method === 'GET') {
    const rows = await emergencyRepo.listByGrantor(env.DB, user.id);
    const data = [];
    for (const row of rows) data.push(await granteeDetails(env.DB, row));
    return jsonResponse({ data, object: 'list', continuationToken: null });
  }
  if (normalized === '/emergency-access/granted' && method === 'GET') {
    const rows = await emergencyRepo.listByGrantee(env.DB, user.id);
    const data = [];
    for (const row of rows) data.push(await grantorDetails(env.DB, row));
    return jsonResponse({ data, object: 'list', continuationToken: null });
  }
  if (normalized === '/emergency-access/invite' && method === 'POST') {
    const body = await parseBody(request, EmergencyAccessSettings.extend({ email: emailAddress('Email is not valid.') }));
    if (body instanceof Response) return body;
    const { email } = body;
    if (email === user.email.toLowerCase()) return errorResponse('Cannot invite yourself', 400);
    const existing = await emergencyRepo.findInvite(env.DB, user.id, email);
    if (existing) return errorResponse('User already invited', 400);
    const grantee = await userRepo.getUser(env.DB, email);
    const now = new Date().toISOString();
    const record: emergencyRepo.EmergencyAccessRecord = {
      id: generateUUID(),
      grantorId: user.id,
      granteeId: grantee?.id || null,
      email,
      keyEncrypted: null,
      type: body.type ?? EmergencyAccessType.View,
      status: grantee ? EmergencyAccessStatus.Accepted : EmergencyAccessStatus.Invited,
      waitTimeDays: Math.max(0, body.waitTimeDays ?? 7),
      recoveryInitiatedAt: null,
      lastNotificationAt: null,
      createdAt: now,
      updatedAt: now,
    };
    const outcome = await mailEmergencyAccessInvite(request, env, user, record);
    const check = mailStatusCheck(outcome);
    if (!check.ok) return errorResponse(check.message, check.status, check.headers);
    if (outcome.kind === 'sent') record.status = EmergencyAccessStatus.Invited;
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
    return jsonResponse(await granteeDetails(env.DB, record));
  }
  if ((method === 'PUT' || method === 'POST') && !action) {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    const body = await parseBody(request, EmergencyAccessSettings);
    if (body instanceof Response) return body;
    record.type = body.type ?? record.type;
    record.waitTimeDays = Math.max(0, body.waitTimeDays ?? record.waitTimeDays);
    if (body.keyEncrypted !== undefined) record.keyEncrypted = body.keyEncrypted;
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
    if (record.status !== EmergencyAccessStatus.Invited || !record.email) return errorResponse('Emergency access not valid', 400);
    const outcome = await mailEmergencyAccessInvite(request, env, user, record);
    const check = mailStatusCheck(outcome);
    if (!check.ok) return errorResponse(check.message, check.status, check.headers);
    if (outcome.kind === 'sent') return new Response(null, { status: 200 });
    if (record.email) {
      const grantee = await userRepo.getUser(env.DB, record.email);
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
    const body = await parseBody(request, z.object({ token: text }));
    if (body instanceof Response) return body;
    const config = readMailConfig(env);
    const check = mailStatusCheck(config.kind === 'enabled' ? { kind: 'sent' } : config);
    if (!check.ok) return errorResponse(check.message, check.status, check.headers);
    if (config.kind === 'enabled' && configuredVaultOrigin(request, env)
      && !await verifyEmergencyAccessInviteToken(body.token, env.JWT_SECRET, record.id, email)) {
      return errorResponse('Emergency access invitation is invalid or expired', 400);
    }
    record.granteeId = user.id;
    record.status = EmergencyAccessStatus.Accepted;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    runInBackground('emergency-access-accepted', () => sendEmergencyAccessNotice(env, record, 'emergencyAccessAccepted', 'grantor'));
    return new Response(null, { status: 200 });
  }
  if (action === 'confirm' && method === 'POST') {
    if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.Accepted) {
      return errorResponse('Emergency access not valid', 400);
    }
    const body = await parseBody(request, z.object({ key: text }));
    if (body instanceof Response) return body;
    record.keyEncrypted = body.key;
    record.status = EmergencyAccessStatus.Confirmed;
    record.email = null;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    runInBackground('emergency-access-confirmed', () => sendEmergencyAccessNotice(env, record, 'emergencyAccessConfirmed', 'grantee'));
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
    runInBackground('emergency-access-initiated', async () => {
      await sendEmergencyAccessNotice(env, record, 'emergencyAccessRecoveryInitiated', 'grantor');
      if (record.status === EmergencyAccessStatus.RecoveryApproved) await sendEmergencyAccessNotice(env, record, 'emergencyAccessApproved', 'grantee');
    });
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'approve' && method === 'POST') {
    if (record.grantorId !== user.id || record.status !== EmergencyAccessStatus.RecoveryInitiated) {
      return errorResponse('Emergency access not valid', 400);
    }
    record.status = EmergencyAccessStatus.RecoveryApproved;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    runInBackground('emergency-access-approved', () => sendEmergencyAccessNotice(env, record, 'emergencyAccessApproved', 'grantee'));
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'reject' && method === 'POST') {
    if (record.grantorId !== user.id) return errorResponse('Emergency access not valid', 404);
    if (record.status !== EmergencyAccessStatus.RecoveryInitiated && record.status !== EmergencyAccessStatus.RecoveryApproved) {
      return errorResponse('Emergency access not valid', 400);
    }
    record.status = EmergencyAccessStatus.Confirmed;
    record.recoveryInitiatedAt = null;
    record.updatedAt = new Date().toISOString();
    await emergencyRepo.saveEmergencyAccess(env.DB, record);
    runInBackground('emergency-access-rejected', () => sendEmergencyAccessNotice(env, record, 'emergencyAccessRejected', 'grantee'));
    return jsonResponse(emergencyJson(record));
  }
  if (action === 'view' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.View)) return errorResponse('Emergency access not valid', 400);
    const ciphers = await cipherRepo.getAllCiphers(env.DB, record.grantorId);
    const attachments = await attachmentRepo.getAttachmentsByCipherIds(env.DB, ciphers.map((cipher) => cipher.id));
    return jsonResponse({
      ciphers: ciphers.map((cipher) => cipherToResponse(cipher, attachments.get(cipher.id) || [])),
      keyEncrypted: record.keyEncrypted,
      object: 'emergencyAccessView',
    });
  }
  if (action === 'takeover' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.Takeover)) return errorResponse('Emergency access not valid', 400);
    const grantor = await userRepo.getUserById(env.DB, record.grantorId);
    if (!grantor) return errorResponse('Grantor user not found', 404);
    return jsonResponse({
      kdf: grantor.kdfType,
      kdfIterations: grantor.kdfIterations,
      kdfMemory: grantor.kdfMemory ?? null,
      kdfParallelism: grantor.kdfParallelism ?? null,
      keyEncrypted: record.keyEncrypted,
      // Web 2026.9 salts the new password with this and only falls back to the email it was given.
      salt: grantor.email.toLowerCase(),
      object: 'emergencyAccessTakeover',
    });
  }
  if (action === 'password' && method === 'POST') {
    if (!canAct(record, user.id, EmergencyAccessType.Takeover)) return errorResponse('Emergency access not valid', 400);
    const grantor = await userRepo.getUserById(env.DB, record.grantorId);
    if (!grantor) return errorResponse('Grantor user not found', 404);
    const body = await parseBody(request, MasterPasswordFields);
    if (body instanceof Response) return body;
    const update = masterPasswordUpdate(body, grantor);
    if (update instanceof Response) return update;
    const auth = new AuthService(env);
    grantor.masterPasswordHash = await auth.hashPasswordServer(update.masterPasswordHash);
    grantor.key = update.key;
    const originalSecurityStamp = grantor.securityStamp;
    grantor.securityStamp = generateUUID();
    grantor.updatedAt = new Date().toISOString();
    if (!await userRepo.saveUser(env.DB, grantor, ['masterPasswordHash', 'key', 'securityStamp'], originalSecurityStamp)) return errorResponse('User verification failed.', 400);
    AuthService.invalidateUserCache(grantor.id);
    if (!await upsertCredentialAccount(env.DB, grantor.id, grantor.masterPasswordHash, grantor.securityStamp)) return errorResponse('User verification failed.', 400);
    await sessionRepo.deleteRefreshTokensByUserId(env.DB, grantor.id);
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
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessTimedOut', 'grantor');
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessApproved', 'grantee');
  }
}

export async function remindPendingEmergencyAccess(env: Env): Promise<void> {
  const now = new Date().toISOString();
  for (const record of await emergencyRepo.listRecoveryToNotify(env.DB, now)) {
    if (!await emergencyRepo.claimRecoveryNotification(env.DB, record, now)) continue;
    const daysLeft = Math.ceil((Date.parse(record.recoveryInitiatedAt!) + record.waitTimeDays * 86_400_000 - Date.parse(now)) / 86_400_000);
    await sendEmergencyAccessNotice(env, record, 'emergencyAccessReminder', 'grantor', daysLeft);
  }
}
