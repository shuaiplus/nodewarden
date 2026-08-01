import { Env, Send, SendAuthType, SendType } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { buildDirectUploadUrl, getSafeJwtSecret, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { LIMITS } from '../config/limits';
import {
  getBlobStorageMaxBytes,
  getSendFileObjectKey,
  getBlobObject,
  putBlobObject,
  deleteBlobObject,
} from '../services/blob-store';
import { createSendFileUploadToken, verifySendFileUploadToken } from '../utils/jwt';
import {
  formatSize,
  getAliasedProp,
  normalizeEmails,
  notifySendCreateForRequest,
  notifySendDeleteForRequest,
  notifySendUpdateForRequest,
  notifyVaultSyncForRequest,
  parseDate,
  parseFileLength,
  parseInteger,
  parseMaxAccessCount,
  parseSendAuthType,
  parseSendType,
  parseStoredSendData,
  sanitizeSendData,
  sendToResponse,
  setSendPassword,
  validateDeletionDate,
} from './sends-shared';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';

const SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE = 'Send email verification is not supported by this server.';

async function writeSendAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'send',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

async function processSendFileUpload(
  request: Request,
  env: Env,
  send: Send,
  fileId: string
): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.send.maxFileSizeBytes);
  const sendData = parseStoredSendData(send);
  const expectedFileId = typeof sendData.id === 'string' ? sendData.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse('Send file does not match send data.', 400);
  }

  const expectedFileName = typeof sendData.fileName === 'string' ? sendData.fileName : null;
  const expectedSize = parseInteger(sendData.size);
  const upload = await parseDirectUploadPayload(request, {
    expectedSize,
    expectedFileName,
    maxFileSize,
    tooLargeMessage: 'Send storage limit exceeded with this file',
    sizeMismatchMessage: 'Send file size does not match.',
    fileNameMismatchMessage: 'Send file name does not match.',
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getSendFileObjectKey(send.id, fileId);
  if (await getBlobObject(env, path)) {
    return errorResponse('Send file has already been uploaded', 409);
  }

  try {
    await putBlobObject(env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        sendId: send.id,
        fileId,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse('Send storage limit exceeded with this file', 413);
    }
    return errorResponse('Attachment storage is not configured', 500);
  }

  const storage = new StorageService(env.DB);
  const revisionDate = await storage.updateRevisionDate(send.userId);
  notifyVaultSyncForRequest(request, env, send.userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, send.userId, revisionDate);

  return new Response(null, { status: 201 });
}

export async function handleGetSends(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let sends: Send[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getSendsPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    sends = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + sends.length) : null;
  } else {
    sends = await storage.getAllSends(userId);
  }

  const sendResponses = sends.map(sendToResponse);
  return jsonResponse({
    data: sendResponses,
    object: 'list',
    continuationToken,
  });
}

export async function handleGetSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);

  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  return jsonResponse(sendToResponse(send));
}

export async function handleCreateSend(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  const sendType = parseSendType(typeRaw.value);
  if (sendType === null) {
    return errorResponse('Invalid Send type', 400);
  }
  if (sendType === SendType.File) {
    return errorResponse('File sends should use /api/sends/file/v2', 400);
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  const deletionDateRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  const textRaw = getAliasedProp(body, ['text', 'Text']);

  if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
    return errorResponse('Name is required', 400);
  }
  if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
    return errorResponse('Key is required', 400);
  }

  const deletionDate = parseDate(deletionDateRaw.value);
  if (!deletionDate) {
    return errorResponse('Invalid deletionDate', 400);
  }

  const deletionValidation = validateDeletionDate(deletionDate);
  if (deletionValidation) return deletionValidation;

  const sendData = sanitizeSendData(textRaw.value);
  if (!sendData) {
    return errorResponse('Send data not provided', 400);
  }

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  const maxAccess = parseMaxAccessCount(maxAccessRaw.value);
  if (!maxAccess.ok) return maxAccess.response;

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  const expirationDate = expirationRaw.value === null || expirationRaw.value === undefined
    ? null
    : parseDate(expirationRaw.value);
  if (expirationRaw.value !== null && expirationRaw.value !== undefined && !expirationDate) {
    return errorResponse('Invalid expirationDate', 400);
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  const authTypeRaw = getAliasedProp(body, ['authType', 'AuthType']);
  const emailsRaw = getAliasedProp(body, ['emails', 'Emails']);

  const requestedAuthType = parseSendAuthType(authTypeRaw.value);
  if (authTypeRaw.present && requestedAuthType === null) {
    return errorResponse('Invalid authType', 400);
  }
  if (requestedAuthType === SendAuthType.Email) {
    return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  }

  const normalizedEmails = normalizeEmails(emailsRaw.value);
  if (emailsRaw.present && emailsRaw.value !== null && normalizedEmails === null) {
    return errorResponse('Invalid emails', 400);
  }
  if (normalizedEmails) {
    return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  }

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type: sendType,
    name: nameRaw.value.trim(),
    notes: typeof notesRaw.value === 'string' ? notesRaw.value : null,
    data: JSON.stringify(sendData),
    key: keyRaw.value,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: requestedAuthType ?? SendAuthType.None,
    emails: normalizedEmails,
    maxAccessCount: maxAccess.value,
    accessCount: 0,
    disabled: typeof disabledRaw.value === 'boolean' ? disabledRaw.value : false,
    hideEmail: typeof hideEmailRaw.value === 'boolean' ? hideEmailRaw.value : null,
    createdAt: now,
    updatedAt: now,
    expirationDate: expirationDate ? expirationDate.toISOString() : null,
    deletionDate: deletionDate.toISOString(),
  };

  if (typeof passwordRaw.value === 'string' && passwordRaw.value.length > 0) {
    await setSendPassword(send, passwordRaw.value);
  } else if (send.authType === SendAuthType.Password) {
    return errorResponse('Password is required for password auth', 400);
  }

  if (send.authType !== SendAuthType.Email) {
    send.emails = null;
  }

  await storage.saveSend(send);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendCreateForRequest(request, env, send.id, userId, revisionDate);

  return jsonResponse(sendToResponse(send));
}

export async function handleCreateFileSendV2(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.send.maxFileSizeBytes);

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  const sendType = parseSendType(typeRaw.value);
  if (sendType !== SendType.File) {
    return errorResponse('Send content is not a file', 400);
  }

  const fileLengthRaw = getAliasedProp(body, ['fileLength', 'FileLength']);
  const fileLengthParsed = parseFileLength(fileLengthRaw.value);
  if (!fileLengthParsed.ok) return fileLengthParsed.response;
  if (fileLengthParsed.value > maxFileSize) {
    return errorResponse('Send storage limit exceeded with this file', 400);
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  const deletionDateRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  const fileRaw = getAliasedProp(body, ['file', 'File']);

  if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
    return errorResponse('Name is required', 400);
  }
  if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
    return errorResponse('Key is required', 400);
  }

  const deletionDate = parseDate(deletionDateRaw.value);
  if (!deletionDate) {
    return errorResponse('Invalid deletionDate', 400);
  }
  const deletionValidation = validateDeletionDate(deletionDate);
  if (deletionValidation) return deletionValidation;

  const fileData = sanitizeSendData(fileRaw.value);
  if (!fileData) {
    return errorResponse('Send data not provided', 400);
  }

  const fileId = generateUUID();
  fileData.id = fileId;
  fileData.size = fileLengthParsed.value;
  fileData.sizeName = formatSize(fileLengthParsed.value);

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  const maxAccess = parseMaxAccessCount(maxAccessRaw.value);
  if (!maxAccess.ok) return maxAccess.response;

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  const expirationDate = expirationRaw.value === null || expirationRaw.value === undefined
    ? null
    : parseDate(expirationRaw.value);
  if (expirationRaw.value !== null && expirationRaw.value !== undefined && !expirationDate) {
    return errorResponse('Invalid expirationDate', 400);
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  const authTypeRaw = getAliasedProp(body, ['authType', 'AuthType']);
  const emailsRaw = getAliasedProp(body, ['emails', 'Emails']);

  const requestedAuthType = parseSendAuthType(authTypeRaw.value);
  if (authTypeRaw.present && requestedAuthType === null) {
    return errorResponse('Invalid authType', 400);
  }
  if (requestedAuthType === SendAuthType.Email) {
    return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  }

  const normalizedEmails = normalizeEmails(emailsRaw.value);
  if (emailsRaw.present && emailsRaw.value !== null && normalizedEmails === null) {
    return errorResponse('Invalid emails', 400);
  }
  if (normalizedEmails) {
    return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  }

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type: sendType,
    name: nameRaw.value.trim(),
    notes: typeof notesRaw.value === 'string' ? notesRaw.value : null,
    data: JSON.stringify(fileData),
    key: keyRaw.value,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: requestedAuthType ?? SendAuthType.None,
    emails: normalizedEmails,
    maxAccessCount: maxAccess.value,
    accessCount: 0,
    disabled: typeof disabledRaw.value === 'boolean' ? disabledRaw.value : false,
    hideEmail: typeof hideEmailRaw.value === 'boolean' ? hideEmailRaw.value : null,
    createdAt: now,
    updatedAt: now,
    expirationDate: expirationDate ? expirationDate.toISOString() : null,
    deletionDate: deletionDate.toISOString(),
  };

  if (typeof passwordRaw.value === 'string' && passwordRaw.value.length > 0) {
    await setSendPassword(send, passwordRaw.value);
  } else if (send.authType === SendAuthType.Password) {
    return errorResponse('Password is required for password auth', 400);
  }

  if (send.authType !== SendAuthType.Email) {
    send.emails = null;
  }

  await storage.saveSend(send);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendCreateForRequest(request, env, send.id, userId, revisionDate);
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createSendFileUploadToken(userId, send.id, fileId, jwtSecret);

  return jsonResponse({
    fileUploadType: 1,
    object: 'send-fileUpload',
    url: buildDirectUploadUrl(request, `/api/sends/${send.id}/file/${fileId}`, uploadToken),
    sendResponse: sendToResponse(send),
  });
}

export async function handleGetSendFileUpload(
  request: Request,
  env: Env,
  userId: string,
  sendId: string,
  fileId: string
): Promise<Response> {
  void request;
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse('Send is not a file type send.', 400);
  }

  const sendData = parseStoredSendData(send);
  const expectedFileId = typeof sendData.id === 'string' ? sendData.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse('Send file does not match send data.', 400);
  }
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createSendFileUploadToken(userId, send.id, fileId, jwtSecret);

  return jsonResponse({
    fileUploadType: 1,
    object: 'send-fileUpload',
    url: buildDirectUploadUrl(request, `/api/sends/${send.id}/file/${fileId}`, uploadToken),
    sendResponse: sendToResponse(send),
  });
}

export async function handleUploadSendFile(
  request: Request,
  env: Env,
  userId: string,
  sendId: string,
  fileId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse('Send is not a file type send.', 400);
  }

  return processSendFileUpload(request, env, send, fileId);
}

export async function handlePublicUploadSendFile(
  request: Request,
  env: Env,
  sendId: string,
  fileId: string
): Promise<Response> {
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifySendFileUploadToken(token, jwtSecret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, claims.userId);
  if (!send || send.userId !== claims.userId) {
    return errorResponse('Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse('Send is not a file type send.', 400);
  }

  return processSendFileUpload(request, env, send, fileId);
}

export async function handleUpdateSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const typeRaw = getAliasedProp(body, ['type', 'Type']);
  if (typeRaw.present) {
    const incomingType = parseSendType(typeRaw.value);
    if (incomingType === null) {
      return errorResponse('Invalid Send type', 400);
    }
    if (incomingType !== send.type) {
      return errorResponse("Sends can't change type", 400);
    }
  }

  const deletionRaw = getAliasedProp(body, ['deletionDate', 'DeletionDate']);
  if (deletionRaw.present) {
    const deletionDate = parseDate(deletionRaw.value);
    if (!deletionDate) return errorResponse('Invalid deletionDate', 400);
    const deletionValidation = validateDeletionDate(deletionDate);
    if (deletionValidation) return deletionValidation;
    send.deletionDate = deletionDate.toISOString();
  }

  const expirationRaw = getAliasedProp(body, ['expirationDate', 'ExpirationDate']);
  if (expirationRaw.present) {
    if (expirationRaw.value === null || expirationRaw.value === '') {
      send.expirationDate = null;
    } else {
      const expiration = parseDate(expirationRaw.value);
      if (!expiration) return errorResponse('Invalid expirationDate', 400);
      send.expirationDate = expiration.toISOString();
    }
  }

  const nameRaw = getAliasedProp(body, ['name', 'Name']);
  if (nameRaw.present) {
    if (typeof nameRaw.value !== 'string' || !nameRaw.value.trim()) {
      return errorResponse('Name is required', 400);
    }
    send.name = nameRaw.value.trim();
  }

  const keyRaw = getAliasedProp(body, ['key', 'Key']);
  if (keyRaw.present) {
    if (typeof keyRaw.value !== 'string' || !keyRaw.value.trim()) {
      return errorResponse('Key is required', 400);
    }
    send.key = keyRaw.value;
  }

  const notesRaw = getAliasedProp(body, ['notes', 'Notes']);
  if (notesRaw.present) {
    send.notes = typeof notesRaw.value === 'string' ? notesRaw.value : null;
  }

  const disabledRaw = getAliasedProp(body, ['disabled', 'Disabled']);
  if (disabledRaw.present) {
    if (typeof disabledRaw.value !== 'boolean') {
      return errorResponse('Invalid disabled', 400);
    }
    send.disabled = disabledRaw.value;
  }

  const hideEmailRaw = getAliasedProp(body, ['hideEmail', 'HideEmail']);
  if (hideEmailRaw.present) {
    if (hideEmailRaw.value === null) {
      send.hideEmail = null;
    } else if (typeof hideEmailRaw.value === 'boolean') {
      send.hideEmail = hideEmailRaw.value;
    } else {
      return errorResponse('Invalid hideEmail', 400);
    }
  }

  const maxAccessRaw = getAliasedProp(body, ['maxAccessCount', 'MaxAccessCount']);
  if (maxAccessRaw.present) {
    const parsedMax = parseMaxAccessCount(maxAccessRaw.value);
    if (!parsedMax.ok) return parsedMax.response;
    send.maxAccessCount = parsedMax.value;
  }

  if (send.type === SendType.Text) {
    const textRaw = getAliasedProp(body, ['text', 'Text']);
    if (textRaw.present) {
      const textData = sanitizeSendData(textRaw.value);
      if (!textData) {
        return errorResponse('Send data not provided', 400);
      }
      send.data = JSON.stringify(textData);
    }
  }

  const authTypeRaw = getAliasedProp(body, ['authType', 'AuthType']);
  if (authTypeRaw.present) {
    const parsedAuthType = parseSendAuthType(authTypeRaw.value);
    if (parsedAuthType === null) {
      return errorResponse('Invalid authType', 400);
    }
    if (parsedAuthType === SendAuthType.Email) {
      return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
    }
    send.authType = parsedAuthType;
    send.emails = null;
  }

  const emailsRaw = getAliasedProp(body, ['emails', 'Emails']);
  if (emailsRaw.present) {
    const normalizedEmails = normalizeEmails(emailsRaw.value);
    if (emailsRaw.value !== null && normalizedEmails === null) {
      return errorResponse('Invalid emails', 400);
    }
    if (normalizedEmails) {
      return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
    }
    send.emails = normalizedEmails;
    if (send.emails) {
      send.authType = SendAuthType.Email;
    } else if (Number(send.authType) === SendAuthType.Email) {
      send.authType = SendAuthType.None;
    }
  }

  const passwordRaw = getAliasedProp(body, ['password', 'Password']);
  if (passwordRaw.present && typeof passwordRaw.value === 'string') {
    await setSendPassword(send, passwordRaw.value);
  }

  if (send.authType === SendAuthType.Password && !send.passwordHash) {
    return errorResponse('Password is required for password auth', 400);
  }

  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, userId, revisionDate);

  return jsonResponse(sendToResponse(send));
}

export async function handleDeleteSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  if (send.type === SendType.File) {
    const data = parseStoredSendData(send);
    const fileId = typeof data.id === 'string' ? data.id : null;
    if (fileId) {
      await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));
    }
  }

  await storage.deleteSend(sendId, userId);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendDeleteForRequest(request, env, sendId, userId, revisionDate);
  await writeSendAudit(storage, request, userId, 'send.delete', {
    id: sendId,
    type: send.type,
  });

  return new Response(null, { status: 200 });
}

export async function handleBulkDeleteSends(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.ids || !Array.isArray(body.ids)) {
    return errorResponse('ids array is required', 400);
  }

  const sends = await storage.getSendsByIds(body.ids, userId);
  for (const send of sends) {
    if (send.type !== SendType.File) continue;
    const data = parseStoredSendData(send);
    const fileId = typeof data.id === 'string' ? data.id : null;
    if (fileId) {
      await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));
    }
  }

  const revisionDate = await storage.bulkDeleteSends(body.ids, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    for (const send of sends) {
      notifySendDeleteForRequest(request, env, send.id, userId, revisionDate);
    }
    await writeSendAudit(storage, request, userId, 'send.delete.bulk', {
      count: sends.length,
      requestedCount: body.ids.length,
    });
  }

  return new Response(null, { status: 200 });
}

export async function handleRemoveSendPassword(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  await setSendPassword(send, null);
  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, userId, revisionDate);
  await writeSendAudit(storage, request, userId, 'send.password.remove', {
    id: send.id,
    type: send.type,
  });

  return jsonResponse(sendToResponse(send));
}

export async function handleRemoveSendAuth(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const send = await storage.getSendForUser(sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  send.authType = SendAuthType.None;
  send.emails = null;
  send.updatedAt = new Date().toISOString();
  await storage.saveSend(send);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, userId, revisionDate);
  await writeSendAudit(storage, request, userId, 'send.auth.remove', {
    id: send.id,
    type: send.type,
  });

  return jsonResponse(sendToResponse(send));
}
