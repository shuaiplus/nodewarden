import { z } from 'zod';
import { Env, Send, SendAuthType, SendType } from '../types';
import { recordSendEvent, recordSendEvents } from '../services/events';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { buildDirectUploadUrl, parseDirectUploadPayload } from '../utils/direct-upload';
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
import { readActingDeviceIdentifier } from '../utils/device';
import {
  notifyUserSendCreate,
  notifyUserSendDelete,
  notifyUserSendUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import {
  formatSize,
  parseDate,
  parseStoredSendData,
  sendFileIdMatches,
  sendToResponse,
  setSendPassword,
  toInteger,
} from './sends-shared';
import { writeDataAudit } from '../services/audit-events';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sendRepo from '../services/storage-send-repo';

const SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE = 'Send email verification is not supported by this server.';
const DAY_MS = 24 * 60 * 60 * 1000;

const nonBlank = (error: string) => z.string({ error }).regex(/\S/, { error });
const sendDate = (error: string) => z.string({ error }).transform(parseDate).pipe(z.date({ error }));
const sendType = z.preprocess(toInteger, z.enum(SendType, { error: 'Invalid Send type' }));
const sendName = nonBlank('Name is required').trim();
const sendKey = nonBlank('Key is required');
const deletionDate = sendDate('Invalid deletionDate')
  .refine((date) => date.getTime() <= Date.now() + LIMITS.send.maxDeletionDays * DAY_MS, {
    error: 'You cannot have a Send with a deletion date that far into the future. Adjust the Deletion Date to a value less than 31 days from now and try again.',
  })
  .transform((date) => date.toISOString());
// The text or file object is stored as sent so new client fields round-trip; only the server's own
// response echo is dropped.
const sendData = z.looseObject({}, { error: 'Send data not provided' }).transform(({ response, ...data }) => data);
const emailsError = 'Invalid emails';

// Every field an edit may carry; absent fields stay untouched. Official clients send the unused
// content object as null.
const SendEdit = z.object({
  type: sendType.optional(),
  name: sendName.optional(),
  key: sendKey.optional(),
  deletionDate: deletionDate.optional(),
  text: sendData.nullable().optional(),
  maxAccessCount: z.preprocess(
    (raw) => (raw === '' ? null : toInteger(raw)),
    z.int({ error: 'Invalid maxAccessCount' }).min(0, { error: 'Invalid maxAccessCount' }).nullable()
  ).optional(),
  expirationDate: z.preprocess(
    (raw) => (raw === '' ? null : raw),
    sendDate('Invalid expirationDate').transform((date) => date.toISOString()).nullable()
  ).optional(),
  authType: z.preprocess(toInteger, z.enum(SendAuthType, { error: 'Invalid authType' })).optional(),
  emails: z.union(
    [z.string().min(1, { error: emailsError }), z.array(z.string()).min(1, { error: emailsError })],
    { error: emailsError }
  ).nullable().optional(),
  notes: z.string().nullable().catch(null).optional(),
  disabled: z.boolean({ error: 'Invalid disabled' }).optional(),
  hideEmail: z.boolean({ error: 'Invalid hideEmail' }).nullable().optional(),
  password: z.string().optional().catch(undefined),
});

const newSendFields = { name: sendName, key: sendKey, deletionDate };

const TextSendCreate = SendEdit.extend({
  type: sendType.refine((type) => type === SendType.Text, { error: 'File sends should use /api/sends/file/v2' }),
  ...newSendFields,
  text: sendData,
});

const FileSendCreate = SendEdit.extend({
  type: z.preprocess(toInteger, z.literal(SendType.File, { error: 'Send content is not a file' })),
  ...newSendFields,
  fileLength: z.preprocess(
    toInteger,
    z.int({ error: 'Invalid send length' }).min(0, { error: "Send size can't be negative" })
  ),
  file: sendData,
});

const SendIds = z.object({ ids: z.array(z.string(), { error: 'ids array is required' }) });

async function processSendFileUpload(
  request: Request,
  env: Env,
  send: Send,
  fileId: string
): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.send.maxFileSizeBytes);
  const { id, fileName, size } = parseStoredSendData(send);
  if (id !== fileId) {
    return errorResponse('Send file does not match send data.', 400);
  }

  const upload = await parseDirectUploadPayload(request, {
    expectedSize: size === undefined ? null : Number(size),
    expectedFileName: fileName ?? null,
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

  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, send.userId);
  notifyUserVaultSync(env, send.userId, revisionDate, readActingDeviceIdentifier(request));
  notifyUserSendUpdate(env, { userId: send.userId, sendId: send.id, revisionDate, contextId: readActingDeviceIdentifier(request) });

  return new Response(null, { status: 201 });
}

export async function handleGetSends(request: Request, env: Env, userId: string): Promise<Response> {
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let sends: Send[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await sendRepo.getSendsPage(env.DB, userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    sends = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + sends.length) : null;
  } else {
    sends = await sendRepo.getAllSends(env.DB, userId);
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
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);

  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  return jsonResponse(sendToResponse(send));
}

// Text and file Sends share every field but the content object; the file handler adds the upload
// metadata it owns so the stored blob names the object the client is about to upload.
async function parseNewSend(
  body: z.output<typeof TextSendCreate> | z.output<typeof FileSendCreate>,
  userId: string,
  type: SendType,
  data: Record<string, unknown>
): Promise<Send | Response> {
  if (body.authType === SendAuthType.Email || body.emails) return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);

  const now = new Date().toISOString();
  const send: Send = {
    id: generateUUID(),
    userId,
    type,
    name: body.name,
    notes: body.notes ?? null,
    data: JSON.stringify(data),
    key: body.key,
    passwordHash: null,
    passwordSalt: null,
    passwordIterations: null,
    authType: body.authType ?? SendAuthType.None,
    // Email verification was refused above, so no address list survives creation.
    emails: null,
    maxAccessCount: body.maxAccessCount ?? null,
    accessCount: 0,
    disabled: body.disabled ?? false,
    hideEmail: body.hideEmail ?? null,
    createdAt: now,
    updatedAt: now,
    expirationDate: body.expirationDate ?? null,
    deletionDate: body.deletionDate,
  };

  if (body.password) {
    await setSendPassword(send, body.password);
  } else if (send.authType === SendAuthType.Password) {
    return errorResponse('Password is required for password auth', 400);
  }
  return send;
}

// Creating or editing a Send persists it, bumps the owner's revision, signals their devices and
// records the matching event.
async function saveSendAndNotify(request: Request, env: Env, send: Send, action: 'created' | 'edited'): Promise<void> {
  await sendRepo.saveSend(env.DB, send);
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, send.userId);
  notifyUserVaultSync(env, send.userId, revisionDate, readActingDeviceIdentifier(request));
  (action === 'created' ? notifyUserSendCreate : notifyUserSendUpdate)(env, {
    userId: send.userId,
    sendId: send.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
  await recordSendEvent(env, request, send, action);
}

// The file arrives in a second request authorised by a short-lived upload token bound to this Send.
async function sendFileUploadResponse(request: Request, env: Env, send: Send, fileId: string): Promise<Response> {
  const uploadToken = await createSendFileUploadToken(send.userId, send.id, fileId, env.JWT_SECRET);
  return jsonResponse({
    fileUploadType: 1,
    object: 'send-fileUpload',
    url: buildDirectUploadUrl(request, `/api/sends/${send.id}/file/${fileId}`, uploadToken),
    sendResponse: sendToResponse(send),
  });
}

export async function handleCreateSend(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, TextSendCreate);
  if (body instanceof Response) return body;

  const send = await parseNewSend(body, userId, SendType.Text, body.text);
  if (send instanceof Response) return send;
  await saveSendAndNotify(request, env, send, 'created');
  return jsonResponse(sendToResponse(send));
}

export async function handleCreateFileSendV2(request: Request, env: Env, userId: string): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.send.maxFileSizeBytes);
  const body = await parseBody(request, FileSendCreate);
  if (body instanceof Response) return body;
  if (body.fileLength > maxFileSize) return errorResponse('Send storage limit exceeded with this file', 400);

  const fileId = generateUUID();
  const send = await parseNewSend(body, userId, SendType.File, {
    ...body.file,
    id: fileId,
    size: body.fileLength,
    sizeName: formatSize(body.fileLength),
  });
  if (send instanceof Response) return send;
  await saveSendAndNotify(request, env, send, 'created');
  return sendFileUploadResponse(request, env, send, fileId);
}

export async function handleGetSendFileUpload(
  request: Request,
  env: Env,
  userId: string,
  sendId: string,
  fileId: string
): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
  if (!send || send.userId !== userId) return errorResponse('Send not found', 404);
  if (send.type !== SendType.File) return errorResponse('Send is not a file type send.', 400);
  if (!sendFileIdMatches(send, fileId)) return errorResponse('Send file does not match send data.', 400);
  return sendFileUploadResponse(request, env, send, fileId);
}

export async function handleUploadSendFile(
  request: Request,
  env: Env,
  userId: string,
  sendId: string,
  fileId: string
): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
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

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifySendFileUploadToken(token, env.JWT_SECRET);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse('Token mismatch', 401);
  }

  const send = await sendRepo.getSendForUser(env.DB, sendId, claims.userId);
  if (!send || send.userId !== claims.userId) {
    return errorResponse('Send not found. Unable to save the file.', 404);
  }
  if (send.type !== SendType.File) {
    return errorResponse('Send is not a file type send.', 400);
  }

  return processSendFileUpload(request, env, send, fileId);
}

export async function handleUpdateSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  const body = await parseBody(request, SendEdit);
  if (body instanceof Response) return body;
  if (body.type !== undefined && body.type !== send.type) return errorResponse("Sends can't change type", 400);
  if (body.authType === SendAuthType.Email || body.emails) return errorResponse(SEND_EMAIL_AUTH_UNSUPPORTED_MESSAGE, 501);
  if (send.type === SendType.Text && body.text === null) return errorResponse('Send data not provided', 400);

  const { type, text, emails, password, ...edits } = body;
  Object.assign(send, edits satisfies Partial<Send>);
  // A new auth type replaces any address list; clearing the list drops email auth with it.
  if (edits.authType !== undefined || emails === null) send.emails = null;
  if (emails === null && Number(send.authType) === SendAuthType.Email) send.authType = SendAuthType.None;
  if (send.type === SendType.Text && text) send.data = JSON.stringify(text);
  if (password !== undefined) await setSendPassword(send, password);

  if (send.authType === SendAuthType.Password && !send.passwordHash) {
    return errorResponse('Password is required for password auth', 400);
  }

  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(request, env, send, 'edited');

  return jsonResponse(sendToResponse(send));
}

export async function handleDeleteSend(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  const fileId = send.type === SendType.File ? parseStoredSendData(send).id : undefined;
  if (fileId) await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));

  await sendRepo.deleteSend(env.DB, sendId, userId);
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  notifyUserSendDelete(env, { userId, sendId, revisionDate, contextId: readActingDeviceIdentifier(request) });
  await recordSendEvent(env, request, send, 'deleted');
  await writeDataAudit(env.DB, request, userId, 'send', 'send.delete', {
    id: sendId,
    type: send.type,
  });

  return new Response(null, { status: 200 });
}

export async function handleBulkDeleteSends(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, SendIds);
  if (body instanceof Response) return body;

  const sends = await sendRepo.getSendsByIds(env.DB, body.ids, userId);
  for (const send of sends) {
    const fileId = send.type === SendType.File ? parseStoredSendData(send).id : undefined;
    if (fileId) await deleteBlobObject(env, getSendFileObjectKey(send.id, fileId));
  }

  const revisionDate = await sendRepo.bulkDeleteSends(env.DB, body.ids, userId);
  if (revisionDate) {
    notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    for (const send of sends) {
      notifyUserSendDelete(env, { userId, sendId: send.id, revisionDate, contextId: readActingDeviceIdentifier(request) });
    }
    await recordSendEvents(env, request, userId, sends, 'deleted');
    await writeDataAudit(env.DB, request, userId, 'send', 'send.delete.bulk', {
      count: sends.length,
      requestedCount: body.ids.length,
    });
  }

  return new Response(null, { status: 200 });
}

export async function handleRemoveSendPassword(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  await setSendPassword(send, null);
  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(request, env, send, 'edited');
  await writeDataAudit(env.DB, request, userId, 'send', 'send.password.remove', {
    id: send.id,
    type: send.type,
  });

  return jsonResponse(sendToResponse(send));
}

export async function handleRemoveSendAuth(request: Request, env: Env, userId: string, sendId: string): Promise<Response> {
  const send = await sendRepo.getSendForUser(env.DB, sendId, userId);
  if (!send || send.userId !== userId) {
    return errorResponse('Send not found', 404);
  }

  send.authType = SendAuthType.None;
  send.emails = null;
  send.updatedAt = new Date().toISOString();
  await saveSendAndNotify(request, env, send, 'edited');
  await writeDataAudit(env.DB, request, userId, 'send', 'send.auth.remove', {
    id: send.id,
    type: send.type,
  });

  return jsonResponse(sendToResponse(send));
}
