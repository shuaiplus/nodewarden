import { z } from 'zod';
import { Env, Attachment, Cipher } from '../types';
import { notifyUserCipherUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { buildDirectUploadUrl, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { sanitizeDownloadContentType } from '../utils/content-type';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { applyCipherEmbeddedAttachmentMetadata, cipherToResponse, recordCipherEvents } from './ciphers';
import { LIMITS } from '../config/limits';
import { cipherNotifyPayload, readActingDeviceIdentifier } from '../utils/device';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../services/blob-store';
import { writeDataAudit } from '../services/audit-events';
import { createR2PresignedPutUrl, shouldPresignUpload } from '../services/r2-presign';
import { loadAccessibleCipher } from './cipher-access';
import { EventType } from '../services/events';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as attachmentTokenRepo from '../services/storage-attachment-token-repo';
import * as cipherRepo from '../services/storage-cipher-repo';

const ATTACHMENT_FIELD_REQUIRED = 'fileName and key are required';
const requiredAttachmentField = z.string({ error: ATTACHMENT_FIELD_REQUIRED }).min(1, { error: ATTACHMENT_FIELD_REQUIRED });

const CreateAttachmentBody = z.object({
  fileName: requiredAttachmentField,
  key: requiredAttachmentField,
  // Android sends fileSize as a numeric string.
  fileSize: z.coerce.number().optional(),
});

// Only the sent fields change; a present fileName must not be blank, and a blank key clears it.
const AttachmentMetadataBody = z.object({
  fileName: z.unknown().transform((value) => String(value || '').trim()).pipe(z.string().min(1, { error: 'fileName is required' })).optional(),
  key: z.unknown().transform((value) => String(value || '').trim() || null).optional(),
}).refine((body) => 'fileName' in body || 'key' in body, { error: 'No metadata fields supplied' });

// An attachment change is a change to its cipher: the cipher's owner gets a new revision and their
// devices the cipher update signal. Returns null when the cipher row is gone.
async function afterAttachmentChange(
  request: Request,
  env: Env,
  cipher: Cipher,
  cipherId: string
): Promise<{ userId: string; revisionDate: string } | null> {
  const revisionInfo = await attachmentRepo.updateCipherRevisionDate(env.DB, cipherId);
  if (revisionInfo) {
    notifyUserVaultSync(env, revisionInfo.userId, revisionInfo.revisionDate, readActingDeviceIdentifier(request));
    notifyUserCipherUpdate(env, cipherNotifyPayload(cipher, revisionInfo.revisionDate, request));
  }
  return revisionInfo;
}

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'attachment';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

// Format file size to human readable
function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} Bytes`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

async function runWithConcurrency<T>(
  items: T[],
  concurrency: number,
  worker: (item: T) => Promise<void>
): Promise<void> {
  if (items.length === 0) return;
  const limit = Math.max(1, concurrency);
  for (let index = 0; index < items.length; index += limit) {
    await Promise.all(items.slice(index, index + limit).map(worker));
  }
}

async function processAttachmentUpload(
  request: Request,
  env: Env,
  cipher: Cipher,
  attachment: Attachment,
  cipherId: string
): Promise<Response> {
  const maxFileSize = getBlobStorageMaxBytes(env, LIMITS.attachment.maxFileSizeBytes);
  const upload = await parseDirectUploadPayload(request, {
    expectedSize: Number(attachment.size) || 0,
    maxFileSize,
    tooLargeMessage: `File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`,
  });
  if (upload instanceof Response) {
    return upload;
  }

  const path = getAttachmentObjectKey(cipherId, attachment.id);
  if (await getBlobObject(env, path)) {
    return errorResponse('Attachment file has already been uploaded', 409);
  }

  try {
    await putBlobObject(env, path, upload.body, {
      size: upload.size,
      contentType: upload.contentType,
      customMetadata: {
        cipherId,
        attachmentId: attachment.id,
      },
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('KV object too large')) {
      return errorResponse(`File too large. Maximum size is ${Math.floor(maxFileSize / (1024 * 1024))}MB`, 413);
    }
    return errorResponse('Attachment storage is not configured', 500);
  }

  if (upload.size !== attachment.size) {
    attachment.size = upload.size;
    attachment.sizeName = formatSize(upload.size);
    await attachmentRepo.saveAttachment(env.DB, attachment);
  }

  await afterAttachmentChange(request, env, cipher, cipherId);

  return new Response(null, { status: 201 });
}

// POST /api/ciphers/{cipherId}/attachment/v2
// Creates attachment metadata and returns upload URL
export async function handleCreateAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string
): Promise<Response> {

  const cipher = await loadAccessibleCipher(env, env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);
  const body = await parseBody(request, CreateAttachmentBody);
  if (body instanceof Response) return body;

  const fileSize = body.fileSize || 0;
  const attachmentId = generateUUID();

  // Create attachment metadata
  const attachment: Attachment = {
    id: attachmentId,
    cipherId: cipherId,
    fileName: body.fileName,
    size: fileSize,
    sizeName: formatSize(fileSize),
    key: body.key,
  };

  // Save attachment metadata
  await attachmentRepo.saveAttachment(env.DB, attachment);

  // Add attachment to cipher
  if (cipher.organizationId) {
    await attachmentRepo.addAttachmentToCipher(env.DB, cipherId, attachmentId);
  } else {
    await attachmentRepo.addAttachmentToCipherForUser(env.DB, cipherId, attachmentId, userId);
  }

  await afterAttachmentChange(request, env, cipher, cipherId);

  // Get updated cipher for response
  const updatedCipher = cipher.organizationId
    ? await cipherRepo.getCipher(env.DB, cipherId)
    : await cipherRepo.getCipherForUser(env.DB, cipherId, userId);
  const attachments = await attachmentRepo.getAttachmentsByCipher(env.DB, cipherId);
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, env.JWT_SECRET);
  const usePresign = shouldPresignUpload(fileSize, env);
  const url = usePresign
    ? await createR2PresignedPutUrl(env, getAttachmentObjectKey(cipherId, attachmentId))
    : buildDirectUploadUrl(request, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken);

  await recordCipherEvents(env, request, userId, EventType.CipherAttachmentCreated, [cipher]);
  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url,
    urlType: usePresign ? 's3-presigned' : 'direct',
    fileUploadType: usePresign ? 0 : 1,
    cipherResponse: cipherToResponse(updatedCipher || cipher, attachments),
  });
}

// POST /api/ciphers/{cipherId}/attachment/{attachmentId}
// Upload attachment file content
export async function handleUploadAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const cipher = await loadAccessibleCipher(env, env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

export async function handlePublicUploadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, env.JWT_SECRET);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const cipher = await cipherRepo.getCipher(env.DB, cipherId);
  if (!cipher) return errorResponse('Cipher not found', 404);

  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  return processAttachmentUpload(request, env, cipher, attachment, cipherId);
}

// GET /api/ciphers/{cipherId}/attachment/{attachmentId}
// Get attachment download info
export async function handleGetAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const cipher = await loadAccessibleCipher(env, env.DB, userId, cipherId, 'read');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }
  const responseAttachment = applyCipherEmbeddedAttachmentMetadata(cipher, [attachment])[0] || attachment;

  // Generate short-lived download token
  const token = await createFileDownloadToken(cipherId, attachmentId, env.JWT_SECRET);
  
  // Generate download URL with token
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/attachments/${cipherId}/${attachmentId}?token=${token}`;

  return jsonResponse({
    object: 'attachment',
    id: responseAttachment.id,
    url: downloadUrl,
    fileName: responseAttachment.fileName,
    key: responseAttachment.key,
    size: String(Number(responseAttachment.size) || 0),
    sizeName: responseAttachment.sizeName,
  });
}

// PUT /api/ciphers/{cipherId}/attachment/{attachmentId}/metadata
// 修正旧附件的加密元数据，供官方客户端按当前 Bitwarden 契约解密。
export async function handleUpdateAttachmentMetadata(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const cipher = await loadAccessibleCipher(env, env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }
  const body = await parseBody(request, AttachmentMetadataBody);
  if (body instanceof Response) return body;

  if (body.fileName !== undefined) attachment.fileName = body.fileName;
  if (body.key !== undefined) attachment.key = body.key;

  await attachmentRepo.saveAttachment(env.DB, attachment);
  await afterAttachmentChange(request, env, cipher, cipherId);

  return jsonResponse({
    object: 'attachment',
    id: attachment.id,
    fileName: attachment.fileName,
    key: attachment.key,
    size: String(Number(attachment.size) || 0),
    sizeName: attachment.sizeName,
  });
}

// GET /api/attachments/{cipherId}/{attachmentId}?token=xxx
// Public download endpoint (uses token for auth instead of header)
export async function handlePublicDownloadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, env.JWT_SECRET);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }


  // Verify attachment exists
  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const firstUse = await attachmentTokenRepo.consumeAttachmentDownloadToken(env.DB, claims.jti, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  const object = await getBlobObject(env, path);
  if (!object) {
    return errorResponse('Attachment file not found', 404);
  }

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(attachment.fileName),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

// DELETE /api/ciphers/{cipherId}/attachment/{attachmentId}
// Delete attachment
export async function handleDeleteAttachment(
  request: Request,
  env: Env,
  userId: string,
  cipherId: string,
  attachmentId: string
): Promise<Response> {

  const cipher = await loadAccessibleCipher(env, env.DB, userId, cipherId, 'edit');
  if (!cipher) return errorResponse('Cipher not found', 404);

  const attachment = await attachmentRepo.getAttachment(env.DB, attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(env, path);

  if (cipher.organizationId) {
    await attachmentRepo.deleteAttachment(env.DB, attachmentId);
  } else {
    await attachmentRepo.deleteAttachmentForUser(env.DB, attachmentId, userId);
  }

  const revisionInfo = await afterAttachmentChange(request, env, cipher, cipherId);
  if (revisionInfo) {
    await writeDataAudit(env.DB, request, revisionInfo.userId, 'attachment', 'attachment.delete', {
      id: attachmentId,
      cipherId,
      size: attachment.size,
    });
  }

  const updatedCipher = cipher.organizationId
    ? await cipherRepo.getCipher(env.DB, cipherId)
    : await cipherRepo.getCipherForUser(env.DB, cipherId, userId);
  const attachments = await attachmentRepo.getAttachmentsByCipher(env.DB, cipherId);
  const cipherResponse = cipherToResponse(updatedCipher || cipher, attachments);
  await recordCipherEvents(env, request, userId, EventType.CipherAttachmentDeleted, [cipher]);

  return jsonResponse({
    Cipher: cipherResponse,
    cipher: cipherResponse,
    Object: 'deleteAttachment',
    object: 'deleteAttachment',
  });
}

// Delete all attachments for a cipher (used when deleting cipher)
export async function deleteAllAttachmentsForCipher(
  env: Env,
  cipherId: string
): Promise<void> {
  await deleteAllAttachmentsForCiphers(env, [cipherId]);
}

export async function deleteAllAttachmentsForCiphers(
  env: Env,
  cipherIds: string[]
): Promise<void> {
  const attachmentsByCipher = await attachmentRepo.getAttachmentsByCipherIds(env.DB, cipherIds);
  const attachments = Array.from(attachmentsByCipher.entries()).flatMap(([ownedCipherId, items]) =>
    items.map((attachment) => ({ attachment, cipherId: ownedCipherId }))
  );
  if (!attachments.length) return;

  await runWithConcurrency(attachments, LIMITS.performance.attachmentDeleteConcurrency, async ({ attachment, cipherId }) => {
    const path = getAttachmentObjectKey(cipherId, attachment.id);
    await deleteBlobObject(env, path);
  });

  await attachmentRepo.bulkDeleteAttachmentsByIds(env.DB, attachments.map(({ attachment }) => attachment.id));
}
