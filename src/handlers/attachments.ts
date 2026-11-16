import { Env, Attachment, Cipher } from '../types';
import { notifyUserCipherUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { buildDirectUploadUrl, getSafeJwtSecret, parseDirectUploadPayload } from '../utils/direct-upload';
import { generateUUID } from '../utils/uuid';
import { sanitizeDownloadContentType } from '../utils/content-type';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
} from '../utils/jwt';
import { applyCipherEmbeddedAttachmentMetadata, cipherToResponse } from './ciphers';
import { bumpOrganizationMembers } from '../utils/org-notify';
import { LIMITS } from '../config/limits';
import { readActingDeviceIdentifier } from '../utils/device';
import {
  deleteBlobObject,
  getAttachmentObjectKey,
  getBlobObject,
  getBlobStorageMaxBytes,
  putBlobObject,
} from '../services/blob-store';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';

function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

function notifyCipherUpdateForRequest(
  request: Request,
  env: Env,
  cipher: Cipher,
  revisionDate: string,
  actingUserId: string
): void {
  notifyUserCipherUpdate(env, {
    userId: cipher.userId ?? actingUserId,
    cipherId: cipher.id,
    revisionDate,
    organizationId: normalizeOptionalId((cipher as any).organizationId ?? null),
    collectionIds: Array.isArray((cipher as any).collectionIds)
      ? (cipher as any).collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  });
}

// Load a cipher + attachment for an authenticated operation: personal ownership
// or confirmed organization membership. requireWrite rejects read-only members.
async function loadAttachmentContext(
  storage: StorageService,
  userId: string,
  cipherId: string,
  attachmentId: string,
  options: { requireWrite?: boolean } = {}
): Promise<{ cipher: Cipher; attachment: Attachment } | Response> {
  const loaded = await loadCipherContext(storage, userId, cipherId, options);
  if (loaded instanceof Response) return loaded;
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }
  return { cipher: loaded.cipher, attachment };
}

// Load a cipher for an authenticated operation without requiring an existing
// attachment (used by the attachment-create endpoint, where the attachment
// does not exist yet).
async function loadCipherContext(
  storage: StorageService,
  userId: string,
  cipherId: string,
  options: { requireWrite?: boolean } = {}
): Promise<{ cipher: Cipher } | Response> {
  const loaded = await storage.getAccessibleCipher(cipherId, userId);
  if (!loaded) return errorResponse('Cipher not found', 404);
  if (options.requireWrite && loaded.access && !loaded.access.canEdit) {
    return errorResponse('You do not have permission to modify this cipher', 403);
  }
  // Overlay the acting user's per-user filing for org ciphers (matches sync
  // and loadCipherForRequest; saveCipher guards the column).
  if (loaded.cipher.organizationId) {
    loaded.cipher.folderId = await storage.getCipherUserFolder(userId, cipherId);
  }
  return { cipher: loaded.cipher };
}

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'attachment';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

async function writeAttachmentAudit(
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
    targetType: 'attachment',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
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
  cipherId: string,
  actingUserId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
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
    await storage.saveAttachment(attachment);
  }

  const revisionInfo = await storage.updateCipherRevisionDate(cipherId);
  if (revisionInfo) {
    notifyVaultSyncForRequest(request, env, revisionInfo.userId ?? actingUserId, revisionInfo.revisionDate);
    notifyCipherUpdateForRequest(request, env, cipher, revisionInfo.revisionDate, actingUserId);
  }
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  }

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
  const storage = new StorageService(env.DB);

  // Verify cipher exists and belongs to user (or is an editable org cipher);
  // the attachment does not exist yet, so use the cipher-only context loader.
  const context = await loadCipherContext(storage, userId, cipherId, { requireWrite: true });
  if (context instanceof Response) return context;
  const cipher = context.cipher;

  let body: {
    fileName?: string;
    key?: string;
    fileSize?: number;
  };

  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.fileName || !body.key) {
    return errorResponse('fileName and key are required', 400);
  }

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
  await storage.saveAttachment(attachment);

  // Add attachment to cipher
  await storage.addAttachmentToCipherForUser(cipherId, attachmentId, userId);

  // Update cipher revision date
  const revisionInfo = await storage.updateCipherRevisionDate(cipherId);
  if (revisionInfo) {
    notifyVaultSyncForRequest(request, env, revisionInfo.userId ?? userId, revisionInfo.revisionDate);
    notifyCipherUpdateForRequest(request, env, cipher, revisionInfo.revisionDate, userId);
  }
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  }

  // Get updated cipher for response
  const updatedLoaded = await storage.getAccessibleCipher(cipherId, userId);
  const updatedCipher = updatedLoaded?.cipher ?? cipher;
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }
  const uploadToken = await createAttachmentUploadToken(userId, cipherId, attachmentId, jwtSecret);

  return jsonResponse({
    object: 'attachment-fileUpload',
    attachmentId: attachmentId,
    url: buildDirectUploadUrl(request, `/api/ciphers/${cipherId}/attachment/${attachmentId}`, uploadToken),
    fileUploadType: 1,
    cipherResponse: cipherToResponse(updatedCipher!, attachments),
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
  const storage = new StorageService(env.DB);

  const context = await loadAttachmentContext(storage, userId, cipherId, attachmentId, { requireWrite: true });
  if (context instanceof Response) return context;

  return processAttachmentUpload(request, env, context.cipher, context.attachment, cipherId, userId);
}

export async function handlePublicUploadAttachment(
  request: Request,
  env: Env,
  cipherId: string,
  attachmentId: string
): Promise<Response> {
  const jwtSecret = getSafeJwtSecret(env);
  if (!jwtSecret) {
    return errorResponse('Server configuration error', 500);
  }

  const token = new URL(request.url).searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifyAttachmentUploadToken(token, jwtSecret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const context = await loadAttachmentContext(storage, claims.userId, cipherId, attachmentId, { requireWrite: true });
  if (context instanceof Response) return context;

  return processAttachmentUpload(request, env, context.cipher, context.attachment, cipherId, claims.userId);
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
  const storage = new StorageService(env.DB);

  const context = await loadAttachmentContext(storage, userId, cipherId, attachmentId);
  if (context instanceof Response) return context;
  const { cipher, attachment } = context;
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
  const storage = new StorageService(env.DB);

  const context = await loadAttachmentContext(storage, userId, cipherId, attachmentId, { requireWrite: true });
  if (context instanceof Response) return context;
  const { cipher, attachment } = context;

  let body: { fileName?: string | null; key?: string | null };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!Object.prototype.hasOwnProperty.call(body, 'fileName') && !Object.prototype.hasOwnProperty.call(body, 'key')) {
    return errorResponse('No metadata fields supplied', 400);
  }

  if (Object.prototype.hasOwnProperty.call(body, 'fileName')) {
    const fileName = String(body.fileName || '').trim();
    if (!fileName) return errorResponse('fileName is required', 400);
    attachment.fileName = fileName;
  }
  if (Object.prototype.hasOwnProperty.call(body, 'key')) {
    const key = body.key == null ? null : String(body.key || '').trim();
    attachment.key = key || null;
  }

  await storage.saveAttachment(attachment);
  const revisionInfo = await storage.updateCipherRevisionDate(cipherId);
  if (revisionInfo) {
    notifyVaultSyncForRequest(request, env, revisionInfo.userId ?? userId, revisionInfo.revisionDate);
    notifyCipherUpdateForRequest(request, env, cipher, revisionInfo.revisionDate, userId);
  }
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  }

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
  const secret = getSafeJwtSecret(env);
  if (!secret) return errorResponse('Server configuration error', 500);

  const url = new URL(request.url);
  const token = url.searchParams.get('token');

  if (!token) {
    return errorResponse('Token required', 401);
  }

  // Verify token
  const claims = await verifyFileDownloadToken(token, secret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }

  // Verify token matches request
  if (claims.cipherId !== cipherId || claims.attachmentId !== attachmentId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);

  // Verify attachment exists
  const attachment = await storage.getAttachment(attachmentId);
  if (!attachment || attachment.cipherId !== cipherId) {
    return errorResponse('Attachment not found', 404);
  }

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  const firstUse = await storage.consumeAttachmentDownloadToken(claims.jti, claims.exp);
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
  const storage = new StorageService(env.DB);

  const context = await loadAttachmentContext(storage, userId, cipherId, attachmentId, { requireWrite: true });
  if (context instanceof Response) return context;
  const { cipher, attachment } = context;

  const path = getAttachmentObjectKey(cipherId, attachmentId);
  await deleteBlobObject(env, path);

  // Delete attachment metadata
  await storage.deleteAttachmentForUser(attachmentId, userId);

  // Update cipher revision date
  const revisionInfo = await storage.updateCipherRevisionDate(cipherId);
  if (revisionInfo) {
    notifyVaultSyncForRequest(request, env, revisionInfo.userId ?? userId, revisionInfo.revisionDate);
    notifyCipherUpdateForRequest(request, env, cipher, revisionInfo.revisionDate, userId);
    await writeAttachmentAudit(storage, request, revisionInfo.userId ?? userId, 'attachment.delete', {
      id: attachmentId,
      cipherId,
      size: attachment.size,
    });
  }
  if (cipher.organizationId) {
    await bumpOrganizationMembers(request, env, storage, cipher.organizationId);
  }

  // Get updated cipher for response
  const updatedLoaded = await storage.getAccessibleCipher(cipherId, userId);
  const updatedCipher = updatedLoaded?.cipher ?? cipher;
  const attachments = await storage.getAttachmentsByCipher(cipherId);
  const cipherResponse = cipherToResponse(updatedCipher!, attachments);

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
  const storage = new StorageService(env.DB);
  const attachmentsByCipher = await storage.getAttachmentsByCipherIds(cipherIds);
  const attachments = Array.from(attachmentsByCipher.entries()).flatMap(([ownedCipherId, items]) =>
    items.map((attachment) => ({ attachment, cipherId: ownedCipherId }))
  );
  if (!attachments.length) return;

  await runWithConcurrency(attachments, LIMITS.performance.attachmentDeleteConcurrency, async ({ attachment, cipherId }) => {
    const path = getAttachmentObjectKey(cipherId, attachment.id);
    await deleteBlobObject(env, path);
  });

  await storage.bulkDeleteAttachmentsByIds(attachments.map(({ attachment }) => attachment.id));
}
