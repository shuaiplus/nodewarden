import { Env, SendType } from '../types';
import { StorageService } from '../services/storage';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse } from '../utils/response';
import { sanitizeDownloadContentType } from '../utils/content-type';
import {
  createSendAccessToken,
  createSendFileDownloadToken,
  verifySendAccessToken,
  verifySendFileDownloadToken,
} from '../utils/jwt';
import {
  getBlobObject,
  getSendFileObjectKey,
} from '../services/blob-store';
import {
  SEND_INACCESSIBLE_MSG,
  extractBearerToken,
  fromAccessId,
  getCreatorIdentifier,
  getSafeJwtSecret,
  hasEmailAuth,
  isSendAvailable,
  notifySendUpdateForRequest,
  notifyVaultSyncForRequest,
  parseStoredSendData,
  resolveSendFromIdOrAccessId,
  sendPasswordLimitKey,
  sendPasswordLockedErrorResponse,
  sendPasswordLockedOAuthResponse,
  sendToAccessResponse,
  validatePublicSendAccess,
  verifySendPassword,
  verifySendPasswordHashB64,
} from './sends-shared';

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'send-file';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

export async function handleAccessSend(request: Request, env: Env, accessId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const sendId = fromAccessId(accessId);
  if (!sendId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const send = await storage.getSend(sendId);
  if (!send || !isSendAvailable(send)) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let sendPasswordLimitIpKey: string | null = null;
  let sendPasswordRateLimit: RateLimitService | null = null;
  if (send.passwordHash) {
    const clientIdentifier = getClientIdentifier(request);
    if (!clientIdentifier) {
      return errorResponse('Client IP is required', 403);
    }
    sendPasswordLimitIpKey = sendPasswordLimitKey(clientIdentifier, send.id);
    sendPasswordRateLimit = new RateLimitService(env.DB);
    const sendPasswordCheck = await sendPasswordRateLimit.checkLoginAttempt(sendPasswordLimitIpKey);
    if (!sendPasswordCheck.allowed) {
      return sendPasswordLockedErrorResponse(sendPasswordCheck.retryAfterSeconds || 60);
    }
  }

  const validation = await validatePublicSendAccess(send, body);
  if (!validation.ok) {
    if (validation.reason === 'invalid_password' && sendPasswordRateLimit && sendPasswordLimitIpKey) {
      const failed = await sendPasswordRateLimit.recordFailedLogin(sendPasswordLimitIpKey);
      if (failed.locked) {
        return sendPasswordLockedErrorResponse(failed.retryAfterSeconds || 60);
      }
    }
    return validation.response;
  }

  if (send.passwordHash && sendPasswordRateLimit && sendPasswordLimitIpKey) {
    await sendPasswordRateLimit.clearLoginAttempts(sendPasswordLimitIpKey);
  }

  if (send.type === SendType.Text) {
    const updated = await storage.incrementSendAccessCount(send.id);
    if (!updated) {
      return errorResponse(SEND_INACCESSIBLE_MSG, 404);
    }
    send.accessCount += 1;
    const revisionDate = await storage.updateRevisionDate(send.userId);
    notifyVaultSyncForRequest(request, env, send.userId, revisionDate);
    notifySendUpdateForRequest(request, env, send.id, send.userId, revisionDate);
  }

  const creatorIdentifier = await getCreatorIdentifier(storage, send);
  return jsonResponse(sendToAccessResponse(send, creatorIdentifier));
}

export async function handleAccessSendFile(
  request: Request,
  env: Env,
  idOrAccessId: string,
  fileId: string
): Promise<Response> {
  const safeSecret = getSafeJwtSecret(env);
  if (!safeSecret.ok) return safeSecret.response;
  const { secret } = safeSecret;

  const storage = new StorageService(env.DB);
  const send = await resolveSendFromIdOrAccessId(storage, idOrAccessId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const data = parseStoredSendData(send);
  const expectedFileId = typeof data.id === 'string' ? data.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  let body: unknown = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  let sendPasswordLimitIpKey: string | null = null;
  let sendPasswordRateLimit: RateLimitService | null = null;
  if (send.passwordHash) {
    const clientIdentifier = getClientIdentifier(request);
    if (!clientIdentifier) {
      return errorResponse('Client IP is required', 403);
    }
    sendPasswordLimitIpKey = sendPasswordLimitKey(clientIdentifier, send.id);
    sendPasswordRateLimit = new RateLimitService(env.DB);
    const sendPasswordCheck = await sendPasswordRateLimit.checkLoginAttempt(sendPasswordLimitIpKey);
    if (!sendPasswordCheck.allowed) {
      return sendPasswordLockedErrorResponse(sendPasswordCheck.retryAfterSeconds || 60);
    }
  }

  const validation = await validatePublicSendAccess(send, body);
  if (!validation.ok) {
    if (validation.reason === 'invalid_password' && sendPasswordRateLimit && sendPasswordLimitIpKey) {
      const failed = await sendPasswordRateLimit.recordFailedLogin(sendPasswordLimitIpKey);
      if (failed.locked) {
        return sendPasswordLockedErrorResponse(failed.retryAfterSeconds || 60);
      }
    }
    return validation.response;
  }

  if (send.passwordHash && sendPasswordRateLimit && sendPasswordLimitIpKey) {
    await sendPasswordRateLimit.clearLoginAttempts(sendPasswordLimitIpKey);
  }

  const updated = await storage.incrementSendAccessCount(send.id);
  if (!updated) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }
  send.accessCount += 1;
  const revisionDate = await storage.updateRevisionDate(send.userId);
  notifyVaultSyncForRequest(request, env, send.userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, send.userId, revisionDate);

  const token = await createSendFileDownloadToken(send.id, fileId, secret);
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/sends/${send.id}/${fileId}?t=${token}`;

  return jsonResponse({
    object: 'send-fileDownload',
    id: fileId,
    url: downloadUrl,
  });
}

export async function handleAccessSendV2(request: Request, env: Env): Promise<Response> {
  const jwt = getSafeJwtSecret(env);
  if (!jwt.ok) return jwt.response;

  const token = extractBearerToken(request);
  if (!token) {
    return errorResponse('Unauthorized', 401);
  }

  const claims = await verifySendAccessToken(token, jwt.secret);
  if (!claims) {
    return errorResponse('Unauthorized', 401);
  }

  const storage = new StorageService(env.DB);
  const send = await storage.getSend(claims.sub);
  if (!send || !isSendAvailable(send)) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  if (send.type === SendType.Text) {
    const updated = await storage.incrementSendAccessCount(send.id);
    if (!updated) {
      return errorResponse(SEND_INACCESSIBLE_MSG, 404);
    }
    send.accessCount += 1;
    const revisionDate = await storage.updateRevisionDate(send.userId);
    notifyVaultSyncForRequest(request, env, send.userId, revisionDate);
    notifySendUpdateForRequest(request, env, send.id, send.userId, revisionDate);
  }

  const creatorIdentifier = await getCreatorIdentifier(storage, send);
  return jsonResponse(sendToAccessResponse(send, creatorIdentifier));
}

export async function handleAccessSendFileV2(request: Request, env: Env, fileId: string): Promise<Response> {
  const jwt = getSafeJwtSecret(env);
  if (!jwt.ok) return jwt.response;

  const token = extractBearerToken(request);
  if (!token) {
    return errorResponse('Unauthorized', 401);
  }

  const claims = await verifySendAccessToken(token, jwt.secret);
  if (!claims) {
    return errorResponse('Unauthorized', 401);
  }

  const storage = new StorageService(env.DB);
  const send = await storage.getSend(claims.sub);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const data = parseStoredSendData(send);
  const expectedFileId = typeof data.id === 'string' ? data.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const updated = await storage.incrementSendAccessCount(send.id);
  if (!updated) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }
  send.accessCount += 1;
  const revisionDate = await storage.updateRevisionDate(send.userId);
  notifyVaultSyncForRequest(request, env, send.userId, revisionDate);
  notifySendUpdateForRequest(request, env, send.id, send.userId, revisionDate);

  const downloadToken = await createSendFileDownloadToken(send.id, fileId, jwt.secret);
  const url = new URL(request.url);
  const downloadUrl = `${url.origin}/api/sends/${send.id}/${fileId}?t=${downloadToken}`;

  return jsonResponse({
    object: 'send-fileDownload',
    id: fileId,
    url: downloadUrl,
  });
}

export async function handleDownloadSendFile(
  request: Request,
  env: Env,
  sendId: string,
  fileId: string
): Promise<Response> {
  const jwt = getSafeJwtSecret(env);
  if (!jwt.ok) return jwt.response;

  const url = new URL(request.url);
  const token = url.searchParams.get('t') || url.searchParams.get('token');
  if (!token) {
    return errorResponse('Token required', 401);
  }

  const claims = await verifySendFileDownloadToken(token, jwt.secret);
  if (!claims) {
    return errorResponse('Invalid or expired token', 401);
  }
  if (claims.sendId !== sendId || claims.fileId !== fileId) {
    return errorResponse('Token mismatch', 401);
  }

  const storage = new StorageService(env.DB);
  const send = await storage.getSend(sendId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }
  const data = parseStoredSendData(send);
  const expectedFileId = typeof data.id === 'string' ? data.id : null;
  if (!expectedFileId || expectedFileId !== fileId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const firstUse = await storage.consumeAttachmentDownloadToken(`send:${claims.jti}`, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  const object = await getBlobObject(env, getSendFileObjectKey(sendId, fileId));
  if (!object) {
    return errorResponse('Send file not found', 404);
  }
  const fileName = typeof data.fileName === 'string' ? data.fileName : fileId;

  return new Response(object.body, {
    headers: {
      'Content-Type': sanitizeDownloadContentType(object.contentType),
      'Content-Length': String(object.size),
      'Content-Disposition': contentDispositionAttachment(fileName),
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

export async function issueSendAccessToken(
  env: Env,
  sendIdOrAccessId: string,
  passwordHashB64?: string | null,
  password?: string | null,
  rateLimit?: RateLimitService,
  clientIdentifier?: string
): Promise<{ token: string } | { error: Response }> {
  const jwt = getSafeJwtSecret(env);
  if (!jwt.ok) {
    return { error: jwt.response };
  }

  const storage = new StorageService(env.DB);
  const send = await resolveSendFromIdOrAccessId(storage, sendIdOrAccessId);

  if (!send || !isSendAvailable(send)) {
    return {
      error: jsonResponse(
        {
          error: 'invalid_grant',
          error_description: SEND_INACCESSIBLE_MSG,
          send_access_error_type: 'send_not_available',
          ErrorModel: {
            Message: SEND_INACCESSIBLE_MSG,
            Object: 'error',
          },
        },
        400
      ),
    };
  }

  if (hasEmailAuth(send)) {
    const message = 'Email verification for this Send is not supported by this server.';
    return {
      error: jsonResponse(
        {
          error: 'invalid_grant',
          error_description: message,
          send_access_error_type: 'email_verification_not_supported',
          ErrorModel: {
            Message: message,
            Object: 'error',
          },
        },
        501
      ),
    };
  }

  const sendPasswordLimitIpKey =
    rateLimit && clientIdentifier ? sendPasswordLimitKey(clientIdentifier, send.id) : null;

  if (send.passwordHash) {
    if (rateLimit && sendPasswordLimitIpKey) {
      const sendPasswordCheck = await rateLimit.checkLoginAttempt(sendPasswordLimitIpKey);
      if (!sendPasswordCheck.allowed) {
        return {
          error: sendPasswordLockedOAuthResponse(sendPasswordCheck.retryAfterSeconds || 60),
        };
      }
    }

    let ok = false;
    if (passwordHashB64) {
      ok = verifySendPasswordHashB64(send, passwordHashB64);
    } else if (password) {
      ok = await verifySendPassword(send, password);
    }

    if (!ok) {
      if (rateLimit && sendPasswordLimitIpKey) {
        const failed = await rateLimit.recordFailedLogin(sendPasswordLimitIpKey);
        if (failed.locked) {
          return {
            error: sendPasswordLockedOAuthResponse(failed.retryAfterSeconds || 60),
          };
        }
      }
      return {
        error: jsonResponse(
          {
            error: 'invalid_grant',
            error_description: 'Invalid password.',
            send_access_error_type: 'invalid_password',
            ErrorModel: {
              Message: 'Invalid password.',
              Object: 'error',
            },
          },
          400
        ),
      };
    }

    if (rateLimit && sendPasswordLimitIpKey) {
      await rateLimit.clearLoginAttempts(sendPasswordLimitIpKey);
    }
  }

  const token = await createSendAccessToken(send.id, jwt.secret);
  return { token };
}
