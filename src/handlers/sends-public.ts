import { Env, Send, SendType } from '../types';
import { recordSendEvent } from '../services/events';
import { RateLimitService, getClientIdentifier } from '../services/ratelimit';
import { jsonResponse, errorResponse } from '../utils/response';
import { sanitizeDownloadContentType } from '../utils/content-type';
import { readActingDeviceIdentifier } from '../utils/device';
import { notifyUserSendUpdate, notifyUserVaultSync } from '../durable/notifications-hub';
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
  parseStoredSendData,
  resolveSendFromIdOrAccessId,
  sendFileIdMatches,
  sendPasswordLimitKey,
  sendPasswordLockedErrorResponse,
  sendPasswordLockedOAuthResponse,
  sendToAccessResponse,
  validatePublicSendAccess,
  verifySendPassword,
  verifySendPasswordHashB64,
} from './sends-shared';
import * as attachmentTokenRepo from '../services/storage-attachment-token-repo';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sendRepo from '../services/storage-send-repo';

function contentDispositionAttachment(fileName: string | null | undefined): string {
  const fallback = 'send-file';
  const value = String(fileName || fallback)
    .replace(/[\r\n"]/g, '_')
    .trim() || fallback;
  return `attachment; filename="${value}"`;
}

// Reads the optional JSON body and checks the Send password inside the per-client attempt limit,
// so a guessed password costs the guesser lockouts rather than the owner's Send. Resolves to the
// rejection to answer with, or null once the caller may proceed.
async function authorizeSendByPassword(request: Request, env: Env, send: Send): Promise<Response | null> {
  const body: unknown = await request.json().catch(() => ({}));

  const clientIdentifier = send.passwordHash ? getClientIdentifier(request) : null;
  if (send.passwordHash && !clientIdentifier) return errorResponse('Client IP is required', 403);
  const limitKey = clientIdentifier ? sendPasswordLimitKey(clientIdentifier, send.id) : null;
  const rateLimit = new RateLimitService(env);
  if (limitKey) {
    const check = await rateLimit.checkLoginAttempt(limitKey);
    if (!check.allowed) return sendPasswordLockedErrorResponse(check.retryAfterSeconds || 60);
  }

  const validation = await validatePublicSendAccess(send, body);
  if (!validation.ok) {
    if (validation.reason === 'invalid_password' && limitKey) {
      const failed = await rateLimit.recordFailedLogin(limitKey);
      if (failed.locked) return sendPasswordLockedErrorResponse(failed.retryAfterSeconds || 60);
    }
    return validation.response;
  }
  if (limitKey) await rateLimit.clearLoginAttempts(limitKey);
  return null;
}

// Resolves the available Send named by the bearer send-access token, or the rejection to answer with.
async function authorizeSendByToken(request: Request, env: Env): Promise<{ secret: string; send: Send } | Response> {
  const jwt = getSafeJwtSecret(env);
  if (!jwt.ok) return jwt.response;
  const token = extractBearerToken(request);
  const claims = token ? await verifySendAccessToken(token, jwt.secret) : null;
  if (!claims) return errorResponse('Unauthorized', 401);
  const send = await sendRepo.getSend(env.DB, claims.sub);
  if (!send || !isSendAvailable(send)) return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  return { secret: jwt.secret, send };
}

// Counts one access against the Send's limit, then tells the owner's devices and the event log.
async function touchSendAccess(request: Request, env: Env, send: Send): Promise<Response | null> {
  if (!await sendRepo.incrementSendAccessCount(env.DB, send.id)) return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  send.accessCount += 1;
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, send.userId);
  notifyUserVaultSync(env, send.userId, revisionDate, readActingDeviceIdentifier(request));
  notifyUserSendUpdate(env, { userId: send.userId, sendId: send.id, revisionDate, contextId: readActingDeviceIdentifier(request) });
  await recordSendEvent(env, request, send, 'accessed');
  return null;
}

// The file itself is fetched through a short-lived signed URL rather than a bearer header.
async function sendFileDownloadResponse(request: Request, send: Send, fileId: string, secret: string): Promise<Response> {
  const token = await createSendFileDownloadToken(send.id, fileId, secret);
  return jsonResponse({
    object: 'send-fileDownload',
    id: fileId,
    url: `${new URL(request.url).origin}/api/sends/${send.id}/${fileId}?t=${token}`,
  });
}

export async function handleAccessSend(request: Request, env: Env, accessId: string): Promise<Response> {
  const sendId = fromAccessId(accessId);
  const send = sendId ? await sendRepo.getSend(env.DB, sendId) : null;
  if (!send || !isSendAvailable(send)) return errorResponse(SEND_INACCESSIBLE_MSG, 404);

  const rejected = await authorizeSendByPassword(request, env, send);
  if (rejected) return rejected;

  if (send.type === SendType.Text) {
    const touched = await touchSendAccess(request, env, send);
    if (touched) return touched;
  }

  return jsonResponse(sendToAccessResponse(send, await getCreatorIdentifier(env.DB, send)));
}

export async function handleAccessSendFile(
  request: Request,
  env: Env,
  idOrAccessId: string,
  fileId: string
): Promise<Response> {
  const safeSecret = getSafeJwtSecret(env);
  if (!safeSecret.ok) return safeSecret.response;

  const send = await resolveSendFromIdOrAccessId(env.DB, idOrAccessId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File || !sendFileIdMatches(send, fileId)) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const rejected = await authorizeSendByPassword(request, env, send);
  if (rejected) return rejected;

  const touched = await touchSendAccess(request, env, send);
  if (touched) return touched;

  return sendFileDownloadResponse(request, send, fileId, safeSecret.secret);
}

export async function handleAccessSendV2(request: Request, env: Env): Promise<Response> {
  const auth = await authorizeSendByToken(request, env);
  if (auth instanceof Response) return auth;
  const { send } = auth;

  if (send.type === SendType.Text) {
    const touched = await touchSendAccess(request, env, send);
    if (touched) return touched;
  }

  return jsonResponse(sendToAccessResponse(send, await getCreatorIdentifier(env.DB, send)));
}

export async function handleAccessSendFileV2(request: Request, env: Env, fileId: string): Promise<Response> {
  const auth = await authorizeSendByToken(request, env);
  if (auth instanceof Response) return auth;
  const { send, secret } = auth;
  if (send.type !== SendType.File || !sendFileIdMatches(send, fileId)) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const touched = await touchSendAccess(request, env, send);
  if (touched) return touched;

  return sendFileDownloadResponse(request, send, fileId, secret);
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

  const send = await sendRepo.getSend(env.DB, sendId);
  if (!send || !isSendAvailable(send) || send.type !== SendType.File) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }
  const data = parseStoredSendData(send);
  if (data.id !== fileId) {
    return errorResponse(SEND_INACCESSIBLE_MSG, 404);
  }

  const firstUse = await attachmentTokenRepo.consumeAttachmentDownloadToken(env.DB, `send:${claims.jti}`, claims.exp);
  if (!firstUse) {
    return errorResponse('Invalid or expired token', 401);
  }

  const object = await getBlobObject(env, getSendFileObjectKey(sendId, fileId));
  if (!object) {
    return errorResponse('Send file not found', 404);
  }
  const fileName = data.fileName ?? fileId;

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

  const send = await resolveSendFromIdOrAccessId(env.DB, sendIdOrAccessId);

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
