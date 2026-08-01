import { LIMITS } from '../config/limits';
import { Env } from '../types';
import { errorResponse } from './response';

export interface DirectUploadPayload {
  body: ReadableStream;
  contentType: string;
  size: number;
}

interface ParseDirectUploadOptions {
  expectedSize?: number | null;
  expectedFileName?: string | null;
  maxFileSize: number;
  tooLargeMessage: string;
  missingBodyMessage?: string;
  contentLengthRequiredMessage?: string;
  sizeMismatchMessage?: string;
  fileNameMismatchMessage?: string;
}

const MULTIPART_FORMDATA_OVERHEAD_BYTES = 256 * 1024;

export function buildDirectUploadUrl(request: Request, path: string, token: string): string {
  const version = '2023-11-03';
  const expiresAt = '2099-12-31T23:59:59Z';
  const origin = new URL(request.url).origin;
  return `${origin}${path}?sv=${encodeURIComponent(version)}&se=${encodeURIComponent(expiresAt)}&token=${encodeURIComponent(token)}`;
}

export function getSafeJwtSecret(env: Env): string | null {
  const secret = (env.JWT_SECRET || '').trim();
  if (!secret || secret.length < LIMITS.auth.jwtSecretMinLength) {
    return null;
  }
  return secret;
}

export function getMultipartRequestMaxBytes(maxFileSize: number): number {
  return maxFileSize + MULTIPART_FORMDATA_OVERHEAD_BYTES;
}

function parseContentLength(request: Request): number | null {
  const raw = request.headers.get('content-length');
  if (!raw) return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return null;
  return Math.floor(value);
}

export async function parseDirectUploadPayload(
  request: Request,
  options: ParseDirectUploadOptions
): Promise<DirectUploadPayload | Response> {
  const {
    expectedSize = null,
    expectedFileName = null,
    maxFileSize,
    tooLargeMessage,
    missingBodyMessage = 'No file uploaded',
    contentLengthRequiredMessage = 'Content-Length is required for direct uploads',
    sizeMismatchMessage,
    fileNameMismatchMessage,
  } = options;
  const contentType = request.headers.get('content-type') || '';

  if (contentType.includes('multipart/form-data')) {
    const declaredSize = parseContentLength(request);
    if (declaredSize !== null && declaredSize > getMultipartRequestMaxBytes(maxFileSize)) {
      return errorResponse(tooLargeMessage, 413);
    }
    const formData = await request.formData();
    const file = formData.get('data') as File | null;
    if (!file) {
      return errorResponse(missingBodyMessage, 400);
    }
    if (file.size > maxFileSize) {
      return errorResponse(tooLargeMessage, 413);
    }
    if (expectedFileName && file.name !== expectedFileName) {
      return errorResponse(fileNameMismatchMessage || 'File name does not match.', 400);
    }
    if (expectedSize !== null && expectedSize !== undefined && file.size !== expectedSize) {
      return errorResponse(sizeMismatchMessage || 'File size does not match.', 400);
    }
    return {
      body: file.stream(),
      contentType: file.type || 'application/octet-stream',
      size: file.size,
    };
  }

  if (!request.body) {
    return errorResponse(missingBodyMessage, 400);
  }

  const declaredSize = parseContentLength(request);
  const uploadSize = declaredSize ?? (expectedSize && expectedSize > 0 ? expectedSize : null);
  if (uploadSize === null) {
    return errorResponse(contentLengthRequiredMessage, 400);
  }
  if (uploadSize > maxFileSize) {
    return errorResponse(tooLargeMessage, 413);
  }
  if (expectedSize !== null && expectedSize !== undefined && uploadSize !== expectedSize) {
    return errorResponse(sizeMismatchMessage || 'File size does not match.', 400);
  }

  return {
    body: request.body,
    contentType: contentType || 'application/octet-stream',
    size: uploadSize,
  };
}
