import { AwsClient } from 'aws4fetch';
import type { Env } from '../types';
import { LIMITS } from '../config/limits';

export const PRESIGN_THRESHOLD_BYTES = LIMITS.attachment.maxFileSizeBytes;
const DEFAULT_EXPIRES_SECONDS = 3600;

export function shouldPresignUpload(size: number, env: Env): boolean {
  return size > PRESIGN_THRESHOLD_BYTES && canPresign(env);
}

export function canPresign(env: Env): boolean {
  return !!(
    env.R2_ACCOUNT_ID
    && env.R2_ACCESS_KEY_ID
    && env.R2_SECRET_ACCESS_KEY
    && (env.R2_BUCKET || 'nodewarden-attachments')
  );
}

export async function createR2PresignedPutUrl(
  env: Env,
  objectKey: string,
  expiresSeconds: number = DEFAULT_EXPIRES_SECONDS
): Promise<string> {
  const accountId = String(env.R2_ACCOUNT_ID || '').trim();
  const accessKeyId = String(env.R2_ACCESS_KEY_ID || '').trim();
  const secretAccessKey = String(env.R2_SECRET_ACCESS_KEY || '').trim();
  const bucket = String(env.R2_BUCKET || 'nodewarden-attachments').trim();
  if (!accountId || !accessKeyId || !secretAccessKey) {
    throw new Error('R2 S3 credentials are not configured');
  }

  const client = new AwsClient({ accessKeyId, secretAccessKey, service: 's3', region: 'auto' });
  const objectPath = objectKey.split('/').map(encodeURIComponent).join('/');
  // Query signing covers only the host header and leaves the payload unsigned, so the client can PUT any body within the TTL.
  const signed = await client.sign(
    `https://${accountId}.r2.cloudflarestorage.com/${bucket}/${objectPath}?X-Amz-Expires=${expiresSeconds}`,
    { method: 'PUT', aws: { signQuery: true } }
  );
  return signed.url;
}
