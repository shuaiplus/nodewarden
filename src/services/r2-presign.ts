import { AwsClient } from 'aws4fetch';
import { readEnvConfig } from '../config/env';
import type { Env } from '../types';
import { LIMITS } from '../config/limits';

export const PRESIGN_THRESHOLD_BYTES = LIMITS.attachment.maxFileSizeBytes;
const DEFAULT_EXPIRES_SECONDS = 3600;

export function shouldPresignUpload(size: number, env: Env): boolean {
  return size > PRESIGN_THRESHOLD_BYTES && canPresign(env);
}

export function canPresign(env: Env): boolean {
  const config = readEnvConfig(env);
  return !!(config.R2_ACCOUNT_ID && config.R2_ACCESS_KEY_ID && config.R2_SECRET_ACCESS_KEY);
}

export async function createR2PresignedPutUrl(
  env: Env,
  objectKey: string,
  expiresSeconds: number = DEFAULT_EXPIRES_SECONDS,
): Promise<string> {
  const {
    R2_ACCOUNT_ID: accountId,
    R2_ACCESS_KEY_ID: accessKeyId,
    R2_SECRET_ACCESS_KEY: secretAccessKey,
    R2_BUCKET: bucket,
  } = readEnvConfig(env);
  if (!accountId || !accessKeyId || !secretAccessKey) {
    throw new Error('R2 S3 credentials are not configured');
  }

  const client = new AwsClient({ accessKeyId, secretAccessKey, service: 's3', region: 'auto' });
  const objectPath = objectKey.split('/').map(encodeURIComponent).join('/');
  // Query signing covers only the host header and leaves the payload unsigned, so the client can PUT any body within the TTL.
  const signed = await client.sign(
    `https://${accountId}.r2.cloudflarestorage.com/${bucket}/${objectPath}?X-Amz-Expires=${expiresSeconds}`,
    { method: 'PUT', aws: { signQuery: true } },
  );
  return signed.url;
}
