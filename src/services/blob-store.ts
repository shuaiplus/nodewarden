import { Env } from '../types';

const DEFAULT_CONTENT_TYPE = 'application/octet-stream';
export const KV_MAX_OBJECT_BYTES = 25 * 1024 * 1024;

interface KVBlobMetadata {
  size?: number;
  contentType?: string;
  customMetadata?: Record<string, string> | null;
}

export interface BlobObject {
  body: ReadableStream | null;
  size: number;
  contentType: string;
}

export interface PutBlobOptions {
  size: number;
  contentType?: string;
  customMetadata?: Record<string, string>;
}

function hasR2Storage(env: Env): env is Env & { ATTACHMENTS: R2Bucket } {
  return !!env.ATTACHMENTS;
}

function hasKvStorage(env: Env): env is Env & { ATTACHMENTS_KV: KVNamespace } {
  return !!env.ATTACHMENTS_KV;
}

export function getBlobStorageKind(env: Env): 'r2' | 'kv' | null {
  // Keep R2 as preferred backend when both are bound.
  if (hasR2Storage(env)) return 'r2';
  if (hasKvStorage(env)) return 'kv';
  return null;
}

export function getBlobStorageMaxBytes(env: Env, configuredLimit: number): number {
  if (getBlobStorageKind(env) === 'kv') {
    return Math.min(configuredLimit, KV_MAX_OBJECT_BYTES);
  }
  return configuredLimit;
}

export function getAttachmentObjectKey(cipherId: string, attachmentId: string): string {
  return `${cipherId}/${attachmentId}`;
}

export function getSendFileObjectKey(sendId: string, fileId: string): string {
  return `sends/${sendId}/${fileId}`;
}

export async function putBlobObject(
  env: Env,
  key: string,
  value: string | ArrayBuffer | ArrayBufferView | ReadableStream,
  options: PutBlobOptions,
): Promise<void> {
  const contentType = options.contentType || DEFAULT_CONTENT_TYPE;

  if (hasR2Storage(env)) {
    await env.ATTACHMENTS.put(key, value, {
      httpMetadata: { contentType },
      customMetadata: options.customMetadata,
    });
    return;
  }

  if (hasKvStorage(env)) {
    if (options.size > KV_MAX_OBJECT_BYTES) {
      throw new Error('KV object too large');
    }
    const metadata: KVBlobMetadata = {
      size: options.size,
      contentType,
      customMetadata: options.customMetadata || null,
    };
    await env.ATTACHMENTS_KV.put(key, value, { metadata });
    return;
  }

  throw new Error('Attachment storage is not configured');
}

export async function getBlobObject(env: Env, key: string): Promise<BlobObject | null> {
  if (hasR2Storage(env)) {
    const object = await env.ATTACHMENTS.get(key);
    if (!object) return null;
    return {
      body: object.body,
      size: Number(object.size) || 0,
      contentType: object.httpMetadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  if (hasKvStorage(env)) {
    const result = await env.ATTACHMENTS_KV.getWithMetadata<KVBlobMetadata>(key, 'arrayBuffer');
    if (!result.value) return null;

    const sizeFromMeta = Number(result.metadata?.size || 0);
    const size = sizeFromMeta > 0 ? sizeFromMeta : result.value.byteLength;
    const body = new Response(result.value).body;

    return {
      body,
      size,
      contentType: result.metadata?.contentType || DEFAULT_CONTENT_TYPE,
    };
  }

  return null;
}

export async function deleteBlobObject(env: Env, key: string): Promise<void> {
  if (hasR2Storage(env)) {
    await env.ATTACHMENTS.delete(key);
    return;
  }
  if (hasKvStorage(env)) {
    await env.ATTACHMENTS_KV.delete(key);
    return;
  }
}
