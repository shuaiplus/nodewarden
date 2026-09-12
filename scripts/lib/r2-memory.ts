// R2 内存桩：只实现 blob-store.ts 实际用到的 put / get / delete
//
// 用途：在没有 Cloudflare 运行时的情况下验证附件 blob 的读写往返。
// 局限：只覆盖 workspace 里用到的最小面（不含 list/multipart/条件请求等）。
import type { R2Bucket } from '@cloudflare/workers-types';

interface StoredObject {
  bytes: Uint8Array;
  contentType: string;
  customMetadata: Record<string, string> | null;
}

export interface R2MemoryBucket {
  /** 交给被测代码当 R2Bucket 用 */
  readonly bucket: R2Bucket;
  /** 已存对象的 key 列表（排序后），供断言使用 */
  keys(): string[];
  /** 读取对象原始字节；不存在返回 null */
  bytesOf(key: string): Uint8Array | null;
  /** 读取对象的 contentType（验证元数据是否被保留） */
  contentTypeOf(key: string): string | null;
  size(): number;
}

async function toBytes(value: unknown): Promise<Uint8Array> {
  if (typeof value === 'string') return new TextEncoder().encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value instanceof ReadableStream) {
    // 上传路径（`parseDirectUploadPayload`）交出来的正是 ReadableStream。
    // 它的 `put` 本来就是 async 的，所以这里直接消费掉即可 ——
    // 早期版本对流直接抛错，导致本桩根本盖不到附件上传。
    return new Uint8Array(await new Response(value).arrayBuffer());
  }
  throw new Error(`R2MemoryBucket: unsupported value type ${typeof value}`);
}

export function createR2MemoryBucket(): R2MemoryBucket {
  const store = new Map<string, StoredObject>();

  const bucket = {
    async put(
      key: string,
      value: unknown,
      options?: { httpMetadata?: { contentType?: string }; customMetadata?: Record<string, string> }
    ): Promise<void> {
      store.set(key, {
        bytes: await toBytes(value),
        contentType: options?.httpMetadata?.contentType ?? 'application/octet-stream',
        customMetadata: options?.customMetadata ?? null,
      });
    },
    async get(key: string) {
      const hit = store.get(key);
      if (!hit) return null;
      return {
        body: new Response(hit.bytes).body,
        size: hit.bytes.byteLength,
        httpMetadata: { contentType: hit.contentType },
        customMetadata: hit.customMetadata,
      };
    },
    async delete(key: string): Promise<void> {
      store.delete(key);
    },
  };

  return {
    // 单次显式转换：本桩只实现 R2Bucket 的最小可用子集（put/get/delete）
    bucket: bucket as unknown as R2Bucket,
    keys: () => [...store.keys()].sort(),
    bytesOf: (key) => store.get(key)?.bytes ?? null,
    contentTypeOf: (key) => store.get(key)?.contentType ?? null,
    size: () => store.size,
  };
}
