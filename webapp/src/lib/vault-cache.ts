import { createStore, del, get, promisifyRequest } from 'idb-keyval';
import type { Cipher, Folder, Send } from './types';

export interface VaultCoreSnapshot {
  ciphers: Cipher[];
  folders: Folder[];
  sends: Send[];
}

interface VaultCoreCacheRecord {
  cacheKey: string;
  revisionStamp: number;
  savedAt: number;
  snapshot: VaultCoreSnapshot;
}

const vaultCoreStore = createStore('nodewarden-web-cache', 'vault-core');

function stripDecryptedCacheFields<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => stripDecryptedCacheFields(item)) as T;
  }
  if (!value || typeof value !== 'object') return value;
  const source = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(source)) {
    if (/^dec[A-Z]/.test(key) || key === 'shareUrl') continue;
    out[key] = stripDecryptedCacheFields(item);
  }
  return out as T;
}

function sanitizeSnapshotForCache(snapshot: VaultCoreSnapshot): VaultCoreSnapshot {
  return {
    ciphers: stripDecryptedCacheFields(Array.isArray(snapshot.ciphers) ? snapshot.ciphers : []),
    folders: stripDecryptedCacheFields(Array.isArray(snapshot.folders) ? snapshot.folders : []),
    sends: stripDecryptedCacheFields(Array.isArray(snapshot.sends) ? snapshot.sends : []),
  };
}

// Cache failures (no IndexedDB, quota, blocked storage) only cost a cold start, so every
// operation degrades to a miss or a no-op instead of throwing.
export async function loadCachedVaultCoreSnapshot(cacheKey: string): Promise<VaultCoreCacheRecord | null> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return null;
  try {
    const record = await get<VaultCoreCacheRecord>(normalized, vaultCoreStore);
    return record ? { ...record, snapshot: sanitizeSnapshotForCache(record.snapshot) } : null;
  } catch {
    return null;
  }
}

export async function saveCachedVaultCoreSnapshot(
  cacheKey: string,
  revisionStamp: number,
  snapshot: VaultCoreSnapshot
): Promise<void> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return;
  const record: VaultCoreCacheRecord = {
    cacheKey: normalized,
    revisionStamp,
    savedAt: Date.now(),
    snapshot: sanitizeSnapshotForCache(snapshot),
  };
  try {
    // Stores created before idb-keyval use the in-line keyPath 'cacheKey' and reject an explicit
    // key, while idb-keyval creates out-of-line stores that require one.
    await vaultCoreStore('readwrite', (store) => {
      store.put(record, store.keyPath === null ? normalized : undefined);
      return promisifyRequest(store.transaction);
    });
  } catch {
    // Best-effort cache write; see above.
  }
}

export async function clearCachedVaultCoreSnapshot(cacheKey: string): Promise<void> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return;
  try {
    await del(normalized, vaultCoreStore);
  } catch {
    // Best-effort cache delete; see above.
  }
}
