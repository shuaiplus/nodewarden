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

const DB_NAME = 'nodewarden-web-cache';
const DB_VERSION = 1;
const VAULT_CORE_STORE = 'vault-core';

let dbPromise: Promise<IDBDatabase | null> | null = null;

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

function supportsIndexedDb(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDatabase(): Promise<IDBDatabase | null> {
  if (!supportsIndexedDb()) return Promise.resolve(null);
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve) => {
    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(VAULT_CORE_STORE)) {
          db.createObjectStore(VAULT_CORE_STORE, { keyPath: 'cacheKey' });
        }
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => resolve(null);
      request.onblocked = () => resolve(null);
    } catch {
      resolve(null);
    }
  });
  return dbPromise;
}

function withStore<T>(
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => Promise<T>
): Promise<T | null> {
  return openDatabase().then((db) => {
    if (!db) return null;
    return new Promise<T | null>((resolve) => {
      try {
        const tx = db.transaction(VAULT_CORE_STORE, mode);
        const store = tx.objectStore(VAULT_CORE_STORE);
        void run(store).then(resolve).catch(() => resolve(null));
        tx.onerror = () => resolve(null);
        tx.onabort = () => resolve(null);
      } catch {
        resolve(null);
      }
    });
  });
}

export async function loadCachedVaultCoreSnapshot(cacheKey: string): Promise<VaultCoreCacheRecord | null> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return null;
  return withStore('readonly', (store) => new Promise<VaultCoreCacheRecord | null>((resolve) => {
    const request = store.get(normalized);
    request.onsuccess = () => {
      const record = request.result as VaultCoreCacheRecord | undefined;
      resolve(record ? { ...record, snapshot: sanitizeSnapshotForCache(record.snapshot) } : null);
    };
    request.onerror = () => resolve(null);
  }));
}

export async function saveCachedVaultCoreSnapshot(
  cacheKey: string,
  revisionStamp: number,
  snapshot: VaultCoreSnapshot
): Promise<void> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return;
  await withStore('readwrite', (store) => new Promise<void>((resolve) => {
    const record: VaultCoreCacheRecord = {
      cacheKey: normalized,
      revisionStamp,
      savedAt: Date.now(),
      snapshot: sanitizeSnapshotForCache(snapshot),
    };
    const request = store.put(record);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
  }));
}

export async function clearCachedVaultCoreSnapshot(cacheKey: string): Promise<void> {
  const normalized = String(cacheKey || '').trim();
  if (!normalized) return;
  await withStore('readwrite', (store) => new Promise<void>((resolve) => {
    const request = store.delete(normalized);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
  }));
}
