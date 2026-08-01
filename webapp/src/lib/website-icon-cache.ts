type WebsiteIconStatus = 'idle' | 'loading' | 'loaded' | 'error';

interface WebsiteIconRecord {
  status: WebsiteIconStatus;
  imageUrl: string | null;
  errorAt: number;
  loadStartedAt: number;
  loadToken: number;
  loader: HTMLImageElement | null;
  timeoutId: ReturnType<typeof setTimeout> | null;
  listeners: Set<(status: WebsiteIconStatus) => void>;
}

const WEBSITE_ICON_ERROR_TTL_MS = 5 * 60 * 1000;
const WEBSITE_ICON_LOAD_TIMEOUT_MS = 15 * 1000;

const iconRecords = new Map<string, WebsiteIconRecord>();

function ensureRecord(host: string): WebsiteIconRecord {
  let record = iconRecords.get(host);
  if (!record) {
    record = {
      status: 'idle',
      imageUrl: null,
      errorAt: 0,
      loadStartedAt: 0,
      loadToken: 0,
      loader: null,
      timeoutId: null,
      listeners: new Set(),
    };
    iconRecords.set(host, record);
  }
  return record;
}

function clearLoadTimer(record: WebsiteIconRecord): void {
  if (record.timeoutId) {
    clearTimeout(record.timeoutId);
    record.timeoutId = null;
  }
}

function expireRecordIfNeeded(record: WebsiteIconRecord): void {
  const now = Date.now();
  if (record.status === 'error' && record.errorAt && now - record.errorAt >= WEBSITE_ICON_ERROR_TTL_MS) {
    record.status = 'idle';
    record.errorAt = 0;
    record.imageUrl = null;
  }
  if (record.status === 'loading' && record.loadStartedAt && now - record.loadStartedAt >= WEBSITE_ICON_LOAD_TIMEOUT_MS) {
    clearLoadTimer(record);
    record.status = 'error';
    record.errorAt = now;
    record.imageUrl = null;
    record.loader = null;
  }
}

function notifyRecord(host: string, status: WebsiteIconStatus): void {
  const record = ensureRecord(host);
  record.status = status;
  for (const listener of Array.from(record.listeners)) {
    listener(status);
  }
}

export function getWebsiteIconStatus(host: string): WebsiteIconStatus {
  if (!host) return 'idle';
  const record = ensureRecord(host);
  expireRecordIfNeeded(record);
  return record.status;
}

export function getWebsiteIconImageUrl(host: string): string {
  if (!host) return '';
  const record = ensureRecord(host);
  expireRecordIfNeeded(record);
  return record.imageUrl || '';
}

export function subscribeWebsiteIconStatus(host: string, listener: (status: WebsiteIconStatus) => void): () => void {
  if (!host) return () => undefined;
  const record = ensureRecord(host);
  record.listeners.add(listener);
  return () => {
    record.listeners.delete(listener);
  };
}

function markWebsiteIconLoaded(host: string, imageUrl?: string): void {
  if (!host) return;
  const record = ensureRecord(host);
  clearLoadTimer(record);
  if (imageUrl) {
    record.imageUrl = imageUrl;
  }
  record.errorAt = 0;
  record.loadStartedAt = 0;
  record.loader = null;
  notifyRecord(host, 'loaded');
}

function markWebsiteIconErrored(host: string): void {
  if (!host) return;
  const record = ensureRecord(host);
  clearLoadTimer(record);
  record.imageUrl = null;
  record.errorAt = Date.now();
  record.loadStartedAt = 0;
  record.loader = null;
  notifyRecord(host, 'error');
}

export function beginWebsiteIconLoad(host: string, src: string): boolean {
  if (!host || !src) return false;
  const record = ensureRecord(host);
  expireRecordIfNeeded(record);
  if (record.status !== 'idle') return false;

  if (typeof Image !== 'function') {
    markWebsiteIconErrored(host);
    return false;
  }

  const token = record.loadToken + 1;
  const loader = new Image();
  record.loadToken = token;
  record.loader = loader;
  record.imageUrl = src;
  record.errorAt = 0;
  record.loadStartedAt = Date.now();
  notifyRecord(host, 'loading');

  record.timeoutId = setTimeout(() => {
    const current = ensureRecord(host);
    if (current.loadToken !== token || current.status !== 'loading') return;
    current.imageUrl = null;
    current.errorAt = Date.now();
    current.loadStartedAt = 0;
    current.loader = null;
    current.timeoutId = null;
    notifyRecord(host, 'error');
  }, WEBSITE_ICON_LOAD_TIMEOUT_MS);

  loader.onload = () => {
    const current = ensureRecord(host);
    if (current.loadToken !== token) return;
    markWebsiteIconLoaded(host, src);
  };
  loader.onerror = () => {
    const current = ensureRecord(host);
    if (current.loadToken !== token) return;
    markWebsiteIconErrored(host);
  };
  loader.src = src;

  return true;
}
