import { t, translateServerError } from '../i18n';
import type { SessionState, TokenError } from '../types';

export type AuthedFetch = (input: string, init?: RequestInit) => Promise<Response>;
export type SessionSetter = (next: SessionState | null) => void;

export const BULK_API_CHUNK_SIZE = 200;

export function chunkArray<T>(items: T[], size: number): T[][] {
  if (items.length <= size) return [items];
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    chunks.push(items.slice(i, i + size));
  }
  return chunks;
}

export async function parseJson<T>(response: Response): Promise<T | null> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as T;
  } catch {
    return null;
  }
}

export function parseContentDispositionFileName(response: Response, fallback: string): string {
  const header = String(response.headers.get('Content-Disposition') || '').trim();
  if (!header) return fallback;

  const utf8Match = header.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      // Ignore malformed filename*= values and fall back to the plain filename.
    }
  }

  const plainMatch = header.match(/filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)/i);
  const raw = plainMatch?.[1] || plainMatch?.[2] || '';
  const normalized = String(raw).trim().replace(/^"+|"+$/g, '');
  return normalized || fallback;
}

export async function parseErrorMessage(resp: Response, fallback: string): Promise<string> {
  const body = await parseJson<TokenError>(resp);
  return translateServerError(body?.error_description || body?.error, fallback);
}

export function createApiError(message: string, status?: number): Error & { status?: number } {
  const error = new Error(message) as Error & { status?: number };
  if (status !== undefined) error.status = status;
  return error;
}

export function requiredError(messageKey: string): never {
  throw new Error(t(messageKey));
}

interface UploadWithProgressOptions {
  accessToken?: string;
  method?: string;
  headers?: HeadersInit;
  body?: XMLHttpRequestBodyInit | null;
  onProgress?: (percent: number | null) => void;
}

interface DirectEncryptedUploadOptions {
  accessToken: string;
  uploadUrl: string;
  payload: XMLHttpRequestBodyInit;
  fileUploadType: number | null | undefined;
  unsupportedMessage: string;
  onProgress?: (percent: number | null) => void;
}

function toAbsoluteUrl(input: string): string {
  if (typeof window === 'undefined') return input;
  return new URL(input, window.location.origin).toString();
}

function parseXhrHeaders(raw: string): Headers {
  const headers = new Headers();
  for (const line of raw.split(/\r?\n/)) {
    const index = line.indexOf(':');
    if (index <= 0) continue;
    const name = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();
    if (name) headers.append(name, value);
  }
  return headers;
}

export async function uploadWithProgress(input: string, options: UploadWithProgressOptions = {}): Promise<Response> {
  if (typeof XMLHttpRequest === 'undefined') {
    const headers = new Headers(options.headers || {});
    if (options.accessToken) headers.set('Authorization', `Bearer ${options.accessToken}`);
    return fetch(input, {
      method: options.method || 'POST',
      headers,
      body: options.body ?? null,
    });
  }

  return new Promise<Response>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(options.method || 'POST', toAbsoluteUrl(input), true);

    const headers = new Headers(options.headers || {});
    if (options.accessToken) headers.set('Authorization', `Bearer ${options.accessToken}`);
    headers.forEach((value, key) => xhr.setRequestHeader(key, value));

    xhr.upload.onprogress = (event) => {
      if (!options.onProgress) return;
      if (!event.lengthComputable || event.total <= 0) {
        options.onProgress(null);
        return;
      }
      options.onProgress(Math.max(0, Math.min(100, Math.round((event.loaded / event.total) * 100))));
    };

    xhr.onerror = () => reject(new Error('Network error'));
    xhr.onabort = () => reject(new Error('Upload aborted'));
    xhr.onload = () => {
      options.onProgress?.(100);
      resolve(
        new Response(xhr.responseText || null, {
          status: xhr.status,
          statusText: xhr.statusText,
          headers: parseXhrHeaders(xhr.getAllResponseHeaders()),
        })
      );
    };

    xhr.send(options.body ?? null);
  });
}

export async function uploadDirectEncryptedPayload(options: DirectEncryptedUploadOptions): Promise<Response> {
  if (options.fileUploadType !== 1) {
    throw new Error(options.unsupportedMessage);
  }

  return uploadWithProgress(options.uploadUrl, {
    accessToken: options.accessToken,
    method: 'PUT',
    headers: {
      'Content-Type': 'application/octet-stream',
      'x-ms-blob-type': 'BlockBlob',
    },
    body: options.payload,
    onProgress: options.onProgress,
  });
}
