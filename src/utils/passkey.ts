import { decodeBase64Url, encodeBase64Url } from 'hono/utils/encode';

// WebAuthn values, challenges and our stored ids are unpadded base64url; hono keeps the padding.
// Copying into a fresh Uint8Array hands hono exactly the view's bytes, even for a subarray.
export function bytesToBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  return encodeBase64Url(new Uint8Array(bytes).buffer).replace(/=+$/, '');
}

export function parseClientDataJSON(base64Url: string): { type?: string; challenge?: string; origin?: string } | null {
  try {
    const raw = decodeBase64Url(base64Url);
    const text = new TextDecoder().decode(raw);
    const parsed = JSON.parse(text) as { type?: string; challenge?: string; origin?: string };
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}
