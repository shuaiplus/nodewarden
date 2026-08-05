import { generateUUID } from './uuid';

const WEBSOCKET_NOTIFICATION_SCOPE = 'notifications.websocket';

export interface WebSocketConnectionTokenClaims {
  userId: string;
  expiresAt: number;
  nonce: string;
  scope: typeof WEBSOCKET_NOTIFICATION_SCOPE;
}

function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(value: string): Uint8Array {
  let normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  while (normalized.length % 4) normalized += '=';
  const binary = atob(normalized);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function getSigningKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function createWebSocketConnectionToken(
  userId: string,
  expiresAt: number,
  secret: string
): Promise<string> {
  const claims: WebSocketConnectionTokenClaims = {
    userId,
    expiresAt,
    nonce: generateUUID(),
    scope: WEBSOCKET_NOTIFICATION_SCOPE,
  };
  const payload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(claims)));
  const signature = await crypto.subtle.sign(
    'HMAC',
    await getSigningKey(secret),
    new TextEncoder().encode(payload)
  );
  return `${payload}.${base64UrlEncode(new Uint8Array(signature))}`;
}

export async function verifyWebSocketConnectionToken(
  token: string,
  secret: string
): Promise<WebSocketConnectionTokenClaims | null> {
  try {
    if (!token || token.length > 1024) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [payload, encodedSignature] = parts;
    const valid = await crypto.subtle.verify(
      'HMAC',
      await getSigningKey(secret),
      base64UrlDecode(encodedSignature),
      new TextEncoder().encode(payload)
    );
    if (!valid) return null;

    const claims = JSON.parse(new TextDecoder().decode(base64UrlDecode(payload))) as Partial<WebSocketConnectionTokenClaims>;
    if (
      claims.scope !== WEBSOCKET_NOTIFICATION_SCOPE
      || !String(claims.userId || '').trim()
      || !Number.isFinite(claims.expiresAt)
      || Number(claims.expiresAt) <= Date.now()
    ) {
      return null;
    }
    return claims as WebSocketConnectionTokenClaims;
  } catch {
    return null;
  }
}
