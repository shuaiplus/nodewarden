import { signHs256Jwt, verifyHs256Jwt } from './jwt';
import { generateUUID } from './uuid';

const WEBSOCKET_NOTIFICATION_SCOPE = 'notifications.websocket';

export interface WebSocketConnectionTokenClaims {
  userId: string;
  expiresAt: number;
  nonce: string;
  scope: typeof WEBSOCKET_NOTIFICATION_SCOPE;
}

export async function createWebSocketConnectionToken(
  userId: string,
  expiresAt: number,
  secret: string,
): Promise<string> {
  return signHs256Jwt(
    {
      userId,
      expiresAt,
      nonce: generateUUID(),
      scope: WEBSOCKET_NOTIFICATION_SCOPE,
    } satisfies WebSocketConnectionTokenClaims,
    secret,
  );
}

export async function verifyWebSocketConnectionToken(
  token: string,
  secret: string,
): Promise<WebSocketConnectionTokenClaims | null> {
  if (!token || token.length > 1024) return null;
  const claims = await verifyHs256Jwt<Partial<WebSocketConnectionTokenClaims>>(token, secret);
  if (
    claims?.scope !== WEBSOCKET_NOTIFICATION_SCOPE ||
    !String(claims.userId || '').trim() ||
    !Number.isFinite(claims.expiresAt) ||
    Number(claims.expiresAt) <= Date.now()
  ) {
    return null;
  }
  return claims as WebSocketConnectionTokenClaims;
}
