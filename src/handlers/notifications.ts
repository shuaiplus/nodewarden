import { AuthService } from '../services/auth';
import { isAuthRequestExpired } from '../services/storage-auth-request-repo';
import type { Env, JWTPayload } from '../types';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { createWebSocketConnectionToken, verifyWebSocketConnectionToken } from '../utils/websocket-connection-token';
import * as authRequestRepo from '../services/storage-auth-request-repo';

const WEBSOCKET_CONNECTION_TOKEN_TTL_MS = 60 * 1000;

async function authenticateAccessToken(request: Request, env: Env): Promise<JWTPayload | null> {
  const authHeader = String(request.headers.get('Authorization') || '').trim();
  const accessToken = authHeader.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (!accessToken) return null;

  const auth = new AuthService(env);
  return auth.verifyAccessToken(`Bearer ${accessToken}`);
}

export async function handleNotificationsNegotiate(request: Request, env: Env): Promise<Response> {
  const payload = await authenticateAccessToken(request, env);
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  // Issue the single-use connection token the WebSocket upgrade presents instead of the access JWT.
  const expiresAt = Date.now() + WEBSOCKET_CONNECTION_TOKEN_TTL_MS;
  const connectionToken = await createWebSocketConnectionToken(payload.sub, expiresAt, env.JWT_SECRET);
  const id = env.NOTIFICATIONS_HUB.idFromName(payload.sub);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const response = await stub.fetch('https://notifications/internal/ws-token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: connectionToken,
      userId: payload.sub,
      deviceIdentifier: payload.did || null,
      expiresAt,
    }),
  });
  if (!response.ok) throw new Error('Failed to issue websocket connection token');
  return jsonResponse(
    {
      connectionId: generateUUID(),
      connectionToken,
      negotiateVersion: 1,
      availableTransports: [
        {
          transport: 'WebSockets',
          transferFormats: ['Text', 'Binary'],
        },
      ],
    },
    200,
    { 'Cache-Control': 'no-store' },
  );
}

export async function handleNotificationsHub(request: Request, env: Env): Promise<Response> {
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }
  // Never accept an access JWT from the URL: URLs are routinely retained by logs,
  // browser history, proxies, monitoring, and error tracking systems.
  let payload: JWTPayload | null;
  if (request.headers.has('Authorization')) {
    payload = await authenticateAccessToken(request, env);
  } else {
    // Without the header, consume the single-use connection token from negotiate (SignalR sends it as id).
    const token = String(new URL(request.url).searchParams.get('id') || '').trim();
    const claims = await verifyWebSocketConnectionToken(token, env.JWT_SECRET);
    if (!claims) return errorResponse('Unauthorized', 401);

    // Verify the signed routing claim before selecting a Durable Object. Otherwise an
    // attacker could activate arbitrary object names with forged token prefixes.
    const tokenHub = env.NOTIFICATIONS_HUB.get(env.NOTIFICATIONS_HUB.idFromName(claims.userId));
    const response = await tokenHub.fetch('https://notifications/internal/ws-token/consume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    if (!response.ok) return errorResponse('Unauthorized', 401);

    const connection = (await response.json().catch(() => null)) as {
      userId?: string;
      deviceIdentifier?: string | null;
    } | null;
    if (connection?.userId !== claims.userId) return errorResponse('Unauthorized', 401);

    payload = {
      sub: claims.userId,
      did: String(connection.deviceIdentifier || '').trim() || undefined,
    } as JWTPayload;
  }
  if (!payload?.sub) return errorResponse('Unauthorized', 401);

  const userId = payload.sub;
  const id = env.NOTIFICATIONS_HUB.idFromName(userId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_uid', userId);
  if (payload.did) {
    forwardedUrl.searchParams.set('nw_did', payload.did);
  }
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}

export async function handleAnonymousNotificationsHub(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const authRequestId = String(url.searchParams.get('Token') || url.searchParams.get('token') || '').trim();
  if (!authRequestId) return errorResponse('Token is required', 400);
  if (request.headers.get('Upgrade')?.toLowerCase() !== 'websocket') {
    return errorResponse('Expected websocket', 426);
  }

  const authRequest = await authRequestRepo.getAuthRequestById(env.DB, authRequestId);
  if (!authRequest || isAuthRequestExpired(authRequest)) {
    return errorResponse('Not found', 404);
  }

  const id = env.NOTIFICATIONS_HUB.idFromName(authRequestId);
  const stub = env.NOTIFICATIONS_HUB.get(id);
  const forwardedUrl = new URL(request.url);
  forwardedUrl.searchParams.set('nw_auth_request_id', authRequestId);
  return stub.fetch(new Request(forwardedUrl.toString(), request));
}
