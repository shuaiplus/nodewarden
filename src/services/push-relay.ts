import type { Env } from '../types';
import {
  setConfigValue as saveConfigValue,
} from './storage-config-repo';

const PUSH_RELAY_URI = 'https://push.bitwarden.com';
const PUSH_IDENTITY_URI = 'https://identity.bitwarden.com';
const INSTALLATIONS_URI = 'https://api.bitwarden.com/installations';
const PUSH_INSTALLATION_ID_KEY = 'push.installation.id';
const PUSH_INSTALLATION_KEY_KEY = 'push.installation.key';
const PUSH_REQUEST_TIMEOUT_MS = 5000;

interface CachedPushAccessToken {
  token: string;
  expiresAt: number;
}

let cachedPushAccessToken: CachedPushAccessToken | null = null;

async function fetchPushEndpoint(url: string, init: RequestInit, errorMessage: string): Promise<Response | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PUSH_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } catch (error) {
    console.error(errorMessage, error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function randomInstallationEmail(): string {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const localPart = Array.from(bytes, (byte) => (byte % 36).toString(36)).join('');
  return `${localPart}@nodewarden.app`;
}

async function getConfigKeyPresence(db: D1Database, key: string): Promise<string | null> {
  const row = await db.prepare('SELECT value FROM config WHERE key = ? LIMIT 1').bind(key).first<{ value: string }>();
  return typeof row?.value === 'string' ? row.value : null;
}

async function getPushInstallationCredentials(db: D1Database): Promise<{ id: string; key: string } | null> {
  const [id, key] = await Promise.all([
    getConfigKeyPresence(db, PUSH_INSTALLATION_ID_KEY),
    getConfigKeyPresence(db, PUSH_INSTALLATION_KEY_KEY),
  ]);
  const normalizedId = String(id || '').trim();
  const normalizedKey = String(key || '').trim();
  return normalizedId && normalizedKey ? { id: normalizedId, key: normalizedKey } : null;
}

export async function ensurePushInstallationCredentials(db: D1Database): Promise<{ id: string; key: string } | null> {
  const existing = await getPushInstallationCredentials(db);
  if (existing) return existing;

  const response = await fetchPushEndpoint(
    INSTALLATIONS_URI,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        email: randomInstallationEmail(),
      }),
    },
    'Failed to request Bitwarden push installation:'
  );
  if (!response) return null;

  if (!response.ok) {
    console.error('Failed to request Bitwarden push installation:', response.status, await response.text().catch(() => ''));
    return null;
  }

  const body = (await response.json().catch(() => null)) as { id?: string; Id?: string; key?: string; Key?: string; enabled?: boolean; Enabled?: boolean } | null;
  const id = String(body?.id || body?.Id || '').trim();
  const key = String(body?.key || body?.Key || '').trim();
  if (!id || !key) {
    console.error('Bitwarden push installation response did not include id/key');
    return null;
  }

  await Promise.all([
    saveConfigValue(db, PUSH_INSTALLATION_ID_KEY, id),
    saveConfigValue(db, PUSH_INSTALLATION_KEY_KEY, key),
  ]);
  return { id, key };
}

async function getPushAccessToken(env: Env): Promise<string | null> {
  const credentials = await ensurePushInstallationCredentials(env.DB);
  if (!credentials) return null;

  const now = Date.now();
  if (cachedPushAccessToken && cachedPushAccessToken.expiresAt > now + 30_000) {
    return cachedPushAccessToken.token;
  }

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api.push',
    client_id: `installation.${credentials.id}`,
    client_secret: credentials.key,
  });

  const response = await fetchPushEndpoint(
    `${PUSH_IDENTITY_URI}/connect/token`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    },
    'Failed to get Bitwarden push relay token:'
  );
  if (!response) return null;

  if (!response.ok) {
    console.error('Failed to get Bitwarden push relay token:', response.status, await response.text().catch(() => ''));
    return null;
  }

  const body = (await response.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
  const token = String(body?.access_token || '').trim();
  if (!token) {
    console.error('Bitwarden push relay token response did not include an access_token');
    return null;
  }

  const expiresInSeconds = Math.max(60, Number(body?.expires_in || 3600));
  cachedPushAccessToken = {
    token,
    expiresAt: now + Math.floor(expiresInSeconds * 500),
  };
  return token;
}

async function postToPushRelay(env: Env, path: string, body?: unknown): Promise<boolean> {
  const token = await getPushAccessToken(env);
  if (!token) return false;

  const response = await fetchPushEndpoint(
    `${PUSH_RELAY_URI}${path}`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    `Bitwarden push relay request failed: ${path}`
  );
  if (!response) return false;

  if (!response.ok) {
    console.error('Bitwarden push relay request failed:', path, response.status, await response.text().catch(() => ''));
    return false;
  }

  return true;
}

function mobilePayloadFromSignalR(updateType: number, userId: string, revisionDate: string, payload: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const source = payload || {};
  const id = source.Id ?? source.id;
  const organizationId = source.OrganizationId ?? source.organizationId ?? null;
  const collectionIds = source.CollectionIds ?? source.collectionIds ?? null;

  if (id != null) {
    return {
      id,
      userId: source.UserId ?? source.userId ?? userId,
      organizationId,
      collectionIds,
      revisionDate: source.RevisionDate ?? source.revisionDate ?? revisionDate,
    };
  }

  return {
    userId: source.UserId ?? source.userId ?? userId,
    date: source.Date ?? source.date ?? revisionDate,
  };
}

export async function registerMobilePushDevice(
  env: Env,
  input: {
    userId: string;
    deviceIdentifier: string;
    type: number;
    pushUuid: string;
    pushToken: string;
  }
): Promise<boolean> {
  const credentials = await ensurePushInstallationCredentials(env.DB);
  if (!credentials) return false;

  return postToPushRelay(env, '/push/register', {
    deviceId: input.pushUuid,
    pushToken: input.pushToken,
    userId: input.userId,
    type: input.type,
    identifier: input.deviceIdentifier,
    installationId: credentials.id,
  });
}

export async function unregisterMobilePushDevice(env: Env, pushUuid: string | null | undefined): Promise<boolean> {
  const normalized = String(pushUuid || '').trim();
  if (!normalized) return false;
  return postToPushRelay(env, '/push/delete', { id: normalized });
}

export async function notifyMobilePush(
  env: Env,
  input: {
    userId: string;
    updateType: number;
    revisionDate: string;
    contextId: string | null;
    payload: Record<string, unknown> | null | undefined;
  }
): Promise<void> {
  const hasPushDevice = await env.DB
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND push_token IS NOT NULL AND push_token <> ? LIMIT 1')
    .bind(input.userId, '')
    .first<{ '1': number }>();
  if (!hasPushDevice) return;

  let actingPushUuid: string | null = null;
  if (input.contextId) {
    const row = await env.DB
      .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
      .bind(input.userId, input.contextId)
      .first<{ push_uuid: string | null }>();
    actingPushUuid = row?.push_uuid ?? null;
  }

  await postToPushRelay(env, '/push/send', {
    userId: input.userId,
    organizationId: null,
    deviceId: actingPushUuid,
    identifier: input.contextId,
    type: input.updateType,
    payload: mobilePayloadFromSignalR(input.updateType, input.userId, input.revisionDate, input.payload),
    clientType: null,
    installationId: null,
  });
}
