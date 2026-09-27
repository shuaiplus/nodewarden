import type { Env } from '../types';
import {
  getConfigValue as getStoredConfigValue,
  setConfigValue as saveConfigValue,
} from './storage-config-repo';
import { getDevicePushUuid, userHasPushDevice } from './storage-device-repo';

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

export async function ensurePushInstallationCredentials(db: D1Database): Promise<{ id: string; key: string } | null> {
  const [storedId, storedKey] = (await Promise.all([
    getStoredConfigValue(db, PUSH_INSTALLATION_ID_KEY),
    getStoredConfigValue(db, PUSH_INSTALLATION_KEY_KEY),
  ])).map((value) => String(value || '').trim());
  if (storedId && storedKey) return { id: storedId, key: storedKey };

  const response = await fetchPushEndpoint(
    INSTALLATIONS_URI,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        email: `${Array.from(crypto.getRandomValues(new Uint8Array(10)), (byte) => (byte % 36).toString(36)).join('')}@nodewarden.app`,
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

async function postToPushRelay(env: Env, path: string, body?: unknown): Promise<boolean> {
  const credentials = await ensurePushInstallationCredentials(env.DB);
  if (!credentials) return false;

  // Reuse the cached relay access token while it has over 30 seconds left; otherwise request a new one.
  const now = Date.now();
  let token: string;
  if (cachedPushAccessToken && cachedPushAccessToken.expiresAt > now + 30_000) {
    token = cachedPushAccessToken.token;
  } else {
    const params = new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.push',
      client_id: `installation.${credentials.id}`,
      client_secret: credentials.key,
    });

    const tokenResponse = await fetchPushEndpoint(
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
    if (!tokenResponse) return false;

    if (!tokenResponse.ok) {
      console.error('Failed to get Bitwarden push relay token:', tokenResponse.status, await tokenResponse.text().catch(() => ''));
      return false;
    }

    const tokenBody = (await tokenResponse.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
    token = String(tokenBody?.access_token || '').trim();
    if (!token) {
      console.error('Bitwarden push relay token response did not include an access_token');
      return false;
    }

    const expiresInSeconds = Math.max(60, Number(tokenBody?.expires_in || 3600));
    cachedPushAccessToken = {
      token,
      expiresAt: now + Math.floor(expiresInSeconds * 500),
    };
  }

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
  if (!(await userHasPushDevice(env.DB, input.userId))) return;

  const actingPushUuid = input.contextId
    ? await getDevicePushUuid(env.DB, input.userId, input.contextId)
    : null;

  // Reshape the SignalR payload (PascalCase or camelCase keys) for mobile push: an item change
  // carries its id and scope, anything else only the user and date.
  const source = input.payload || {};
  const id = source.Id ?? source.id;
  await postToPushRelay(env, '/push/send', {
    userId: input.userId,
    organizationId: null,
    deviceId: actingPushUuid,
    identifier: input.contextId,
    type: input.updateType,
    payload: id != null
      ? {
        id,
        userId: source.UserId ?? source.userId ?? input.userId,
        organizationId: source.OrganizationId ?? source.organizationId ?? null,
        collectionIds: source.CollectionIds ?? source.collectionIds ?? null,
        revisionDate: source.RevisionDate ?? source.revisionDate ?? input.revisionDate,
      }
      : {
        userId: source.UserId ?? source.userId ?? input.userId,
        date: source.Date ?? source.date ?? input.revisionDate,
      },
    clientType: null,
    installationId: null,
  });
}
