import assert from 'node:assert/strict';
import test from 'node:test';

import { handleNotificationsHub, handleNotificationsNegotiate } from '../src/handlers/notifications';
import type { Env } from '../src/types';
import { createJWT } from '../src/utils/jwt';

const secret = 'notification-security-test-secret-32-bytes';
const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const securityStamp = 'security-stamp';

function createTestEnv() {
  const connectionTokens = new Map<string, { userId: string; deviceIdentifier: string | null; expiresAt: number }>();
  const forwardedHubUrls: string[] = [];
  const durableObjectNames: string[] = [];
  const userRow = {
    id: userId,
    email: 'user@example.test',
    name: 'Test User',
    master_password_hint: null,
    master_password_hash: 'hash',
    key: 'key',
    private_key: null,
    public_key: null,
    kdf_type: 0,
    kdf_iterations: 600000,
    kdf_memory: null,
    kdf_parallelism: null,
    security_stamp: securityStamp,
    role: 'user',
    status: 'active',
    verify_devices: 0,
    totp_secret: null,
    totp_recovery_code: null,
    yubikey_key1: null,
    yubikey_key2: null,
    yubikey_key3: null,
    yubikey_key4: null,
    yubikey_key5: null,
    yubikey_nfc: 0,
    api_key: null,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const db = {
    prepare() {
      return {
        bind() {
          return this;
        },
        async first() {
          return userRow;
        },
      };
    },
  } as unknown as D1Database;

  const stub = {
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const request = new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === '/internal/ws-token') {
        const body = await request.json() as {
          token: string;
          userId: string;
          deviceIdentifier: string | null;
          expiresAt: number;
        };
        connectionTokens.set(body.token, body);
        return new Response(null, { status: 204 });
      }
      if (url.pathname === '/internal/ws-token/consume') {
        const { token } = await request.json() as { token: string };
        const connection = connectionTokens.get(token);
        connectionTokens.delete(token);
        if (!connection || connection.expiresAt <= Date.now()) return new Response(null, { status: 401 });
        return Response.json(connection);
      }
      forwardedHubUrls.push(request.url);
      return new Response(null, { status: 204 });
    },
  };

  const env = {
    DB: db,
    JWT_SECRET: secret,
    NOTIFICATIONS_HUB: {
      idFromName(name: string) {
        durableObjectNames.push(name);
        return name;
      },
      get() {
        return stub;
      },
    },
  } as unknown as Env;

  return { env, connectionTokens, durableObjectNames, forwardedHubUrls };
}

async function validAccessToken(): Promise<string> {
  return createJWT({
    sub: userId,
    email: 'user@example.test',
    name: 'Test User',
    sstamp: securityStamp,
  }, secret);
}

test('query access_token cannot authenticate a websocket', async () => {
  const { env, forwardedHubUrls } = createTestEnv();
  const token = await validAccessToken();
  const response = await handleNotificationsHub(new Request(
    `https://vault.example.test/notifications/hub?access_token=${encodeURIComponent(token)}`,
    { headers: { Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 401);
  assert.deepEqual(forwardedHubUrls, []);
});

test('Authorization bearer token still authenticates notifications', async () => {
  const { env, forwardedHubUrls } = createTestEnv();
  const token = await validAccessToken();
  const response = await handleNotificationsHub(new Request(
    'https://vault.example.test/notifications/hub',
    { headers: { Authorization: `Bearer ${token}`, Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 204);
  assert.equal(new URL(forwardedHubUrls[0]).searchParams.get('nw_uid'), userId);
});

test('negotiate issues a short-lived one-time websocket connection token', async () => {
  const { env, connectionTokens, forwardedHubUrls } = createTestEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(new Request(
    'https://vault.example.test/notifications/hub/negotiate',
    { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } }
  ), env);
  const body = await negotiate.json() as { connectionToken: string };
  const stored = connectionTokens.get(body.connectionToken);

  assert.equal(negotiate.status, 200);
  assert.ok(stored);
  assert.ok(stored.expiresAt > Date.now());
  assert.ok(stored.expiresAt <= Date.now() + 60_000);

  const request = () => new Request(
    `https://vault.example.test/notifications/hub?id=${encodeURIComponent(body.connectionToken)}`,
    { headers: { Upgrade: 'websocket' } }
  );
  assert.equal((await handleNotificationsHub(request(), env)).status, 204);
  assert.equal((await handleNotificationsHub(request(), env)).status, 401);
  assert.equal(forwardedHubUrls.length, 1);
});

test('a non-upgrade request does not consume a websocket connection token', async () => {
  const { env, connectionTokens } = createTestEnv();
  const accessToken = await validAccessToken();
  const negotiate = await handleNotificationsNegotiate(new Request(
    'https://vault.example.test/notifications/hub/negotiate',
    { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } }
  ), env);
  const { connectionToken } = await negotiate.json() as { connectionToken: string };
  const url = `https://vault.example.test/notifications/hub?id=${encodeURIComponent(connectionToken)}`;

  assert.equal((await handleNotificationsHub(new Request(url), env)).status, 426);
  assert.ok(connectionTokens.has(connectionToken));
  assert.equal((await handleNotificationsHub(new Request(url, { headers: { Upgrade: 'websocket' } }), env)).status, 204);
});

test('a forged ticket cannot select or activate a Durable Object', async () => {
  const { env, durableObjectNames } = createTestEnv();
  const response = await handleNotificationsHub(new Request(
    'https://vault.example.test/notifications/hub?id=attacker-controlled.invalid-signature',
    { headers: { Upgrade: 'websocket' } }
  ), env);

  assert.equal(response.status, 401);
  assert.deepEqual(durableObjectNames, []);
});
