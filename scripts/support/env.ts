import { registerHooks } from 'node:module';

import { LIMITS } from '../../src/config/limits';
import { AuthService } from '../../src/services/auth';
import { StorageService } from '../../src/services/storage';
import type { Env, User } from '../../src/types';
import { waitUntil } from './cloudflare-workers';
import { createSqliteD1 } from './d1-sqlite';

export const TEST_ORIGIN = 'https://vault.example.test';
// Cloudflare always sets CF-Connecting-IP, and public routes refuse to rate-limit without it.
// RFC 5737 documentation address.
const TEST_CLIENT_IP = '203.0.113.10';
const TEST_JWT_SECRET = 'nodewarden-test-jwt-secret-'.padEnd(LIMITS.auth.jwtSecretMinLength, '0');
const PBKDF2_KDF_TYPE = 0;

// Workers-only globals. The Cache API (sync responses, rate-limit counters) is a Map keyed by
// cache name and URL that ignores Cache-Control, so a handler that forgets to bump the revision
// date is served its stale entry. fetch is blocked so tests stay hermetic: the storage
// bootstrap would otherwise register a real push installation with Bitwarden.
const cachedResponses = new Map<string, Response>();
const namedCache = (cacheName: string) => ({
  async match(request: RequestInfo | URL): Promise<Response | undefined> {
    return cachedResponses.get(`${cacheName} ${new Request(request).url}`)?.clone();
  },
  async put(request: RequestInfo | URL, response: Response): Promise<void> {
    cachedResponses.set(`${cacheName} ${new Request(request).url}`, response);
  },
});
Object.assign(globalThis, {
  caches: { default: namedCache('default'), open: async (cacheName: string) => namedCache(cacheName) },
  async fetch(input: RequestInfo | URL): Promise<Response> {
    throw new Error(`Outbound fetch blocked in tests: ${new Request(input).url}`);
  },
});

// src/durable/notifications-hub.ts imports `cloudflare:workers`, which Node cannot resolve.
// Static imports link before this module body runs, so the Worker entry loads dynamically.
const cloudflareWorkersStandIn = new URL('./cloudflare-workers.ts', import.meta.url).href;
registerHooks({
  resolve: (specifier, context, nextResolve) => (specifier === 'cloudflare:workers'
    ? { url: cloudflareWorkersStandIn, shortCircuit: true }
    : nextResolve(specifier, context)),
});
const { default: worker } = await import('../../src/index');

// src/index.ts and StorageService bootstrap storage once per isolate. Run that bootstrap now on
// a throwaway database so it never re-runs on a test database, where it would promote
// whichever user was seeded first to admin.
await new StorageService(await createSqliteD1()).initializeDatabase();

const executionContext = { waitUntil, passThroughOnException: () => {} } as unknown as ExecutionContext;

// Realtime notifications go to the NotificationsHub Durable Object; tests only need them accepted.
const acceptingDurableObjectNamespace = {
  idFromName: (name: string) => name,
  get: () => ({ fetch: async () => new Response(null, { status: 204 }) }),
} as unknown as DurableObjectNamespace;

// Every env is a fresh deployment: its own database and an empty edge cache, so rate-limit
// budgets keyed by the shared test client IP never leak between tests.
export async function createTestEnv(overrides: Partial<Env> = {}): Promise<Env> {
  cachedResponses.clear();
  return {
    DB: await createSqliteD1(),
    JWT_SECRET: TEST_JWT_SECRET,
    NOTIFICATIONS_HUB: acceptingDurableObjectNamespace,
    ...overrides,
  } as Env;
}

export function memoryKv(): { binding: KVNamespace; values: Map<string, string> } {
  const values = new Map<string, string>();
  const binding = {
    get: async (key: string) => values.get(key) ?? null,
    put: async (key: string, value: string) => { values.set(key, value); },
    delete: async (key: string) => { values.delete(key); },
  } as KVNamespace;
  return { binding, values };
}

export async function seedUser(env: Env, overrides: Partial<User> = {}): Promise<User> {
  const id = overrides.id ?? crypto.randomUUID();
  const now = new Date().toISOString();
  const user: User = {
    id,
    email: `${id}@example.test`,
    emailVerified: true,
    name: 'Test User',
    masterPasswordHint: null,
    masterPasswordHash: 'test-master-password-hash',
    key: '2.dGVzdA==|dGVzdA==|dGVzdA==',
    privateKey: null,
    publicKey: null,
    kdfType: PBKDF2_KDF_TYPE,
    kdfIterations: LIMITS.auth.defaultKdfIterations,
    securityStamp: crypto.randomUUID(),
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    twoFactorEmail: null,
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: null,
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
  await new StorageService(env.DB).createUser(user);
  return user;
}

export interface WorkerRequest {
  method?: string;
  path: string;
  // JSON-encoded, except URLSearchParams, which is sent form-encoded as /identity expects, and
  // FormData, which is sent multipart as official web uploads files.
  body?: unknown;
  // Omit for an anonymous request.
  userId?: string;
  headers?: HeadersInit;
}

// Calls the real Worker fetch handler, so routing, auth and CORS all run.
export async function authedFetch(env: Env, { method = 'GET', path, body, userId, headers }: WorkerRequest): Promise<Response> {
  const requestHeaders = new Headers({ 'CF-Connecting-IP': TEST_CLIENT_IP });
  if (userId) {
    const user = await new StorageService(env.DB).getUserById(userId);
    if (!user) throw new Error(`authedFetch: no user ${userId}`);
    requestHeaders.set('Authorization', `Bearer ${await new AuthService(env).generateAccessToken(user)}`);
  }
  const isForm = body instanceof URLSearchParams || body instanceof FormData;
  if (body !== undefined && !isForm) requestHeaders.set('Content-Type', 'application/json');
  new Headers(headers).forEach((value, name) => requestHeaders.set(name, value));

  const request = new Request(new URL(path, TEST_ORIGIN), {
    method,
    headers: requestHeaders,
    body: body === undefined || isForm ? body : JSON.stringify(body),
  });
  return worker.fetch(request, env, executionContext);
}

export const MAILABLE_DOMAIN = 'stevefan1999.tech';
export type SentEmail = Parameters<NonNullable<Env['EMAIL']>['send']>[0];

export function captureEmail(): { overrides: Partial<Env>; sent: SentEmail[] } {
  const sent: SentEmail[] = [];
  return {
    sent,
    overrides: {
      EMAIL: { async send(message) { sent.push(message); return { messageId: crypto.randomUUID() }; } },
      EMAIL_FROM: `noreply@${MAILABLE_DOMAIN}`,
      WEB_VAULT_ORIGINS: 'https://web.example.test',
    },
  };
}

export function failingEmail(code: string): NonNullable<Env['EMAIL']> {
  return { async send() { throw Object.assign(new Error('x'), { code }); } };
}
export { drainWaitUntil } from './cloudflare-workers';

export function portalFetch(env: Env, { method = 'GET', path, form, cookie, headers }: { method?: string; path: string; form?: Record<string, string>; cookie?: string; headers?: HeadersInit }): Promise<Response> {
  const requestHeaders = new Headers(headers);
  if (method === 'POST' && !requestHeaders.has('Origin')) requestHeaders.set('Origin', TEST_ORIGIN);
  if (cookie) requestHeaders.set('Cookie', cookie);
  return authedFetch(env, { method, path, body: form ? new URLSearchParams(form) : undefined, headers: requestHeaders });
}

export async function signInToAdminPortal(env: Env, email: string): Promise<{ cookie: string; csrf: string }> {
  const { parseAdminDirectory, createAdminSession, adminCookie, ADMIN_COOKIE } = await import('../../src/services/admin-portal-auth');
  const directory = parseAdminDirectory(env);
  if (directory.kind !== 'enabled' || !directory.admins.has(email)) throw new Error('Test administrator is not configured');
  const session = await createAdminSession(env, email, directory.admins.get(email)!);
  return { cookie: adminCookie(ADMIN_COOKIE, session.token, LIMITS.admin.sessionTtlSeconds), csrf: session.csrf };
}
