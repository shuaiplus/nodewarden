// Regression tests for the security-audit remediations (M-1, M-2, M-3).
// Run with: npm run test:security-remediations
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { handleCreateAuthRequest } from '../src/handlers/auth-requests';
import { handleToken } from '../src/handlers/identity';
import { buildBackupArchive } from '../src/services/backup-archive';
import { RateLimitService } from '../src/services/ratelimit';
import { LIMITS } from '../src/config/limits';
import type { Env } from '../src/types';

const USER_ID = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const USER_EMAIL = 'user@example.test';

function userRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: USER_ID,
    email: USER_EMAIL,
    name: 'Test User',
    master_password_hint: null,
    master_password_hash: null,
    key: 'key',
    private_key: null,
    public_key: null,
    kdf_type: 0,
    kdf_iterations: 600000,
    kdf_memory: null,
    kdf_parallelism: null,
    security_stamp: 'security-stamp',
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
    ...overrides,
  };
}

interface LoginAttemptRow {
  attempts: number;
  locked_until: number | null;
  updated_at: number;
}

interface FakeD1Options {
  usersByEmail?: Map<string, Record<string, unknown>>;
  knownDevices?: Map<string, Set<string>>; // userId -> device identifiers
  createdAuthRequests?: unknown[][];
}

// Minimal D1 emulation covering the SQL statements the handlers under test issue.
// Login-attempt and rate-limit tables are emulated faithfully enough to exercise
// counter semantics (increment, threshold lock, clear, cleanup).
function createFakeD1(options: FakeD1Options = {}): D1Database {
  const usersByEmail = options.usersByEmail ?? new Map();
  const knownDevices = options.knownDevices ?? new Map();
  const createdAuthRequests = options.createdAuthRequests ?? [];
  const loginTables = new Map<string, Map<string, LoginAttemptRow>>();
  const buckets = new Map<string, number>();

  const loginTable = (name: string): Map<string, LoginAttemptRow> => {
    let table = loginTables.get(name);
    if (!table) {
      table = new Map();
      loginTables.set(name, table);
    }
    return table;
  };

  const dispatch = (sql: string, values: unknown[], kind: 'first' | 'run' | 'all'): unknown => {
    if (/CREATE (TABLE|INDEX|UNIQUE INDEX)/i.test(sql)) {
      return kind === 'run' ? { meta: { changes: 0 } } : null;
    }
    if (/SELECT .+ FROM users WHERE email = \?/i.test(sql)) {
      if (kind !== 'first') return null;
      return usersByEmail.get(String(values[0])) ?? null;
    }
    if (/FROM devices WHERE user_id = \? AND device_identifier = \?/i.test(sql)) {
      if (kind !== 'first') return null;
      const known = knownDevices.get(String(values[0]))?.has(String(values[1]));
      return known ? { device_identifier: String(values[1]) } : null;
    }
    if (/INSERT INTO auth_requests/i.test(sql)) {
      createdAuthRequests.push(values);
      return { meta: { changes: 1 } };
    }
    if (/DELETE FROM auth_requests/i.test(sql)) {
      return { meta: { changes: 0 } };
    }
    if (/INSERT OR IGNORE INTO rate_limit_buckets/i.test(sql)) {
      const key = String(values[2]);
      if (!buckets.has(key)) buckets.set(key, 0);
      return { meta: { changes: 0 } };
    }
    if (/UPDATE rate_limit_buckets SET count = count \+ 1/i.test(sql)) {
      const key = String(values[2]);
      const max = Number(values[3]);
      const current = buckets.get(key) ?? 0;
      if (current >= max) return { meta: { changes: 0 } };
      buckets.set(key, current + 1);
      return { meta: { changes: 1 } };
    }
    if (/SELECT count FROM rate_limit_buckets/i.test(sql)) {
      if (kind !== 'first') return null;
      return { count: buckets.get(String(values[0])) ?? 0 };
    }
    const loginInsert = sql.match(/INSERT INTO (login_attempts_\w+)\(/i);
    if (loginInsert) {
      const table = loginTable(loginInsert[1]);
      const key = String(values[0]);
      const now = Number(values[1]);
      const existing = table.get(key);
      table.set(key, {
        attempts: (existing?.attempts ?? 0) + 1,
        locked_until: existing?.locked_until ?? null,
        updated_at: now,
      });
      return { meta: { changes: 1 } };
    }
    const loginLockUpdate = sql.match(/UPDATE (login_attempts_\w+) SET locked_until = \?, updated_at = \? WHERE/i);
    if (loginLockUpdate) {
      const table = loginTable(loginLockUpdate[1]);
      const key = String(values[2]);
      const existing = table.get(key);
      if (existing) {
        existing.locked_until = Number(values[0]);
        existing.updated_at = Number(values[1]);
      }
      return { meta: { changes: existing ? 1 : 0 } };
    }
    const loginSelect = sql.match(/SELECT attempts, locked_until FROM (login_attempts_\w+) WHERE \w+ = \?/i);
    if (loginSelect) {
      if (kind !== 'first') return null;
      const row = loginTable(loginSelect[1]).get(String(values[0]));
      return row ? { ...row } : null;
    }
    const attemptsSelect = sql.match(/SELECT attempts FROM (login_attempts_\w+) WHERE \w+ = \?/i);
    if (attemptsSelect) {
      if (kind !== 'first') return null;
      const row = loginTable(attemptsSelect[1]).get(String(values[0]));
      return row ? { attempts: row.attempts } : null;
    }
    const loginDeleteByKey = sql.match(/DELETE FROM (login_attempts_\w+) WHERE \w+ = \?\s*$/i);
    if (loginDeleteByKey) {
      loginTable(loginDeleteByKey[1]).delete(String(values[0]));
      return { meta: { changes: 1 } };
    }
    if (/DELETE FROM (login_attempts_\w+) WHERE updated_at < \?/i.test(sql)) {
      const table = loginTable(sql.match(/DELETE FROM (login_attempts_\w+)/i)![1]);
      const cutoff = Number(values[0]);
      const now = Number(values[1]);
      for (const [key, row] of table) {
        if (row.updated_at < cutoff && (row.locked_until === null || row.locked_until < now)) table.delete(key);
      }
      return { meta: { changes: 0 } };
    }
    if (/^\s*SELECT/i.test(sql)) {
      return null;
    }
    return { meta: { changes: 0 } };
  };

  return {
    prepare(sql: string) {
      const statement = {
        values: [] as unknown[],
        bind(...values: unknown[]) {
          statement.values = values;
          return statement;
        },
        async first<T = unknown>(): Promise<T | null> {
          return dispatch(sql, statement.values, 'first') as T | null;
        },
        async run(): Promise<D1Result> {
          return dispatch(sql, statement.values, 'run') as D1Result;
        },
        async all<T = unknown>(): Promise<D1Result<T>> {
          return { results: [] as unknown[] as T[] } as unknown as D1Result<T>;
        },
      };
      return statement;
    },
    async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
      const results: D1Result<T>[] = [];
      for (const statement of statements) {
        results.push(await statement.run() as D1Result<T>);
      }
      return results;
    },
  } as unknown as D1Database;
}

function createAuthRequestRequest(body: Record<string, unknown>, ip = '203.0.113.10'): Request {
  return new Request('https://nodewarden.test/api/auth-requests', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'CF-Connecting-IP': ip },
    body: JSON.stringify(body),
  });
}

function createEnv(db: D1Database): Env {
  return { DB: db } as unknown as Env;
}

test('M-1: rejects public auth-request creation for an unregistered device', async () => {
  const createdAuthRequests: unknown[][] = [];
  const db = createFakeD1({
    usersByEmail: new Map([[USER_EMAIL, userRow()]]),
    knownDevices: new Map(),
    createdAuthRequests,
  });

  const response = await handleCreateAuthRequest(
    createAuthRequestRequest({
      email: USER_EMAIL,
      publicKey: 'PUBLIC-KEY-TEXT',
      accessCode: 'access-code-123',
      deviceIdentifier: 'fresh-device-identifier',
      deviceName: 'Fresh Device',
      deviceType: '14',
      type: 0,
    }),
    createEnv(db)
  );

  assert.equal(response.status, 400);
  const body = await response.json() as { error_description?: string; ErrorModel?: { Message?: string } };
  assert.equal(body.ErrorModel?.Message ?? body.error_description, 'User or known device not found.');
  assert.equal(createdAuthRequests.length, 0);
});

test('M-1: still creates auth requests for registered devices', async () => {
  const createdAuthRequests: unknown[][] = [];
  const db = createFakeD1({
    usersByEmail: new Map([[USER_EMAIL, userRow()]]),
    knownDevices: new Map([[USER_ID, new Set(['known-device-identifier'])]]),
    createdAuthRequests,
  });

  const response = await handleCreateAuthRequest(
    createAuthRequestRequest({
      email: USER_EMAIL,
      publicKey: 'PUBLIC-KEY-TEXT',
      accessCode: 'access-code-123',
      deviceIdentifier: 'known-device-identifier',
      deviceName: 'Known Device',
      deviceType: '14',
      type: 0,
    }),
    createEnv(db)
  );

  assert.equal(response.status, 200);
  assert.equal(createdAuthRequests.length, 1);
  // INSERT bind order: id, user_id, organization_id, type, request_device_identifier, ...
  assert.equal(createdAuthRequests[0][1], USER_ID);
  assert.equal(createdAuthRequests[0][4], 'known-device-identifier');
});

test('M-1: unknown user and known user with unknown device are indistinguishable (anti-enumeration)', async () => {
  const unknownUserDb = createFakeD1({ usersByEmail: new Map() });
  const unknownDeviceDb = createFakeD1({
    usersByEmail: new Map([[USER_EMAIL, userRow()]]),
    knownDevices: new Map(),
  });

  const requestBody = {
    email: USER_EMAIL,
    publicKey: 'PUBLIC-KEY-TEXT',
    accessCode: 'access-code-123',
    deviceIdentifier: 'some-device-identifier',
    deviceName: 'Some Device',
    deviceType: '14',
    type: 0,
  };

  const unknownUserResponse = await handleCreateAuthRequest(createAuthRequestRequest(requestBody), createEnv(unknownUserDb));
  const unknownDeviceResponse = await handleCreateAuthRequest(createAuthRequestRequest(requestBody), createEnv(unknownDeviceDb));

  assert.equal(unknownUserResponse.status, 400);
  assert.equal(unknownDeviceResponse.status, 400);
  const unknownUserBody = await unknownUserResponse.json() as { error_description?: string; ErrorModel?: { Message?: string } };
  const unknownDeviceBody = await unknownDeviceResponse.json() as { error_description?: string; ErrorModel?: { Message?: string } };
  const unknownUserMessage = unknownUserBody.ErrorModel?.Message ?? unknownUserBody.error_description;
  const unknownDeviceMessage = unknownDeviceBody.ErrorModel?.Message ?? unknownDeviceBody.error_description;
  assert.equal(unknownUserMessage, unknownDeviceMessage);
});

// --- M-2: per-account (email) login lockout, independent of client IP ---

test('M-2: per-email counter locks at threshold, clears on success, and is isolated per key', async () => {
  const rateLimit = new RateLimitService(createFakeD1());
  const key = 'a'.repeat(64);

  for (let i = 0; i < LIMITS.rateLimit.loginMaxAttempts - 1; i++) {
    const result = await rateLimit.recordFailedLoginByEmail(key);
    assert.equal(result.locked, false);
  }
  const locked = await rateLimit.recordFailedLoginByEmail(key);
  assert.equal(locked.locked, true);
  assert.ok((locked.retryAfterSeconds ?? 0) > 0);
  assert.equal((await rateLimit.checkLoginAttemptByEmail(key)).allowed, false);
  // A different account key is unaffected.
  assert.equal((await rateLimit.checkLoginAttemptByEmail('b'.repeat(64))).allowed, true);

  await rateLimit.clearLoginAttemptsByEmail(key);
  const cleared = await rateLimit.checkLoginAttemptByEmail(key);
  assert.equal(cleared.allowed, true);
  assert.equal(cleared.remainingAttempts, LIMITS.rateLimit.loginMaxAttempts);
});

function createLoginRequest(email: string, ip: string): Request {
  return new Request('https://nodewarden.test/identity/connect/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip },
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      // Matches the BASE64_32_BYTES shape the server expects for a client KDF hash.
      password: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
      scope: 'api offline_access',
      client_id: 'web',
      deviceIdentifier: 'login-device-1',
      deviceName: 'Test Device',
      deviceType: '14',
    }).toString(),
  });
}

test('M-2: email lockout survives client IP rotation', async () => {
  const maxAttempts = LIMITS.rateLimit.loginMaxAttempts;
  const db = createFakeD1({ usersByEmail: new Map() }); // no users: every login fails
  const env = createEnv(db);

  // Spread failures across two IPs so neither IP counter reaches the lock threshold.
  const firstIp = '198.51.100.1';
  const secondIp = '198.51.100.2';
  for (let i = 0; i < maxAttempts; i++) {
    const ip = i < maxAttempts / 2 ? firstIp : secondIp;
    const response = await handleToken(createLoginRequest(USER_EMAIL, ip), env);
    assert.ok(response.status === 400 || response.status === 429, `attempt ${i} returned ${response.status}`);
  }

  // A third, never-seen IP must not bypass the per-email lockout.
  const rotatedIpResponse = await handleToken(createLoginRequest(USER_EMAIL, '198.51.100.3'), env);
  assert.equal(rotatedIpResponse.status, 429);
  const body = await rotatedIpResponse.json() as { error_description?: string; ErrorModel?: { Message?: string } };
  const message = body.ErrorModel?.Message ?? body.error_description ?? '';
  assert.match(message, /Too many failed login attempts/);
});

test('M-2: a different account is not locked out by another account\u2019s failures', async () => {
  const maxAttempts = LIMITS.rateLimit.loginMaxAttempts;
  const db = createFakeD1({ usersByEmail: new Map() });
  const env = createEnv(db);

  // Lock victim@example.test using failures split over two IPs.
  for (let i = 0; i < maxAttempts; i++) {
    const ip = i < maxAttempts / 2 ? '198.51.100.1' : '198.51.100.2';
    await handleToken(createLoginRequest(USER_EMAIL, ip), env);
  }

  // Same IP as earlier failures, but a different account: must not be locked.
  const otherAccountResponse = await handleToken(createLoginRequest('other@example.test', '198.51.100.1'), env);
  assert.equal(otherAccountResponse.status, 400);
  const body = await otherAccountResponse.json() as { error_description?: string; ErrorModel?: { Message?: string } };
  const message = body.ErrorModel?.Message ?? body.error_description ?? '';
  assert.match(message, /Username or password is incorrect/);
});

// --- H-1 (agreed compromise): TOTP secrets must not enter backup exports ---

test('H-1: backup export no longer selects users.totp_secret / totp_recovery_code', async () => {
  const preparedSql: string[] = [];
  const statement = {
    bindings: [] as unknown[],
    bind(...values: unknown[]) {
      statement.bindings = values;
      return statement;
    },
    async all() {
      return { results: [] };
    },
    async first() {
      return null;
    },
    async run() {
      return { meta: { changes: 0 } };
    },
  };
  const db = {
    prepare(sql: string) {
      preparedSql.push(sql);
      return statement;
    },
    async batch(statements: D1PreparedStatement[]) {
      for (const item of statements) await item.run();
      return [];
    },
  } as unknown as D1Database;

  await buildBackupArchive(createEnv(db), new Date(0), { includeAttachments: false });

  const usersSelect = preparedSql.find((sql) => /FROM users/i.test(sql));
  assert.ok(usersSelect, 'export did not query the users table');
  assert.doesNotMatch(usersSelect, /totp_secret|totp_recovery_code/);
});

// --- M-3: CSP hardening in webapp/index.html ---

test('M-3: script-src drops unsafe-inline and object-src is none', () => {
  const html = readFileSync(new URL('../webapp/index.html', import.meta.url), 'utf8');
  const match = html.match(/<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]+content="([\s\S]*?)"/i);
  assert.ok(match, 'CSP meta tag not found in webapp/index.html');
  const policy = match[1];

  const directive = (name: string): string | null => {
    const directiveMatch = policy.match(new RegExp(`${name}\\s+([^;]*);`));
    return directiveMatch ? directiveMatch[1].trim() : null;
  };

  const scriptSrc = directive('script-src');
  assert.ok(scriptSrc, 'script-src directive missing');
  assert.match(scriptSrc, /'self'/);
  assert.doesNotMatch(scriptSrc, /'unsafe-inline'/);

  assert.equal(directive('object-src'), "'none'");

  // The inline boot <style> in index.html still requires style-src unsafe-inline.
  const styleSrc = directive('style-src');
  assert.ok(styleSrc, 'style-src directive missing');
  assert.match(styleSrc, /'unsafe-inline'/);
});
