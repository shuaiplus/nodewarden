import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createTotpUserVerificationToken,
  handleGetTotpRecoveryCode,
  handlePutTwoFactorAuthenticator,
  handleSetTotpStatus,
  readTotpUserVerificationToken,
} from '../src/handlers/accounts';
import type { Env, User } from '../src/types';

const SECRET = 'test-jwt-secret-at-least-32-characters-long!';
const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const securityStamp = 'stamp-v1';
// Fixtures are low-entropy Base32 alphabet runs on purpose: they decode like real keys, but secret
// scanners can tell them apart from leaked credentials.
const OLD_KEY = 'ABCDEFGHIJKLMNOP';
const NEW_KEY = 'QRSTUVWXYZ234567QRSTUVWXYZ234567';
const OLD_RECOVERY = 'A'.repeat(32);

// --- Minimal RFC 4648 base32 + TOTP helpers (mirror src/utils/totp.ts) ---
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Uint8Array | null {
  const normalized = input.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of normalized) {
    const idx = BASE32.indexOf(char);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  return out.length > 0 ? new Uint8Array(out) : null;
}

async function generateTotpCode(secretBase32: string, nowMs: number = Date.now()): Promise<string> {
  const secret = base32Decode(secretBase32);
  if (!secret) throw new Error(`invalid test secret: ${secretBase32}`);
  const counter = Math.floor(nowMs / 1000 / 30);
  const counterBytes = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return (binary % 1_000_000).toString().padStart(6, '0');
}

function b64urlEncode(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(input: string): Uint8Array {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// --- Fakes ---
function makeUserRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: userId,
    email: 'user@example.test',
    name: 'Test User',
    master_password_hint: null,
    master_password_hash: 'legacy-hash',
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
    ...overrides,
  };
}

function makeTestEnv(userRow: Record<string, unknown>) {
  const runSqls: string[] = [];
  const db = {
    prepare(sql: string) {
      return {
        bind(..._args: unknown[]) {
          return this;
        },
        async first() {
          return userRow;
        },
        async all() {
          return { results: [] as unknown[] };
        },
        async run() {
          runSqls.push(sql);
          return { meta: { changes: 1 } };
        },
      };
    },
  } as unknown as D1Database;

  const env = { DB: db, JWT_SECRET: SECRET } as unknown as Env;
  return { env, runSqls };
}

function makeTokenUser(stamp: string): User {
  return { id: userId, email: 'user@example.test', securityStamp: stamp } as User;
}

function jsonRequest(path: string, body: Record<string, unknown>): Request {
  return new Request(`https://vault.example.test${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

// --- Token integrity tests ---
test('verification token round-trips via and a via-less token has no via', async () => {
  const { env } = makeTestEnv(makeUserRow());
  const user = makeTokenUser(securityStamp);

  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');
  const readTotp = await readTotpUserVerificationToken(env, user, viaTotp);
  assert.ok(readTotp);
  assert.equal(readTotp!.via, 'totp');

  const viaLess = await createTotpUserVerificationToken(env, user);
  const readLess = await readTotpUserVerificationToken(env, user, viaLess);
  assert.ok(readLess);
  assert.equal(readLess!.via, undefined);
});

test('tampering with via in the token invalidates the signature', async () => {
  const { env } = makeTestEnv(makeUserRow());
  const user = makeTokenUser(securityStamp);
  const token = await createTotpUserVerificationToken(env, user, 'totp');
  const [payloadB64, sigB64] = token.split('.');
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadB64))) as Record<string, unknown>;
  payload.via = 'recovery';
  const tampered = `${b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)))}.${sigB64}`;
  assert.equal(await readTotpUserVerificationToken(env, user, tampered), null);
});

test('verification token is invalid after a security-stamp change', async () => {
  const { env } = makeTestEnv(makeUserRow());
  const token = await createTotpUserVerificationToken(env, makeTokenUser('stamp-old'), 'totp');
  assert.equal(await readTotpUserVerificationToken(env, makeTokenUser('stamp-new'), token), null);
});

test('verification token is user-bound', async () => {
  const { env } = makeTestEnv(makeUserRow());
  const token = await createTotpUserVerificationToken(env, makeTokenUser(securityStamp), 'totp');
  const other = { id: 'other-user-id', email: 'x@example.test', securityStamp: securityStamp } as User;
  assert.equal(await readTotpUserVerificationToken(env, other, token), null);
});

// --- Handler: PUT /api/two-factor/authenticator ---
test('INITIAL ENABLE: master-password verification + valid new code succeeds', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow());
  const user = makeTokenUser(securityStamp);
  const viaLess = await createTotpUserVerificationToken(env, user);
  const code = await generateTotpCode(NEW_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: NEW_KEY,
    token: code,
    userVerificationToken: viaLess,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.ok(body.recoveryCode);
  assert.equal(body.recoveryCodeConsumed, false);
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('ROTATION WITHOUT STEP-UP IS REJECTED (critical regression)', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const user = makeTokenUser(securityStamp);
  const viaLess = await createTotpUserVerificationToken(env, user); // valid token, but no `via`
  const code = await generateTotpCode(NEW_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: NEW_KEY,
    token: code,
    userVerificationToken: viaLess,
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('ROTATION WITH CURRENT TOTP succeeds and leaves the recovery code unchanged', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const user = makeTokenUser(securityStamp);
  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');
  const code = await generateTotpCode(NEW_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: NEW_KEY,
    token: code,
    userVerificationToken: viaTotp,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(body.recoveryCode, undefined);
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('ROTATION WITH RECOVERY CODE succeeds and mints a new recovery code', async () => {
  const { env } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const user = makeTokenUser(securityStamp);
  const viaRecovery = await createTotpUserVerificationToken(env, user, 'recovery');
  const code = await generateTotpCode(NEW_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: NEW_KEY,
    token: code,
    userVerificationToken: viaRecovery,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(body.recoveryCodeConsumed, true);
  assert.ok(typeof body.recoveryCode === 'string' && body.recoveryCode !== OLD_RECOVERY);
});

test('FAILED NEW TOTP does not commit and leaves the old TOTP intact', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const user = makeTokenUser(securityStamp);
  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: NEW_KEY,
    token: '000000', // wrong code for NEW_KEY
    userVerificationToken: viaTotp,
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('SAME-SECRET + missing recovery code + via-less is REJECTED (critical regression)', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaLess = await createTotpUserVerificationToken(env, user);
  const code = await generateTotpCode(OLD_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: OLD_KEY,
    token: code,
    userVerificationToken: viaLess,
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('SAME-SECRET + missing recovery code + via=totp mints a recovery code', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');
  const code = await generateTotpCode(OLD_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: OLD_KEY,
    token: code,
    userVerificationToken: viaTotp,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(typeof body.recoveryCode, 'string');
  assert.equal(body.recoveryCodeConsumed, false);
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('SAME-SECRET + existing recovery code is unaffected (no mint, no change)', async () => {
  const { env } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const user = makeTokenUser(securityStamp);
  const viaLess = await createTotpUserVerificationToken(env, user);
  const code = await generateTotpCode(OLD_KEY);

  const res = await handlePutTwoFactorAuthenticator(jsonRequest('/api/two-factor/authenticator', {
    key: OLD_KEY,
    token: code,
    userVerificationToken: viaLess,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(body.recoveryCode, undefined);
});

// --- Handler: legacy PUT /api/accounts/totp ---
test('LEGACY API: master password alone cannot replace an existing TOTP', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));
  const code = await generateTotpCode(NEW_KEY);

  const res = await handleSetTotpStatus(jsonRequest('/api/accounts/totp', {
    enabled: true,
    secret: NEW_KEY,
    token: code,
    masterPasswordHash: 'legacy-hash', // matches stored legacy hash, but must NOT suffice for rotation
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('LEGACY API: first-time enable with master password still succeeds', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow());
  const code = await generateTotpCode(NEW_KEY);

  const res = await handleSetTotpStatus(jsonRequest('/api/accounts/totp', {
    enabled: true,
    secret: NEW_KEY,
    token: code,
    masterPasswordHash: 'legacy-hash',
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(body.enabled, true);
  assert.ok(body.recoveryCode);
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('LEGACY API: same-secret + missing recovery code + master-password-only is REJECTED', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const code = await generateTotpCode(OLD_KEY);

  const res = await handleSetTotpStatus(jsonRequest('/api/accounts/totp', {
    enabled: true,
    secret: OLD_KEY,
    token: code,
    masterPasswordHash: 'legacy-hash',
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('LEGACY API: same-secret + missing recovery code + via=totp mints a recovery code', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');
  const code = await generateTotpCode(OLD_KEY);

  const res = await handleSetTotpStatus(jsonRequest('/api/accounts/totp', {
    enabled: true,
    secret: OLD_KEY,
    token: code,
    userVerificationToken: viaTotp,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(typeof body.recoveryCode, 'string');
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

// --- Handler: POST /api/accounts/totp/recovery-code (also /api/two-factor/get-recover) ---
test('RECOVERY CODE: existing TOTP + missing RC + master-password-only is REJECTED', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('RECOVERY CODE: existing TOTP + missing RC + via-less token is REJECTED', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaLess = await createTotpUserVerificationToken(env, user); // valid token, but no `via`

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
    userVerificationToken: viaLess,
  }), env, userId);

  assert.equal(res.status, 400);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('RECOVERY CODE: existing TOTP + missing RC + via=totp mints a recovery code', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaTotp = await createTotpUserVerificationToken(env, user, 'totp');

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
    userVerificationToken: viaTotp,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(typeof body.code, 'string');
  assert.ok((body.code as string).length > 0);
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('RECOVERY CODE: existing TOTP + missing RC + via=recovery mints a recovery code', async () => {
  const { env } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: null }));
  const user = makeTokenUser(securityStamp);
  const viaRecovery = await createTotpUserVerificationToken(env, user, 'recovery');

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
    userVerificationToken: viaRecovery,
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(typeof body.code, 'string');
});

test('RECOVERY CODE: existing TOTP + existing RC returns it unchanged (no re-mint)', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow({ totp_secret: OLD_KEY, totp_recovery_code: OLD_RECOVERY }));

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(body.code, OLD_RECOVERY);
  assert.ok(!runSqls.some((s) => s.includes('INSERT INTO users')));
});

test('RECOVERY CODE: no TOTP + master-password-only still mints (initial setup unaffected)', async () => {
  const { env, runSqls } = makeTestEnv(makeUserRow());

  const res = await handleGetTotpRecoveryCode(jsonRequest('/api/accounts/totp/recovery-code', {
    masterPasswordHash: 'legacy-hash',
  }), env, userId);

  assert.equal(res.status, 200);
  const body = await res.json() as Record<string, unknown>;
  assert.equal(typeof body.code, 'string');
  assert.ok(runSqls.some((s) => s.includes('INSERT INTO users')));
});
