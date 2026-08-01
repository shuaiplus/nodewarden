import { handleGetApiKey, handleRotateApiKey } from '../src/handlers/accounts.ts';
import { hashApiKey, verifyApiKey } from '../src/utils/api-key.ts';

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function createUserRow(apiKey) {
  return {
    id: 'user-1',
    email: 'user@example.com',
    name: 'User',
    master_password_hint: null,
    master_password_hash: 'master-proof',
    key: 'wrapped-user-key',
    private_key: null,
    public_key: null,
    kdf_type: 0,
    kdf_iterations: 600000,
    kdf_memory: null,
    kdf_parallelism: null,
    security_stamp: 'security-stamp-original',
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
    api_key: apiKey,
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
  };
}

function createDb(apiKey) {
  const state = {
    user: createUserRow(apiKey),
    userWrites: 0,
    refreshDeletes: 0,
    auditActions: [],
  };
  const db = {
    prepare(sql) {
      let bindings = [];
      const statement = {
        bind(...values) {
          bindings = values;
          return statement;
        },
        async first() {
          if (/FROM users WHERE id = \?/i.test(sql)) return { ...state.user };
          return null;
        },
        async all() {
          return { results: [] };
        },
        async run() {
          if (/INSERT INTO users\(/i.test(sql)) {
            state.userWrites += 1;
            state.user.security_stamp = bindings[12];
            state.user.api_key = bindings[24];
            state.user.updated_at = bindings[26];
          }
          if (/DELETE FROM refresh_tokens/i.test(sql)) state.refreshDeletes += 1;
          if (/INSERT INTO audit_logs/i.test(sql)) state.auditActions.push(bindings[2]);
          return { meta: { changes: 1 } };
        },
      };
      return statement;
    },
    async batch(statements) {
      return statements.map(() => ({ success: true, meta: { changes: 1 } }));
    },
  };
  return { db, state };
}

function request() {
  return new Request('https://nodewarden.example/api/accounts/api-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash: 'master-proof' }),
  });
}

function env(db) {
  return { DB: db, JWT_SECRET: 'test-secret-at-least-thirty-two-characters' };
}

const view = createDb('ExistingReadableApiKey1234567');
const viewResponse = await handleGetApiKey(request(), env(view.db), 'user-1');
const viewBody = await viewResponse.json();
assert(viewResponse.status === 200, 'Viewing an existing readable API key failed');
assert(viewBody.apiKey === 'ExistingReadableApiKey1234567', 'View did not return the existing API key');
assert(view.state.userWrites === 0, 'View unexpectedly rewrote the user');
assert(view.state.refreshDeletes === 0, 'View unexpectedly revoked refresh tokens');
assert(view.state.auditActions.includes('account.api_key.view'), 'View audit action is missing');

const rotate = createDb('ExistingReadableApiKey1234567');
const rotateResponse = await handleRotateApiKey(request(), env(rotate.db), 'user-1');
const rotateBody = await rotateResponse.json();
assert(rotateResponse.status === 200, 'API key rotation failed');
assert(rotateBody.apiKey !== 'ExistingReadableApiKey1234567', 'Rotation returned the old API key');
assert(rotate.state.user.api_key === rotateBody.apiKey, 'Rotation did not persist the returned API key');
assert(rotate.state.user.security_stamp === 'security-stamp-original', 'Rotation changed securityStamp');
assert(rotate.state.refreshDeletes === 0, 'Rotation revoked unrelated refresh tokens');
assert(!(await verifyApiKey('ExistingReadableApiKey1234567', rotate.state.user.api_key)), 'Old API key still authenticates');
assert(await verifyApiKey(rotateBody.apiKey, rotate.state.user.api_key), 'Rotated API key does not authenticate');

const legacyPlain = 'LegacyHashedApiKey123456789';
const legacy = createDb(await hashApiKey(legacyPlain));
const legacyResponse = await handleGetApiKey(request(), env(legacy.db), 'user-1');
assert(legacyResponse.status === 409, 'Legacy hashed key view should require explicit rotation');
assert(legacy.state.userWrites === 0, 'Legacy hashed key was silently rotated');
assert(await verifyApiKey(legacyPlain, legacy.state.user.api_key), 'Legacy hashed API key stopped authenticating');

const missing = createDb(null);
const missingResponse = await handleGetApiKey(request(), env(missing.db), 'user-1');
const missingBody = await missingResponse.json();
assert(missingResponse.status === 200 && !!missingBody.apiKey, 'Missing legacy API key was not initialized');
assert(missing.state.userWrites === 1, 'Missing legacy API key initialization was not persisted');

console.log('Bitwarden-compatible API key view and rotation semantics: PASS');
