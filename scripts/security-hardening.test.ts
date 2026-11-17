import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { unzipSync, zipSync } from 'fflate';
import { bytesToBase64, decryptBw, decryptStr, encryptBw } from '../webapp/src/lib/crypto';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { ensureStorageSchema } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { AuthService } from '../src/services/auth';
import { handleCreateAuthRequest } from '../src/handlers/auth-requests';
import { handleToken } from '../src/handlers/identity';
import { handleChangePassword, handleGetPasswordHint, handleRotateApiKey } from '../src/handlers/accounts';
import { handleTrustDevicePermanently } from '../src/handlers/devices';
import {
  PUSH_INSTALLATION_ID_CONFIG_KEY,
  PUSH_INSTALLATION_KEY_CONFIG_KEY,
  buildBackupArchive,
  decryptBackupSecretRows,
  parseBackupArchive,
  verifyBackupPayloadIntegrity,
} from '../src/services/backup-archive';
import { importBackupArchiveBytes } from '../src/services/backup-import';
import {
  createAttachmentUploadToken,
  createFileDownloadToken,
  createJWT,
  createSendAccessToken,
  verifyAttachmentUploadToken,
  verifyFileDownloadToken,
  verifyJWT,
  verifySendAccessToken,
} from '../src/utils/jwt';
import { getClientIdentifier } from '../src/services/ratelimit';
import type { Env, User } from '../src/types';

const TEST_JWT_SECRET = '0123456789abcdef0123456789abcdef0123456789abcdef';

async function createSqliteEnv(ctx: TestContext, extraEnv: Partial<Env> = {}) {
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => {
    await new Promise((resolve) => setImmediate(resolve));
    sqlite.close();
  });

  sqlite.exec(`
    CREATE TABLE IF NOT EXISTS login_attempts_ip (
      ip TEXT PRIMARY KEY,
      attempts INTEGER NOT NULL,
      locked_until INTEGER,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS rate_limit_buckets (
      bucket_key TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  (AuthService as any).userCache?.clear?.();
  (AuthService as any).deviceCache?.clear?.();

  const db: D1Database = {
    prepare(sql: string) {
      let values: unknown[] = [];
      const stmt: any = {
        sql,
        bind(...bound: unknown[]) {
          values = bound.map((v) => (v === undefined ? null : v));
          return stmt;
        },
        async run() {
          const res = sqlite.prepare(sql).run(...(values as any[]));
          return { success: true, meta: { changes: Number(res.changes) } };
        },
        async all() {
          return { success: true, results: sqlite.prepare(sql).all(...(values as any[])) };
        },
        async first() {
          return sqlite.prepare(sql).get(...(values as any[])) ?? null;
        },
      };
      return stmt;
    },
    async batch(statements: D1PreparedStatement[]) {
      const out = [];
      for (const stmt of statements as any[]) {
        out.push(await stmt.run());
      }
      return out as any;
    },
  } as unknown as D1Database;

  await ensureStorageSchema(db);
  const env: Env = {
    DB: db,
    JWT_SECRET: TEST_JWT_SECRET,
    ...extraEnv,
  } as Env;
  const storage = new StorageService(db);
  const auth = new AuthService(env);
  return { sqlite, db, env, storage, auth };
}

async function seedTestUser(storage: StorageService, auth: AuthService, overrides: Partial<User> = {}): Promise<User> {
  const now = new Date().toISOString();
  const user: User = {
    id: overrides.id || '00000000-0000-4000-8000-000000000010',
    email: overrides.email || 'alice@example.com',
    name: overrides.name || 'Alice',
    masterPasswordHint: 'masterPasswordHint' in overrides ? (overrides.masterPasswordHint ?? null) : 'My secret pet name',
    masterPasswordHash: overrides.masterPasswordHash || (await auth.hashPasswordServer('client-password-hash-1')),
    key: overrides.key || '2.AAAAAAAAAAAAAAAAAAAAAA==|BBBBBBBBBBBBBBBBBBBBBB==|CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    privateKey: overrides.privateKey ?? null,
    publicKey: overrides.publicKey ?? 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
    kdfType: overrides.kdfType ?? 0,
    kdfIterations: overrides.kdfIterations ?? 600_000,
    kdfMemory: overrides.kdfMemory ?? null,
    kdfParallelism: overrides.kdfParallelism ?? null,
    securityStamp: overrides.securityStamp || 'sstamp-initial-1',
    role: overrides.role || 'admin',
    status: overrides.status || 'active',
    verifyDevices: overrides.verifyDevices ?? false,
    totpSecret: 'totpSecret' in overrides ? (overrides.totpSecret ?? null) : 'JBSWY3DPEHPK3PXP',
    totpRecoveryCode: 'totpRecoveryCode' in overrides ? (overrides.totpRecoveryCode ?? null) : 'ABCD1234EFGH5678IJKL9012MNOP3456',
    yubikeyKey1: null,
    yubikeyKey2: null,
    yubikeyKey3: null,
    yubikeyKey4: null,
    yubikeyKey5: null,
    yubikeyNfc: false,
    apiKey: 'apiKey' in overrides ? (overrides.apiKey ?? null) : 'InitialReadableApiKey0123456789',
    userKeyId: null,
    createdAt: now,
    updatedAt: now,
  };
  await storage.createUser(user);
  return user;
}

test('Web crypto strictly enforces EncType 2 with valid HMAC and blocks EncType 0 downgrade or plaintext fallback', async () => {
  const encKey = new Uint8Array(32).fill(7);
  const macKey = new Uint8Array(32).fill(11);
  const validCipher = await encryptBw(new TextEncoder().encode('super-secret-password'), encKey, macKey);

  assert.equal(await decryptStr(validCipher, encKey, macKey), 'super-secret-password');

  // Downgrade to EncType 0 (unauthenticated AES-CBC) by stripping MAC must fail
  const [, body] = validCipher.split('.');
  const [ivB64, ctB64, macB64] = body.split('|');
  const downgradedEncType0 = `0.${ivB64}|${ctB64}`;

  await assert.rejects(() => decryptBw(downgradedEncType0, encKey, macKey), /unsupported or unauthenticated enc type/);
  await assert.rejects(() => decryptStr(downgradedEncType0, encKey, macKey), /unsupported or unauthenticated enc type/);

  // Missing MAC Key must fail
  await assert.rejects(() => decryptBw(validCipher, encKey, undefined as unknown as Uint8Array), /Invalid symmetric MAC key/);

  // Tampered MAC must fail
  const tamperedMacBytes = Uint8Array.from(Buffer.from(macB64, 'base64'));
  tamperedMacBytes[0] ^= 0xff;
  const tamperedCipher = `2.${ivB64}|${ctB64}|${bytesToBase64(tamperedMacBytes)}`;
  await assert.rejects(() => decryptBw(tamperedCipher, encKey, macKey), /MAC mismatch/);

  // decryptSingleCipher must not leak raw cipherstring when decryption fails
  const dec = await decryptSingleCipher(
    {
      id: 'cipher-1',
      type: 1,
      name: tamperedCipher,
      notes: null,
      favorite: false,
      folderId: null,
      login: { username: validCipher, password: validCipher },
    } as any,
    encKey,
    macKey
  );
  assert.equal(dec.decName, '');
  assert.notEqual(dec.decName, tamperedCipher);
  assert.equal(dec.login?.decUsername, 'super-secret-password');
});

test('Auth-request creation requires an active known device and token exchange enforces device binding', async (ctx) => {
  const { env, storage, auth } = await createSqliteEnv(ctx);
  const user = await seedTestUser(storage, auth, { totpSecret: null });

  const makeCreateReq = (deviceIdentifier: string) =>
    new Request('https://vault.example.test/api/auth-requests', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': '203.0.113.10',
      },
      body: JSON.stringify({
        email: user.email,
        publicKey: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A',
        deviceIdentifier,
        accessCode: 'access-code-secret-12345',
        type: 0,
      }),
    });

  // Unknown device must be rejected
  const unknownResp = await handleCreateAuthRequest(makeCreateReq('unknown-device-id'), env);
  assert.equal(unknownResp.status, 400);

  // Register known active device
  await storage.upsertDevice(user.id, 'known-device-1', 'Phone', 0);

  const knownResp = await handleCreateAuthRequest(makeCreateReq('known-device-1'), env);
  assert.equal(knownResp.status, 200);
  const createdBody = (await knownResp.json()) as { id: string };

  // Approve the auth request
  await storage.updateAuthRequestResponse(createdBody.id, user.id, {
    approved: true,
    key: user.key,
    masterPasswordHash: null,
    responseDeviceIdentifier: 'approver-device',
    responseDate: new Date().toISOString(),
  });

  // Exchange from a DIFFERENT deviceIdentifier must fail
  const mismatchTokenReq = new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'CF-Connecting-IP': '203.0.113.10',
    },
    body: new URLSearchParams({
      grant_type: 'password',
      username: user.email,
      password: 'access-code-secret-12345',
      authRequest: createdBody.id,
      deviceIdentifier: 'attacker-other-device',
      deviceName: 'Attacker',
      deviceType: '9',
    }),
  });
  const mismatchResp = await handleToken(mismatchTokenReq, env);
  assert.equal(mismatchResp.status, 400);

  // Exchange from the original requesting device succeeds
  const validTokenReq = new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'CF-Connecting-IP': '203.0.113.10',
    },
    body: new URLSearchParams({
      grant_type: 'password',
      username: user.email,
      password: 'access-code-secret-12345',
      authRequest: createdBody.id,
      deviceIdentifier: 'known-device-1',
      deviceName: 'Phone',
      deviceType: '0',
    }),
  });
  const validResp = await handleToken(validTokenReq, env);
  assert.equal(validResp.status, 200);
});

test('Password hint endpoint hides hint by default and requires explicit SHOW_PASSWORD_HINT opt-in', async (ctx) => {
  const { env, storage, auth } = await createSqliteEnv(ctx);
  const user = await seedTestUser(storage, auth, { masterPasswordHint: 'TopSecretHint123' });

  const makeHintReq = (ip: string) =>
    new Request('https://vault.example.test/api/accounts/password-hint', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'CF-Connecting-IP': ip,
      },
      body: JSON.stringify({ email: user.email }),
    });

  const defaultResp = await handleGetPasswordHint(makeHintReq('198.51.100.25'), env);
  assert.equal(defaultResp.status, 200);
  const defaultBody = (await defaultResp.json()) as { hasHint: boolean; masterPasswordHint: string | null };
  assert.equal(defaultBody.hasHint, false);
  assert.equal(defaultBody.masterPasswordHint, null);

  const enabledResp = await handleGetPasswordHint(makeHintReq('198.51.100.26'), { ...env, SHOW_PASSWORD_HINT: '1' });
  assert.equal(enabledResp.status, 200);
  const enabledBody = (await enabledResp.json()) as { hasHint: boolean; masterPasswordHint: string | null };
  assert.equal(enabledBody.hasHint, true);
  assert.equal(enabledBody.masterPasswordHint, 'TopSecretHint123');
});

test('Client IP extraction ignores spoofed X-Forwarded-For / X-Real-IP on non-local hosts', () => {
  const spoofedProdReq = new Request('https://vault.example.test/identity/connect/token', {
    headers: {
      'X-Forwarded-For': '1.2.3.4',
      'X-Real-IP': '5.6.7.8',
    },
  });
  assert.equal(getClientIdentifier(spoofedProdReq), null);

  const cfReq = new Request('https://vault.example.test/identity/connect/token', {
    headers: {
      'CF-Connecting-IP': '203.0.113.99',
      'X-Forwarded-For': '1.2.3.4',
    },
  });
  assert.equal(getClientIdentifier(cfReq), 'ip4:203.0.113.99');
});

test('API key rotation revokes client_credentials access & refresh tokens without breaking password sessions, and blocks permanent 2FA device trust via API key', async (ctx) => {
  const { env, storage, auth } = await createSqliteEnv(ctx);
  const user = await seedTestUser(storage, auth);

  // Issue client_credentials tokens
  const ccReq = new Request('https://vault.example.test/identity/connect/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'CF-Connecting-IP': '203.0.113.50',
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: `user.${user.id}`,
      client_secret: user.apiKey!,
      scope: 'api',
      deviceIdentifier: 'cli-device-1',
      deviceName: 'CLI',
      deviceType: '25',
    }),
  });
  const ccResp = await handleToken(ccReq, env);
  assert.equal(ccResp.status, 200);
  const ccTokens = (await ccResp.json()) as { access_token: string; refresh_token: string };
  assert.ok(await auth.verifyAccessTokenWithUser(`Bearer ${ccTokens.access_token}`));

  // Issue normal password session tokens
  await storage.upsertDevice(user.id, 'web-device-1', 'Web', 9, 'pw-session-stamp-1');
  const passwordDevice = await storage.getDevice(user.id, 'web-device-1');
  assert.ok(passwordDevice);
  const pwAccessToken = await auth.generateAccessToken(user, {
    identifier: 'web-device-1',
    sessionStamp: passwordDevice.sessionStamp,
  });
  const pwRefreshToken = await auth.generateRefreshToken(
    user,
    { identifier: 'web-device-1', sessionStamp: passwordDevice.sessionStamp },
    'web'
  );

  // Permanent 2FA trust endpoint must reject API-key authenticated requests
  const trustViaApiKeyReq = new Request('https://vault.example.test/api/devices/cli-device-1/trust-forever', {
    method: 'POST',
    headers: { 'X-NodeWarden-Auth-Method': 'api_key' },
  });
  const trustViaApiKeyResp = await handleTrustDevicePermanently(trustViaApiKeyReq, env, user.id, 'cli-device-1');
  assert.equal(trustViaApiKeyResp.status, 403);

  // Rotate API key
  const rotateReq = new Request('https://vault.example.test/api/accounts/rotate-api-key', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ masterPasswordHash: 'client-password-hash-1' }),
  });
  const rotateResp = await handleRotateApiKey(rotateReq, env, user.id);
  assert.equal(rotateResp.status, 200);

  // Old client_credentials access & refresh tokens are immediately rejected
  assert.equal(await auth.verifyAccessTokenWithUser(`Bearer ${ccTokens.access_token}`), null);
  const ccRefreshResult = await auth.refreshAccessTokenDetailed(ccTokens.refresh_token);
  assert.equal(ccRefreshResult.ok, false);
  if (!ccRefreshResult.ok) {
    assert.equal(ccRefreshResult.reason, 'api_key_rotated');
  }

  // Normal password session tokens remain valid
  assert.ok(await auth.verifyAccessTokenWithUser(`Bearer ${pwAccessToken}`));
  const pwRefreshResult = await auth.refreshAccessTokenDetailed(pwRefreshToken);
  assert.equal(pwRefreshResult.ok, true);
});

test('Password change revokes remembered 2FA trusted device tokens', async (ctx) => {
  const { env, storage, auth } = await createSqliteEnv(ctx);
  const user = await seedTestUser(storage, auth);

  await storage.saveTrustedTwoFactorDeviceToken(
    'remember-2fa-token-1',
    user.id,
    'browser-device-1',
    Date.now() + 365 * 24 * 60 * 60 * 1000
  );
  assert.equal(
    await storage.getTrustedTwoFactorDeviceTokenUserId('remember-2fa-token-1', 'browser-device-1'),
    user.id
  );

  const changePwReq = new Request('https://vault.example.test/api/accounts/password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      masterPasswordHash: 'client-password-hash-1',
      newMasterPasswordHash: 'client-password-hash-2',
      key: '2.AAAAAAAAAAAAAAAAAAAAAA==|BBBBBBBBBBBBBBBBBBBBBB==|CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
    }),
  });
  const resp = await handleChangePassword(changePwReq, env, user.id);
  assert.equal(resp.status, 200);

  assert.equal(
    await storage.getTrustedTwoFactorDeviceTokenUserId('remember-2fa-token-1', 'browser-device-1'),
    null
  );
});

test('Backup export strips push installation secrets, encrypts TOTP/recovery/hint secrets, and verifies dbSha256 on restore', async (ctx) => {
  const sourceCtx = await createSqliteEnv(ctx);
  const user = await seedTestUser(sourceCtx.storage, sourceCtx.auth, {
    totpSecret: 'JBSWY3DPEHPK3PXP',
    totpRecoveryCode: 'RECOVERYCODE1234567890ABCDEF1234',
    masterPasswordHint: 'SensitiveHint999',
  });
  await sourceCtx.storage.setConfigValue(PUSH_INSTALLATION_ID_CONFIG_KEY, 'push-install-id');
  await sourceCtx.storage.setConfigValue(PUSH_INSTALLATION_KEY_CONFIG_KEY, 'push-install-secret-key');
  await sourceCtx.storage.setConfigValue('globalSettings__yubico__key', 'yubico-raw-secret');

  const archive = await buildBackupArchive(sourceCtx.env, new Date('2026-11-17T00:00:00.000Z'), {
    includeAttachments: false,
  });

  // Verify 12-hex-character SHA-256 prefix in filename
  assert.match(archive.fileName, /_[0-9a-f]{12}\.zip$/);

  const parsed = parseBackupArchive(archive.bytes);
  assert.ok(parsed.payload.manifest.dbSha256);

  // Push credentials must never appear in exported config
  const configKeys = parsed.payload.db.config.map((r) => r.key);
  assert.ok(!configKeys.includes(PUSH_INSTALLATION_ID_CONFIG_KEY));
  assert.ok(!configKeys.includes(PUSH_INSTALLATION_KEY_CONFIG_KEY));

  // Exported TOTP, recovery code, hint, and Yubico secret are encrypted with $nw-bkp-sec-v1$
  const exportedUser = parsed.payload.db.users[0];
  assert.match(String(exportedUser.totp_secret), /^\$nw-bkp-sec-v1\$/);
  assert.match(String(exportedUser.totp_recovery_code), /^\$nw-bkp-sec-v1\$/);
  assert.match(String(exportedUser.master_password_hint), /^\$nw-bkp-sec-v1\$/);
  const exportedYubico = parsed.payload.db.config.find((r) => r.key === 'globalSettings__yubico__key');
  assert.match(String(exportedYubico?.value), /^\$nw-bkp-sec-v1\$/);

  // Decryption helper recovers original secrets with matching key material
  const decrypted = await decryptBackupSecretRows(sourceCtx.env, {
    config: parsed.payload.db.config,
    users: parsed.payload.db.users,
  });
  assert.equal(decrypted.users[0].totp_secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(decrypted.users[0].totp_recovery_code, 'RECOVERYCODE1234567890ABCDEF1234');
  assert.equal(decrypted.users[0].master_password_hint, 'SensitiveHint999');

  // Restore into a fresh target instance succeeds and restores plaintext secrets in D1
  const targetCtx = await createSqliteEnv(ctx);
  await importBackupArchiveBytes(archive.bytes, targetCtx.env, user.id, false);
  const restoredUser = await targetCtx.storage.getUserById(user.id);
  assert.equal(restoredUser?.totpSecret, 'JBSWY3DPEHPK3PXP');
  assert.equal(restoredUser?.totpRecoveryCode, 'RECOVERYCODE1234567890ABCDEF1234');
  assert.equal(restoredUser?.masterPasswordHint, 'SensitiveHint999');

  // Tampering with db.json inside the archive must fail dbSha256 verification
  const rawZip = unzipSync(archive.bytes);
  const tamperedDbJson = JSON.parse(new TextDecoder().decode(rawZip['db.json']));
  tamperedDbJson.users[0].role = 'user';
  const tamperedArchive = zipSync({
    'manifest.json': rawZip['manifest.json'],
    'db.json': new TextEncoder().encode(JSON.stringify(tamperedDbJson)),
  });
  const parsedTampered = parseBackupArchive(tamperedArchive);
  await assert.rejects(
    () => verifyBackupPayloadIntegrity(parsedTampered.payload, parsedTampered.files),
    /db\.json integrity check failed/
  );
  const targetCtx2 = await createSqliteEnv(ctx);
  await assert.rejects(
    () => importBackupArchiveBytes(tamperedArchive, targetCtx2.env, user.id, false),
    /db\.json integrity check failed/
  );
});

test('JWT purpose separation prevents cross-context token confusion across access, attachment, and Send tokens', async () => {
  const accessToken = await createJWT(
    {
      sub: 'user-123',
      email: 'user@example.com',
      name: 'User',
      sstamp: 'sstamp-123',
    },
    TEST_JWT_SECRET
  );
  const fileDownloadToken = await createFileDownloadToken('cipher-1', 'att-1', TEST_JWT_SECRET);
  const attachmentUploadToken = await createAttachmentUploadToken('user-123', 'cipher-1', 'att-1', TEST_JWT_SECRET);
  const sendAccessToken = await createSendAccessToken('send-123', TEST_JWT_SECRET);

  // Each token verifies in its intended verifier
  assert.ok(await verifyJWT(accessToken, TEST_JWT_SECRET));
  assert.ok(await verifyFileDownloadToken(fileDownloadToken, TEST_JWT_SECRET));
  assert.ok(await verifyAttachmentUploadToken(attachmentUploadToken, TEST_JWT_SECRET));
  assert.ok(await verifySendAccessToken(sendAccessToken, TEST_JWT_SECRET));

  // Cross-purpose verification must fail
  assert.equal(await verifyJWT(fileDownloadToken, TEST_JWT_SECRET), null);
  assert.equal(await verifyJWT(attachmentUploadToken, TEST_JWT_SECRET), null);
  assert.equal(await verifyJWT(sendAccessToken, TEST_JWT_SECRET), null);
  assert.equal(await verifyFileDownloadToken(accessToken, TEST_JWT_SECRET), null);
  assert.equal(await verifyAttachmentUploadToken(accessToken, TEST_JWT_SECRET), null);
  assert.equal(await verifySendAccessToken(accessToken, TEST_JWT_SECRET), null);
});
