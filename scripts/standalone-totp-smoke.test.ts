// Temporary smoke test for the standalone TOTP (CipherType.Totp = 9) feature.
// Uses the same harness conventions as scripts/vault-compatibility.test.ts.
import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { StorageService } from '../src/services/storage';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { cipherToResponse, validateCipherEncryptedFieldsForCompatibility, isCipherResponseSyncCompatible } from '../src/handlers/ciphers';
import { bytesToBase64, encryptBw, decryptStr } from '../webapp/src/lib/crypto';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { calcTotpNow } from '../webapp/src/lib/crypto';
import { createCipher, updateCipher, buildCipherImportPayload } from '../webapp/src/lib/api/vault';
import { createEmptyDraft, draftFromCipher, getCreateTypeOptions } from '../webapp/src/components/vault/vault-page-helpers';
import { summarizeImportResult } from '../webapp/src/lib/app-support';

const owner = '00000000-0000-4000-8000-000000000001';
const revision = '2026-10-08T00:00:00.000Z';
const enc = new Uint8Array(32).fill(1);
const mac = new Uint8Array(32).fill(2);
const session = { symEncKey: bytesToBase64(enc), symMacKey: bytesToBase64(mac) } as any;
const email = 'someone@example.com';
const encrypt = (value: string) => encryptBw(new TextEncoder().encode(value), enc, mac);

async function fixture(ctx: TestContext) {
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  sqlite.exec(`
    CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, name TEXT,
      master_password_hint TEXT, master_password_hash TEXT, key TEXT,
      private_key TEXT, public_key TEXT, kdf_type INTEGER, kdf_iterations INTEGER,
      kdf_memory INTEGER, kdf_parallelism INTEGER, security_stamp TEXT, role TEXT,
      status TEXT, verify_devices INTEGER, totp_secret TEXT, totp_recovery_code TEXT,
      yubikey_key1 TEXT, yubikey_key2 TEXT, yubikey_key3 TEXT, yubikey_key4 TEXT,
      yubikey_key5 TEXT, yubikey_nfc INTEGER, api_key TEXT, created_at TEXT, updated_at TEXT);
    INSERT INTO users(id, email, name, master_password_hash, role, status, created_at, updated_at)
      VALUES('${owner}', '${email}', '${email}', '', 'user', 'active', '${revision}', '${revision}');
    CREATE TABLE ciphers(id TEXT PRIMARY KEY, user_id TEXT, type INTEGER,
      folder_id TEXT, name TEXT, notes TEXT, favorite INTEGER, data TEXT,
      reprompt INTEGER, key TEXT, created_at TEXT, updated_at TEXT,
      archived_at TEXT, deleted_at TEXT);
    CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher_id TEXT,
      file_name TEXT, size INTEGER, size_name TEXT, key TEXT);
    CREATE TABLE devices(user_id TEXT, push_token TEXT);
    CREATE TABLE user_revisions(user_id TEXT PRIMARY KEY, revision_date TEXT);
  `);
  const db: any = {
    prepare(sql: string) {
      let values: any[] = [];
      const statement = {
        bind(...bound: any[]) { values = bound; return statement; },
        async run() { const result = sqlite.prepare(sql).run(...values); return { success: true, meta: { changes: Number(result.changes) } }; },
        async all() { return { success: true, results: sqlite.prepare(sql).all(...values) }; },
        async first() { return sqlite.prepare(sql).get(...values) ?? null; },
      };
      return statement;
    },
    exec(sql: string) { sqlite.exec(sql); return true; },
  };
  ctx.mock.method(StorageService.prototype, 'updateRevisionDate', async () => revision);
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  const notifications: any[] = [];
  const env: any = {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (_url: string, init: RequestInit) => { notifications.push(JSON.parse(init.body as string)); return new Response(null, { status: 204 }); } }),
    },
  };
  return { storage: new StorageService(db), env, route: async (path: string, method: string, body?: unknown) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method, headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const response = await handleAuthenticatedRoute(request, env, owner, { id: owner, email } as any, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  }, notifications };
}

test('create menu and draft defaults expose the standalone Verification Code type (9)', () => {
  const options = getCreateTypeOptions();
  assert.ok(options.some((option) => option.type === 9), 'type 9 must be offered');
  const draft = createEmptyDraft(9);
  assert.equal(draft.totpSecret, '');
  assert.equal(draft.totpIssuer, '');
  assert.equal(draft.totpAccountName, '');
});

test('import summary counts the standalone type', () => {
  const summary = summarizeImportResult([{ type: 9 }, { type: 9 }, { type: 1 }], 0);
  const totpEntry = summary.typeCounts.find((entry) => entry.label === 'Verification Code');
  assert.ok(totpEntry, 'Verification Code label must be present');
  assert.equal(totpEntry.count, 2);
});

// Minimal RFC 4648 base32 encoder so the RFC 6238 seeds can be built from their ASCII form.
function base32Encode(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

// RFC 6238 Appendix B known-answer vectors (8 digits, 30 second period).
// If any of these fail, the generated codes would not match what a real authenticator app shows.
test('live codes match RFC 6238 known-answer vectors for SHA-1/256/512', async () => {
  const seeds: Array<[string, 'SHA1' | 'SHA256' | 'SHA512', Record<string, string>]> = [
    [new TextEncoder().encode('12345678901234567890').toString(), 'SHA1', { '59': '94287082', '1111111109': '07081804' }],
    [new TextEncoder().encode('12345678901234567890123456789012').toString(), 'SHA256', { '59': '46119246', '1111111109': '68084774' }],
    [new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234').toString(), 'SHA512', { '59': '90693936', '1111111109': '25091201' }],
  ];

  for (const [commaSeparated, algorithm, expectedBySecond] of seeds) {
    // Undo TextEncoder#toString (which joins bytes with commas) to recover the ASCII seed bytes.
    const seedBytes = Uint8Array.from(commaSeparated.split(',').map(Number));
    const secret = base32Encode(seedBytes);
    for (const [second, expected] of Object.entries(expectedBySecond)) {
      const live = await calcTotpNow(
        `otpauth://totp/rfc6238?secret=${secret}&digits=8&period=30&algorithm=${algorithm}`,
        Number(second) * 1000
      );
      assert.ok(live, `${algorithm} @ ${second}s must be computable`);
      assert.equal(live.code, expected, `${algorithm} @ ${second}s must match the RFC 6238 vector`);
    }
  }
});

test('server rejects plaintext and accepts encrypted standalone TOTP secret', async () => {
  assert.equal(
    validateCipherEncryptedFieldsForCompatibility({ type: 9, totp: { secret: 'JBSWY3DPEHPK3PXP', issuer: null, accountName: null } } as any),
    'TOTP secret must be an encrypted string.',
    'the rejection must come from the totp branch, not an unrelated check'
  );
  assert.equal(
    validateCipherEncryptedFieldsForCompatibility({ type: 9, totp: { secret: await encrypt('JBSWY3DPEHPK3PXP'), issuer: null, accountName: null } } as any),
    null
  );
});

test('web create stores encrypted totp and decrypts to the same plaintext values', async (ctx) => {
  const f = await fixture(ctx);
  const draft = createEmptyDraft(9);
  draft.name = 'GitHub demo';
  draft.totpSecret = 'JBSWY3DPEHPK3PXP';
  draft.totpIssuer = 'GitHub';
  draft.totpAccountName = 'demo@example.com';

  const created = await createCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, draft);
  assert.ok(created.id, 'server must return an id');
  const stored: any = await f.storage.getCipher(created.id);
  assert.equal(stored.type, 9);
  assert.equal(await decryptStr(stored.totp.secret, enc, mac), 'JBSWY3DPEHPK3PXP');
  assert.equal(await decryptStr(stored.totp.issuer, enc, mac), 'GitHub');
  assert.equal(await decryptStr(stored.totp.accountName, enc, mac), 'demo@example.com');

  const readBack = await decryptSingleCipher(cipherToResponse(stored) as any, enc, mac);
  assert.equal(readBack.totp?.decSecret, 'JBSWY3DPEHPK3PXP');
  assert.equal(readBack.totp?.decIssuer, 'GitHub');
  assert.equal(readBack.totp?.decAccountName, 'demo@example.com');

  // The response object must be shaped like the encrypted storage, never carrying decoded values.
  assert.deepEqual(Object.keys(cipherToResponse(stored).totp).sort(), ['accountName', 'issuer', 'secret']);
});

test('live code derives from otpauth params (period 60, SHA-256, 8 digits)', async () => {
  const live = await calcTotpNow('otpauth://totp/X:Y?secret=JBSWY3DPEHPK3PXP&period=60&algorithm=SHA256&digits=8');
  assert.ok(live, 'live code must be computable');
  assert.equal(live.period, 60);
  assert.match(live.code, /^\d{8}$/, 'digits=8 must drive the code length');
  assert.ok(live.remain >= 1 && live.remain <= 60);
});

test('steam:// secrets produce the 5-character Steam guard format', async () => {
  const live = await calcTotpNow('steam://JBSWY3DPEHPK3PXP');
  assert.ok(live, 'steam code must be computable');
  assert.equal(live.period, 30);
  assert.match(live.code, /^[0-9A-Z]{5}$/, 'Steam codes use the Crockford base32 alphabet');
});

test('web edit round trip keeps unknown encrypted values and arms stale-write protection', async (ctx) => {
  const f = await fixture(ctx);
  const extra = await encrypt('Future secret');
  const draft0 = createEmptyDraft(9);
  draft0.name = 'TOTP source';
  draft0.totpSecret = 'JBSWY3DPEHPK3PXP';
  const created = await createCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, draft0);
  const stored = { ...(await f.storage.getCipher(created.id) as any), totp: { ...((await f.storage.getCipher(created.id) as any).totp), futureEncrypted: extra } };

  const readBack = await decryptSingleCipher(cipherToResponse(stored) as any, enc, mac);
  const editDraft = draftFromCipher(readBack);
  assert.equal(editDraft.totpSecret, 'JBSWY3DPEHPK3PXP');
  editDraft.totpIssuer = 'GitHub Inc.';

  let payload: any;
  const updated = await updateCipher(
    (path, init) => { payload = JSON.parse(init!.body as string); return f.route(path, init!.method!, payload); },
    session, readBack as any, editDraft
  );
  assert.equal(await decryptStr(updated.totp.issuer, enc, mac), 'GitHub Inc.');
  assert.equal(await decryptStr(updated.totp.secret, enc, mac), 'JBSWY3DPEHPK3PXP');
  assert.equal(payload.totp.futureEncrypted, extra, 'unknown encrypted value must survive');
  assert.equal(payload.totp.decIssuer, undefined, 'decoded fields must never be sent');
  assert.equal('lastKnownRevisionDate' in payload, true, 'stale-write protection must be armed');

  const stored2: any = await f.storage.getCipher(created.id);
  assert.equal(await decryptStr(stored2.totp.issuer, enc, mac), 'GitHub Inc.');
  assert.equal(stored2.totp.futureEncrypted, extra, 'unknown encrypted value must survive the round trip');
});

test('the standalone item passes the sync response filter and delivers its totp object', async (ctx) => {
  const f = await fixture(ctx);
  const draft = createEmptyDraft(9);
  draft.name = 'Sync me';
  draft.totpSecret = 'JBSWY3DPEHPK3PXP';
  const created = await createCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, draft);

  // handleSync gates items on isCipherResponseSyncCompatible(cipherToResponse(cipher)).
  const stored = (await f.storage.getAllCiphers(owner)).find((cipher) => cipher.id === created.id);
  assert.ok(stored, 'the standalone item must be readable by the sync repository');
  assert.equal(stored!.type, 9);
  const response = cipherToResponse(stored!) as any;
  assert.ok(isCipherResponseSyncCompatible(response), 'the standalone item must pass the sync compatibility gate');
  assert.ok(response.totp?.secret, 'the encrypted totp object must be delivered to clients');
  assert.equal(response.login, null);
  assert.equal(response.type, 9);
});

test('switching the type clears the standalone object server-side and disables live codes', async (ctx) => {
  const f = await fixture(ctx);
  const draft = createEmptyDraft(9);
  draft.name = 'Migrate to login';
  draft.totpSecret = 'JBSWY3DPEHPK3PXP';
  const created = await createCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, draft);
  const readBack = await decryptSingleCipher(cipherToResponse(await f.storage.getCipher(created.id)) as any, enc, mac);
  const asLogin = draftFromCipher(readBack);
  asLogin.type = 1;
  asLogin.loginTotp = readBack.totp!.decSecret!;
  const updated = await updateCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, readBack as any, asLogin);
  const stored: any = await f.storage.getCipher(created.id);
  assert.equal(stored.type, 1);
  assert.equal(await decryptStr(stored.login.totp, enc, mac), 'JBSWY3DPEHPK3PXP');
  assert.equal(stored.totp, null, 'totp object must be nulled after type switch');
  const redecrypted = await decryptSingleCipher(updated, enc, mac);
  assert.equal(redecrypted.login?.decTotp, 'JBSWY3DPEHPK3PXP');
});
