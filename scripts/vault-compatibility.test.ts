import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { StorageService } from '../src/services/storage';
import { handleAuthenticatedRoute } from '../src/router-authenticated';
import { cipherToResponse } from '../src/handlers/ciphers';
import { bytesToBase64, encryptBw, decryptStr } from '../webapp/src/lib/crypto';
import { decryptSingleCipher } from '../webapp/src/lib/decrypt-cipher';
import { updateCipher, buildCipherImportPayload, repairCipherKeyMismatches } from '../webapp/src/lib/api/vault';
import { importCipherToDraft } from '../webapp/src/lib/app-support';
import { draftFromCipher } from '../webapp/src/components/vault/vault-page-helpers';
import { t as translate } from '../webapp/src/lib/i18n';

const owner = '00000000-0000-4000-8000-000000000001';
const otherOwner = '00000000-0000-4000-8000-000000000002';
const id = '00000000-0000-4000-8000-000000000003';
const otherId = '00000000-0000-4000-8000-000000000004';
const attachmentId = '00000000-0000-4000-8000-000000000005';
const revision = '2026-10-04T00:00:00.000Z';
const enc = new Uint8Array(32).fill(1);
const mac = new Uint8Array(32).fill(2);
const session: any = { symEncKey: bytesToBase64(enc), symMacKey: bytesToBase64(mac) };
const encrypt = (value: string) => encryptBw(new TextEncoder().encode(value), enc, mac);

async function fixture(ctx: TestContext) {
  // Execute production SQL in a fresh in-memory SQLite database. Only the D1
  // result wrapper and unrelated audit/notification integrations are substituted.
  const sqlite = new DatabaseSync(':memory:');
  ctx.after(async () => { await new Promise((resolve) => setImmediate(resolve)); sqlite.close(); });
  sqlite.exec(`
    CREATE TABLE ciphers(id TEXT PRIMARY KEY, user_id TEXT, type INTEGER,
      folder_id TEXT, name TEXT, notes TEXT, favorite INTEGER, data TEXT,
      reprompt INTEGER, key TEXT, created_at TEXT, updated_at TEXT,
      archived_at TEXT, deleted_at TEXT);
    CREATE TABLE attachments(id TEXT PRIMARY KEY, cipher_id TEXT,
      file_name TEXT, size INTEGER, size_name TEXT, key TEXT);
    CREATE TABLE devices(user_id TEXT, push_token TEXT);
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
  };
  ctx.mock.method(StorageService.prototype, 'updateRevisionDate', async () => revision);
  ctx.mock.method(StorageService.prototype, 'createAuditLog', async () => {});
  ctx.mock.method(StorageService.prototype, 'getConfigValue', async () => null);
  ctx.mock.method(StorageService.prototype, 'pruneAuditLogs', async () => {});
  const deletedBlobs: string[] = [];
  const notifications: any[] = [];
  const env: any = {
    DB: db,
    ATTACHMENTS: { delete: async (key: string) => { deletedBlobs.push(key); } },
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => name,
      get: () => ({ fetch: async (_url: string, init: RequestInit) => { notifications.push(JSON.parse(init.body as string)); return new Response(null, { status: 204 }); } }),
    },
  };
  const storage = new StorageService(db);
  const base: any = {
    id, userId: owner, type: 1, name: await encrypt('Initial title'),
    notes: await encrypt('Notes'), favorite: false, folderId: null, key: null,
    login: { username: await encrypt('Username'), password: await encrypt('Password') },
    createdAt: revision, updatedAt: revision, deletedAt: null,
  };
  await storage.saveCipher(base);
  await storage.saveCipher({ ...base, id: otherId, userId: otherOwner });
  const route = async (path: string, method: string, body?: unknown, headers: Record<string, string> = {}) => {
    const request = new Request(`https://vault.example.test${path}`, {
      method, headers: { 'Content-Type': 'application/json', ...headers },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const response = await handleAuthenticatedRoute(request, env, owner, { id: owner } as any, path, method);
    assert.ok(response, `${method} ${path} must be handled`);
    return response;
  };
  const attachment = { id: attachmentId, cipherId: id, fileName: await encrypt('file.txt'), key: null, size: 7, sizeName: '7 B' };
  return { storage, base, env, sqlite, route, deletedBlobs, notifications, attachment };
}

for (const method of ['PUT', 'POST']) {
  test(`${method} bulk soft delete and restore retain ownership and return restored items`, async (ctx) => {
    const f = await fixture(ctx);
    await f.storage.saveAttachment(f.attachment);
    const ids = [id, otherId, id, '00000000-0000-4000-8000-000000000099'];
    assert.equal((await f.route('/api/ciphers/delete', method, { ids })).status, 204);
    assert.ok((await f.storage.getCipherForUser(id, owner))?.deletedAt);
    assert.equal((await f.storage.getCipherForUser(otherId, otherOwner))?.deletedAt, null);
    const response = await f.route('/api/ciphers/restore', method, { ids });
    assert.equal(response.status, 200);
    const body: any = await response.json();
    assert.equal(body.object, 'list');
    assert.equal(body.continuationToken, null);
    assert.equal(body.data.length, 1);
    assert.equal(body.data[0].id, id);
    assert.equal(body.data[0].deletedDate, null);
    assert.equal(body.data[0].attachments[0].id, attachmentId);
    assert.deepEqual(f.deletedBlobs, []);
    const empty: any = await (await f.route('/api/ciphers/restore', method, { ids: [] })).json();
    assert.deepEqual(empty.data, []);
  });
}

for (const [path, method] of [['/api/ciphers', 'DELETE'], ['/api/ciphers/delete-permanent', 'POST']]) {
  test(`${method} ${path} permanently deletes only owned items and their attachments`, async (ctx) => {
    const f = await fixture(ctx);
    await f.storage.saveAttachment(f.attachment);
    await f.storage.saveAttachment({ ...f.attachment, id: otherId, cipherId: otherId });
    assert.equal((await f.route(path, method, { ids: [id, otherId, id] })).status, 204);
    assert.equal(await f.storage.getCipherForUser(id, owner), null);
    assert.ok(await f.storage.getCipherForUser(otherId, otherOwner));
    assert.equal(await f.storage.getAttachment(attachmentId), null);
    assert.ok(await f.storage.getAttachment(otherId));
    assert.deepEqual(f.deletedBlobs, [`${id}/${attachmentId}`]);
  });
}

test('single POST delete alias is permanent; existing root DELETE still moves an active item to trash', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${id}`, 'DELETE')).status, 200);
  assert.ok((await f.storage.getCipherForUser(id, owner))?.deletedAt);
  assert.equal((await f.route(`/api/ciphers/${id}/delete`, 'POST')).status, 204);
  assert.equal(await f.storage.getCipherForUser(id, owner), null);
  assert.equal((await f.route(`/api/ciphers/${otherId}/delete`, 'POST')).status, 404);
});

test('invalid bulk requests are rejected without changing vault items', async (ctx) => {
  const f = await fixture(ctx);
  for (const [path, method] of [['/api/ciphers', 'DELETE'], ['/api/ciphers/delete', 'PUT'], ['/api/ciphers/restore', 'PUT']]) {
    assert.equal((await f.route(path, method, {})).status, 400);
    assert.equal((await f.route(path, method, { ids: 'invalid' })).status, 400);
  }
  assert.deepEqual(await f.storage.getCipherForUser(id, owner), await f.storage.getCipher(id));
  assert.equal((await f.storage.getCipherForUser(id, owner))?.deletedAt, null);
});

test('stale updates less than a second apart cannot bypass checks with attachment metadata', async (ctx) => {
  const f = await fixture(ctx);
  await f.storage.saveAttachment(f.attachment);
  await f.storage.saveCipher({ ...f.base, updatedAt: '2026-10-04T00:00:00.001Z' });
  const response = await f.route(`/api/ciphers/${id}`, 'PUT', {
    name: await encrypt('Stale title'), lastKnownRevisionDate: revision,
    attachments2: { [attachmentId]: { fileName: await encrypt('Stale file') } },
  });
  assert.equal(response.status, 400);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.name, f.base.name);
  assert.equal((await f.storage.getAttachment(attachmentId))?.fileName, f.attachment.fileName);
  assert.equal(f.notifications.length, 0);
});

test('a write conflict detected after reading leaves attachment metadata untouched', async (ctx) => {
  const f = await fixture(ctx);
  await f.storage.saveAttachment(f.attachment);
  const update = StorageService.prototype.updateCipherIfUnchanged;
  ctx.mock.method(StorageService.prototype, 'updateCipherIfUnchanged', async function (this: StorageService, cipher: any, expected: string) {
    await f.storage.saveCipher({ ...f.base, updatedAt: '2026-10-04T00:00:01.000Z' });
    return update.call(this, cipher, expected);
  });
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', {
    name: await encrypt('Stale title'), lastKnownRevisionDate: revision,
    attachments2: { [attachmentId]: { fileName: await encrypt('Stale file') } },
  })).status, 400);
  assert.equal((await f.storage.getAttachment(attachmentId))?.fileName, f.attachment.fileName);
  assert.equal(f.notifications.length, 0);
});

test('concurrent saves from the same revision accept only one, even in the same millisecond', async (ctx) => {
  const f = await fixture(ctx);
  ctx.mock.method(Date, 'now', () => Date.parse(revision));
  const response = await Promise.all(['First title', 'Second title'].map(async (title) =>
    f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt(title), lastKnownRevisionDate: revision })
  ));
  assert.deepEqual(response.map((r) => r.status).sort(), [200, 400]);
  assert.equal((await f.storage.getCipherForUser(id, owner))?.updatedAt, '2026-10-04T00:00:00.001Z');
});

test('a competing deletion cannot be resurrected by a delayed update', async (ctx) => {
  const f = await fixture(ctx);
  const get = StorageService.prototype.getCipherForUser;
  ctx.mock.method(StorageService.prototype, 'getCipherForUser', async function (this: StorageService, ...args: [string, string]) {
    const result = await get.apply(this, args);
    await f.storage.deleteCipher(id, owner);
    return result;
  });
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt('Delayed title') })).status, 400);
  assert.equal(await f.storage.getCipher(id), null);
});

test('normal legacy saves without a revision still work and nullable fields can be cleared', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal((await f.route(`/api/ciphers/${id}`, 'PUT', { name: await encrypt('Legacy title'), notes: null, fields: [] })).status, 200);
  const saved = await f.storage.getCipherForUser(id, owner);
  assert.equal(saved?.notes, null);
  assert.deepEqual(saved?.fields, []);
});

test('storage conditional updates cannot change another owner or recreate missing items', async (ctx) => {
  const f = await fixture(ctx);
  assert.equal(await f.storage.updateCipherIfUnchanged({ ...f.base, userId: otherOwner }, revision), false);
  await f.storage.deleteCipher(id, owner);
  assert.equal(await f.storage.updateCipherIfUnchanged(f.base, revision), false);
  assert.equal(await f.storage.getCipher(id), null);
});

test('Web editing preserves linked IDs and field metadata through reorder, removal, encryption, storage and response', async (ctx) => {
  const f = await fixture(ctx);
  const extra = await encrypt('Future encrypted field');
  const cipher = {
    ...f.base,
    fields: [
      { type: 3, name: await encrypt('Linked username'), value: null, linkedId: 100, futureValue: extra },
      { type: 0, name: await encrypt('Remove me'), value: await encrypt('Remove value') },
      { type: 1, name: await encrypt('Keep me'), value: await encrypt('Secret'), futureValue: extra },
    ],
  };
  await f.storage.saveCipher(cipher);
  const decrypted = await decryptSingleCipher(cipherToResponse(cipher) as any, enc, mac);
  const draft = draftFromCipher(decrypted);
  draft.customFields = [draft.customFields[2], draft.customFields[0]];
  draft.name = 'Edited title';
  const updated = await updateCipher((path, init) => f.route(path, init!.method!, JSON.parse(init!.body as string)), session, decrypted, draft);
  assert.equal(updated.fields?.length, 2);
  assert.equal('lastKnownRevisionDate' in updated, false);
  assert.equal(updated.fields?.[1].linkedId, 100);
  for (const field of updated.fields || []) {
    assert.equal((field as any).futureValue, extra);
    assert.equal('decName' in field, false);
    assert.equal('decValue' in field, false);
  }
  const roundtrip = await decryptSingleCipher(updated, enc, mac);
  assert.equal(roundtrip.decName, 'Edited title');
  assert.equal(roundtrip.fields?.[0].decValue, 'Secret');
  assert.equal((await f.storage.getCipherForUser(id, owner))?.fields?.[1].linkedId, 100);
});

for (const [type, property] of [[3, 'card'], [4, 'identity'], [2, 'secureNote']] as const) {
  test(`Web editing ${property} keeps unknown encrypted values without sending decoded properties`, async (ctx) => {
    const f = await fixture(ctx);
    const extra = await encrypt('Future secret');
    const source = { ...f.base, type, login: null, [property]: { futureEncrypted: extra, decFutureEncrypted: 'Decoded secret', type: 0 } };
    await f.storage.saveCipher(source);
    const decrypted = await decryptSingleCipher(cipherToResponse(source) as any, enc, mac);
    const draft = draftFromCipher(decrypted);
    draft.name = 'Changed';
    let payload: any;
    const updated = await updateCipher((path, init) => { payload = JSON.parse(init!.body as string); return f.route(path, init!.method!, payload); }, session, decrypted, draft);
    assert.equal(payload[property].futureEncrypted, extra);
    assert.equal('decFutureEncrypted' in payload[property], false);
    assert.equal((updated as any)[property].futureEncrypted, extra);
  });
}

test('Web sends the revision captured at edit start and exposes a localized conflict while preserving the draft', async (ctx) => {
  const f = await fixture(ctx);
  const initial = await decryptSingleCipher(cipherToResponse(f.base) as any, enc, mac);
  const draft = draftFromCipher(initial);
  draft.name = 'Unsaved edit';
  const newer = { ...f.base, name: await encrypt('New remote title'), updatedAt: '2026-10-04T00:00:00.500Z' };
  await f.storage.saveCipher(newer);
  const synced = await decryptSingleCipher(cipherToResponse(newer) as any, enc, mac);
  let submitted: any;
  await assert.rejects(updateCipher((path, init) => {
    submitted = JSON.parse(init!.body as string);
    return f.route(path, init!.method!, submitted);
  }, session, synced, draft), (error: any) => {
    assert.equal(error.status, 400);
    assert.equal(error.message, translate('txt_item_changed_elsewhere'));
    return true;
  });
  assert.equal(submitted.lastKnownRevisionDate, revision);
  assert.equal(draft.name, 'Unsaved edit');
  assert.equal((await f.storage.getCipherForUser(id, owner))?.name, newer.name);
});

test('plaintext import keeps linked field IDs attached to the encrypted field', async () => {
  const draft = importCipherToDraft({ type: 1, name: 'Imported', fields: [{ type: 3, name: 'Linked', value: null, linkedId: 100 }] }, '');
  assert.equal(draft.customFields[0].linkedId, 100);
  const payload: any = await buildCipherImportPayload(session, draft);
  assert.equal(payload.fields[0].linkedId, 100);
  assert.equal(await decryptStr(payload.fields[0].name, enc, mac), 'Linked');
  assert.equal('lastKnownRevisionDate' in payload, false);
});

test('a draft cannot be saved into a different item after the selection changes', async (ctx) => {
  const f = await fixture(ctx);
  const cipher = await decryptSingleCipher(cipherToResponse(f.base) as any, enc, mac);
  const draft = draftFromCipher(cipher);
  let requested = false;
  await assert.rejects(updateCipher(async () => { requested = true; return new Response(); }, session, { ...cipher, id: otherId }, draft));
  assert.equal(requested, false);
});

test('automatic item-key repair preserves linked metadata and the intentional revision-date behavior', async (ctx) => {
  const f = await fixture(ctx);
  const itemEnc = new Uint8Array(32).fill(3);
  const itemMac = new Uint8Array(32).fill(4);
  const itemKey = new Uint8Array([...itemEnc, ...itemMac]);
  const extra = await encryptBw(new TextEncoder().encode('Future secret'), itemEnc, itemMac);
  const mixed = { ...f.base, key: await encryptBw(itemKey, enc, mac), fields: [
    { type: 3, name: await encrypt('Linked username'), value: null, linkedId: 100, futureEncrypted: extra },
  ] };
  await f.storage.saveCipher(mixed);
  const decrypted = await decryptSingleCipher(cipherToResponse(mixed) as any, enc, mac);
  const repaired = await repairCipherKeyMismatches((path, init) =>
    f.route(path, init!.method!, JSON.parse(init!.body as string), init!.headers as Record<string, string>), session, [decrypted]);
  assert.equal(repaired, 1);
  const saved = (await f.storage.getCipherForUser(id, owner))!;
  assert.equal(saved.updatedAt, revision);
  assert.equal(saved.fields?.[0].linkedId, 100);
  assert.equal((saved.fields?.[0] as any).futureEncrypted, extra);
  assert.equal(await decryptStr(saved.name, itemEnc, itemMac), 'Initial title');
  assert.equal(await decryptStr(saved.fields![0].name!, itemEnc, itemMac), 'Linked username');
  assert.equal('lastKnownRevisionDate' in saved, false);
});
