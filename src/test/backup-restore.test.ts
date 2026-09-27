import assert from 'node:assert/strict';
import test from 'node:test';
import { unzipSync, zipSync } from 'fflate';

import { buildBackupArchive } from '../services/backup-archive';
import { importBackupArchiveBytes } from '../services/backup-import';
import { createTestEnv, memoryKv, seedUser } from './support/env';

type Row = Record<string, unknown>;

// Restored tables with the key that orders their rows, for a stable row-by-row comparison.
const RESTORED_TABLES = {
  users: 'id',
  domain_settings: 'user_id',
  user_revisions: 'user_id',
  webauthn_credentials: 'id',
  folders: 'id',
  ciphers: 'id',
  attachments: 'id',
} as const;

const rowsOf = async (db: D1Database, table: string, orderBy: string) =>
  (await db.prepare(`SELECT * FROM ${table} ORDER BY ${orderBy}`).all<Row>()).results;
// Code-unit order, as SQLite's default BINARY collation sorts.
const byKey = (key: string) => (left: Row, right: Row) => (String(left[key]) < String(right[key]) ? -1 : 1);

test('backup restore brings back every archived value, fills legacy defaults and keeps runtime-only columns empty', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source, { apiKey: 'runtime-api-key', kdfMemory: 64, kdfParallelism: 4, totpSecret: 'totp', yubikeyKey1: 'yubikey', privateKey: 'private', publicKey: 'public' });
  const other = await seedUser(source, { emailVerified: false, verifyDevices: true, name: null, masterPasswordHint: 'hint' });
  const run = (query: string, ...values: unknown[]) => source.DB.prepare(query).bind(...values).run();
  await run('UPDATE users SET user_key_id = ? WHERE id = ?', 'runtime-key-id', owner.id);
  await run("INSERT INTO config (key, value) VALUES ('custom.setting', 'kept')");
  await run("INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES ('folder-1', ?, 'enc-folder', 'c1', 'u1')", owner.id);
  await run("INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, reprompt, key, created_at, updated_at, archived_at, deleted_at) VALUES ('cipher-1', ?, 1, 'folder-1', 'enc-name', NULL, 1, '{\"login\":{}}', 1, 'cipher-key', 'c2', 'u2', 'a2', NULL)", owner.id);
  await run("INSERT INTO ciphers (id, user_id, type, data, created_at, updated_at, deleted_at, organization_id) VALUES ('cipher-2', ?, 2, '{}', 'c3', 'u3', 'd3', 'org-1')", other.id);
  await run("INSERT INTO attachments (id, cipher_id, file_name, size, size_name, key) VALUES ('att-1', 'cipher-1', 'enc-file', 10, '10 Bytes', 'file-key'), ('att-2', 'cipher-1', 'enc-lost', 20, '20 Bytes', NULL)");
  await run("INSERT INTO domain_settings (user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at) VALUES (?, '[[\"a.com\",\"b.com\"]]', '[[\"c.com\"]]', '[1,2]', 'u4'), (?, '[]', '[]', '[]', 'u5')", owner.id, other.id);
  await run("INSERT INTO user_revisions (user_id, revision_date) VALUES (?, 'r1'), (?, 'r2')", owner.id, other.id);
  await run("INSERT INTO webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, type, aa_guid, transports, encrypted_user_key, encrypted_public_key, encrypted_private_key, supports_prf, created_at, updated_at) VALUES ('passkey-1', ?, 'twoFactor', 'Key', 'pk', 'credential-1', 5, 'public-key', 'guid', '[\"usb\"]', 'euk', 'epk', 'eprk', 1, 'c6', 'u6')", owner.id);
  await run("INSERT INTO webauthn_credentials (id, user_id, name, public_key, credential_id, created_at, updated_at) VALUES ('passkey-2', ?, 'Login', 'pk2', 'credential-2', 'c7', 'u7')", other.id);

  const archive = await buildBackupArchive(source, new Date(), { includeAttachments: true });
  const files = unzipSync(archive.bytes);
  const archived = JSON.parse(new TextDecoder().decode(files['db.json'])) as Record<string, Row[]>;
  // An archive from before custom equivalent domains existed lacks the column; restore falls back to its
  // default. Older archives may also still carry runtime-only columns, which restore must ignore.
  const legacy = structuredClone(archived);
  delete legacy.domain_settings.find((row) => row.user_id === owner.id)!.custom_equivalent_domains;
  Object.assign(legacy.users[0], { api_key: 'archived-api-key', user_key_id: 'archived-key-id' });
  Object.assign(legacy.ciphers[0], { organization_id: 'archived-org' });
  files['db.json'] = new TextEncoder().encode(JSON.stringify(legacy));

  const kv = memoryKv();
  const restored = await createTestEnv({ ATTACHMENTS_KV: kv.binding });
  // The remote source can still supply only one of the two attachment blobs.
  const outcome = await importBackupArchiveBytes(zipSync(files), restored, owner.id, false, {
    loadAttachment: async (blobName) => (blobName === 'cipher-1/att-1' ? new TextEncoder().encode('blob') : null),
  });
  assert.equal(outcome.result.imported.attachments, 1);
  assert.equal(outcome.result.skipped.attachments, 1);
  assert.deepEqual([...kv.values.keys()], ['cipher-1/att-1']);

  const expected: Record<string, Row[]> = {
    ...archived,
    domain_settings: archived.domain_settings.map((row) => (row.user_id === owner.id ? { ...row, custom_equivalent_domains: '[]' } : row)),
    attachments: archived.attachments.filter((row) => row.id === 'att-1'),
  };
  for (const [table, orderBy] of Object.entries(RESTORED_TABLES)) {
    const rows = await rowsOf(restored.DB, table, orderBy);
    const wanted = expected[table].toSorted(byKey(orderBy));
    assert.deepEqual(rows.map((row, index) => Object.fromEntries(Object.keys(wanted[index] ?? row).map((column) => [column, row[column]]))), wanted, table);
  }
  const users = await rowsOf(restored.DB, 'users', 'id');
  assert.ok(users.every((row) => row.api_key === null && row.user_key_id === null));
  assert.ok((await rowsOf(restored.DB, 'ciphers', 'id')).every((row) => row.organization_id === null));
  const config = new Map((await rowsOf(restored.DB, 'config', 'key')).map((row) => [row.key, row.value]));
  assert.equal(config.get('custom.setting'), 'kept');
  assert.equal(config.get('registered'), 'true');
});

test('backup restore rejects a row missing a required value outside the replace tables instead of defaulting it', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  await source.DB.prepare("INSERT INTO ciphers (id, user_id, type, favorite, data, created_at, updated_at) VALUES ('cipher-1', ?, 1, 1, '{}', 'c', 'u')").bind(owner.id).run();
  const files = unzipSync((await buildBackupArchive(source, new Date(), { includeAttachments: false })).bytes);
  const archived = JSON.parse(new TextDecoder().decode(files['db.json'])) as Record<string, Row[]>;
  delete archived.ciphers[0].favorite;
  files['db.json'] = new TextEncoder().encode(JSON.stringify(archived));

  const restored = await createTestEnv();
  await assert.rejects(importBackupArchiveBytes(zipSync(files), restored, owner.id, false), /NOT NULL constraint failed: ciphers__restore\.favorite/);
  assert.deepEqual(await rowsOf(restored.DB, 'users', 'id'), []);
});
