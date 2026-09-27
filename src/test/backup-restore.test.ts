import assert from 'node:assert/strict';
import test from 'node:test';
import { eq, getColumns, getTableName } from 'drizzle-orm';
import type { SQLiteColumn, SQLiteTable } from 'drizzle-orm/sqlite-core';
import { unzipSync, zipSync } from 'fflate';

import { getOrm } from '../db/client';
import { attachments, ciphers, config, domainSettings, folders, userRevisions, users, webauthnCredentials } from '../db/schema';
import { unmapped } from '../db/sql';
import { buildBackupArchive } from '../services/backup-archive';
import { importBackupArchiveBytes } from '../services/backup-import';
import { createTestEnv, memoryKv, seedUser } from './support/env';

type Row = Record<string, unknown>;

// Restored tables with the key that orders their rows, for a stable row-by-row comparison.
const RESTORED_TABLES = [
  [users, users.id],
  [domainSettings, domainSettings.userId],
  [userRevisions, userRevisions.userId],
  [webauthnCredentials, webauthnCredentials.id],
  [folders, folders.id],
  [ciphers, ciphers.id],
  [attachments, attachments.id],
] as const;

// Stored values keyed by SQL column name, the shape of the archive's rows.
const rowsOf = (db: D1Database, table: SQLiteTable, orderBy: SQLiteColumn) =>
  getOrm(db).select(Object.fromEntries(Object.values(getColumns(table)).map((column) => [column.name, unmapped(column)]))).from(table).orderBy(orderBy);
// Code-unit order, as SQLite's default BINARY collation sorts.
const byKey = (key: string) => (left: Row, right: Row) => (String(left[key]) < String(right[key]) ? -1 : 1);

test('backup restore brings back every archived value, fills legacy defaults and keeps runtime-only columns empty', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source, { apiKey: 'runtime-api-key', kdfMemory: 64, kdfParallelism: 4, totpSecret: 'totp', yubikeyKey1: 'yubikey', privateKey: 'private', publicKey: 'public' });
  const other = await seedUser(source, { emailVerified: false, verifyDevices: true, name: null, masterPasswordHint: 'hint' });
  const orm = getOrm(source.DB);
  await orm.update(users).set({ userKeyId: 'runtime-key-id' }).where(eq(users.id, owner.id));
  await orm.insert(config).values({ key: 'custom.setting', value: 'kept' });
  await orm.insert(folders).values({ id: 'folder-1', userId: owner.id, name: 'enc-folder', createdAt: 'c1', updatedAt: 'u1' });
  await orm.insert(ciphers).values({ id: 'cipher-1', userId: owner.id, type: 1, folderId: 'folder-1', name: 'enc-name', notes: null, favorite: 1, data: '{"login":{}}', reprompt: 1, key: 'cipher-key', createdAt: 'c2', updatedAt: 'u2', archivedAt: 'a2', deletedAt: null });
  await orm.insert(ciphers).values({ id: 'cipher-2', userId: other.id, type: 2, data: '{}', createdAt: 'c3', updatedAt: 'u3', deletedAt: 'd3', organizationId: 'org-1' });
  await orm.insert(attachments).values([
    { id: 'att-1', cipherId: 'cipher-1', fileName: 'enc-file', size: 10, sizeName: '10 Bytes', key: 'file-key' },
    { id: 'att-2', cipherId: 'cipher-1', fileName: 'enc-lost', size: 20, sizeName: '20 Bytes', key: null },
  ]);
  await orm.insert(domainSettings).values([
    { userId: owner.id, equivalentDomains: '[["a.com","b.com"]]', customEquivalentDomains: '[["c.com"]]', excludedGlobalEquivalentDomains: '[1,2]', updatedAt: 'u4' },
    { userId: other.id, equivalentDomains: '[]', customEquivalentDomains: '[]', excludedGlobalEquivalentDomains: '[]', updatedAt: 'u5' },
  ]);
  await orm.insert(userRevisions).values([{ userId: owner.id, revisionDate: 'r1' }, { userId: other.id, revisionDate: 'r2' }]);
  await orm.insert(webauthnCredentials).values({
    id: 'passkey-1', userId: owner.id, purpose: 'twoFactor', name: 'Key', publicKey: 'pk', credentialId: 'credential-1', counter: 5, type: 'public-key', aaGuid: 'guid',
    transports: '["usb"]', encryptedUserKey: 'euk', encryptedPublicKey: 'epk', encryptedPrivateKey: 'eprk', supportsPrf: 1, createdAt: 'c6', updatedAt: 'u6',
  });
  await orm.insert(webauthnCredentials).values({ id: 'passkey-2', userId: other.id, name: 'Login', publicKey: 'pk2', credentialId: 'credential-2', createdAt: 'c7', updatedAt: 'u7' });

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
  for (const [table, orderBy] of RESTORED_TABLES) {
    const name = getTableName(table);
    const rows = await rowsOf(restored.DB, table, orderBy);
    const wanted = expected[name].toSorted(byKey(orderBy.name));
    assert.deepEqual(rows.map((row, index) => Object.fromEntries(Object.keys(wanted[index] ?? row).map((column) => [column, row[column]]))), wanted, name);
  }
  const userRows = await rowsOf(restored.DB, users, users.id);
  assert.ok(userRows.every((row) => row.api_key === null && row.user_key_id === null));
  assert.ok((await rowsOf(restored.DB, ciphers, ciphers.id)).every((row) => row.organization_id === null));
  const settings = new Map((await rowsOf(restored.DB, config, config.key)).map((row) => [row.key, row.value]));
  assert.equal(settings.get('custom.setting'), 'kept');
  assert.equal(settings.get('registered'), 'true');
});

test('backup restore rejects a row missing a required value outside the replace tables instead of defaulting it', async () => {
  const source = await createTestEnv();
  const owner = await seedUser(source);
  await getOrm(source.DB).insert(ciphers).values({ id: 'cipher-1', userId: owner.id, type: 1, favorite: 1, data: '{}', createdAt: 'c', updatedAt: 'u' });
  const files = unzipSync((await buildBackupArchive(source, new Date(), { includeAttachments: false })).bytes);
  const archived = JSON.parse(new TextDecoder().decode(files['db.json'])) as Record<string, Row[]>;
  delete archived.ciphers[0].favorite;
  files['db.json'] = new TextEncoder().encode(JSON.stringify(archived));

  const restored = await createTestEnv();
  await assert.rejects(importBackupArchiveBytes(zipSync(files), restored, owner.id, false), /NOT NULL constraint failed: ciphers__restore\.favorite/);
  assert.deepEqual(await rowsOf(restored.DB, users, users.id), []);
});
