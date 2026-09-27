import assert from 'node:assert/strict';
import { test } from 'node:test';
import { zipSync } from 'fflate';

import { parseBackupArchive } from './backup-archive';

const tables = { config: [], users: [], user_revisions: [], folders: [], ciphers: [], attachments: [] };

function archive(manifest: unknown, db: unknown): Uint8Array {
  const encoder = new TextEncoder();
  return zipSync({
    'manifest.json': encoder.encode(JSON.stringify(manifest)),
    'db.json': encoder.encode(JSON.stringify(db)),
  });
}

test('parseBackupArchive keeps only allowlisted tables and defaults the optional ones', () => {
  const { payload } = parseBackupArchive(archive({ formatVersion: 1 }, { ...tables, devices: [{ id: 'd1' }] }));
  assert.deepEqual(payload.db, { ...tables, domain_settings: [], webauthn_credentials: [] });
  assert.deepEqual(payload.manifest.attachmentBlobs, []);
});

test('parseBackupArchive names the first malformed table or manifest field', () => {
  const cases: Array<[unknown, unknown, string]> = [
    [{ formatVersion: 2 }, tables, 'Unsupported backup format version'],
    [null, tables, 'Unsupported backup format version'],
    [{ formatVersion: 1 }, [], 'Backup archive database payload is invalid'],
    [{ formatVersion: 1 }, { ...tables, users: {} }, 'Backup archive table users is invalid'],
    [
      { formatVersion: 1 },
      { ...tables, ciphers: [{ data: { nested: true } }] },
      'Backup archive table ciphers is invalid',
    ],
    [{ formatVersion: 1, attachmentBlobs: [{ cipherId: 'c1' }] }, tables, 'Backup archive manifest is invalid'],
  ];
  for (const [manifest, db, message] of cases) {
    assert.throws(() => parseBackupArchive(archive(manifest, db)), { message });
  }
});
