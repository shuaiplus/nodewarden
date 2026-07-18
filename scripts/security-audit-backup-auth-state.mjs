import { unzipSync, zipSync } from 'fflate';
import {
  buildBackupArchive,
  parseBackupArchive,
  validateBackupPayloadContents,
} from '../src/services/backup-archive.ts';
import { importBackupArchiveBytes } from '../src/services/backup-import.ts';

const forbiddenRuntimeTables = [
  'devices',
  'refresh_tokens',
  'auth_requests',
  'trusted_two_factor_device_tokens',
  'account_passkey_challenges',
  'used_attachment_download_tokens',
];

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function sqlTouchesTable(sql, table) {
  return new RegExp(`\\b(?:from|into|table)\\s+[\"']?${table}\\b`, 'i').test(sql);
}

function emptyBackupDb(extra = {}) {
  return {
    config: [],
    users: [],
    domain_settings: [],
    user_revisions: [],
    folders: [],
    ciphers: [],
    attachments: [],
    webauthn_credentials: [],
    ...extra,
  };
}

function archiveBytes(db, tableCounts = {}) {
  const encoder = new TextEncoder();
  return zipSync({
    'manifest.json': encoder.encode(JSON.stringify({
      formatVersion: 1,
      exportedAt: new Date(0).toISOString(),
      appVersion: 'test',
      storageKind: null,
      tableCounts,
      includes: { attachments: false },
      blobSummary: { attachmentFiles: 0, totalBytes: 0, largestObjectBytes: 0 },
      attachmentBlobs: [],
    })),
    'db.json': encoder.encode(JSON.stringify(db)),
  }, { level: 0 });
}

function createD1Mock({ exportMode = false } = {}) {
  const preparedSql = [];
  const db = {
    prepare(sql) {
      preparedSql.push(sql);
      let bindings = [];
      const statement = {
        sql,
        bind(...values) {
          bindings = values;
          return statement;
        },
        async all() {
          if (exportMode) return { results: [] };
          return { results: [] };
        },
        async first() {
          if (/SELECT sql FROM sqlite_master/i.test(sql)) {
            const table = String(bindings[0] || '').trim();
            return { sql: `CREATE TABLE ${table} (id TEXT)` };
          }
          if (/SELECT COUNT\(\*\).*FROM config__restore/i.test(sql)) return { count: 1 };
          if (/SELECT COUNT\(\*\)/i.test(sql)) return { count: 0 };
          return null;
        },
        async run() {
          return { meta: { changes: 0 } };
        },
      };
      return statement;
    },
    async batch(statements) {
      return statements.map(() => ({ success: true, meta: { changes: 0 } }));
    },
  };
  return { db, preparedSql };
}

const exportMock = createD1Mock({ exportMode: true });
const exported = await buildBackupArchive({ DB: exportMock.db }, new Date(0), { includeAttachments: false });
const exportedZip = unzipSync(exported.bytes);
const exportedManifest = JSON.parse(new TextDecoder().decode(exportedZip['manifest.json']));
const exportedDb = JSON.parse(new TextDecoder().decode(exportedZip['db.json']));

for (const table of forbiddenRuntimeTables) {
  assert(!(table in exportedDb), `Export contains forbidden runtime table: ${table}`);
  assert(!(table in exportedManifest.tableCounts), `Manifest counts forbidden runtime table: ${table}`);
  assert(!exportMock.preparedSql.some((sql) => sqlTouchesTable(sql, table)), `Export queried forbidden runtime table: ${table}`);
}

const legacyDb = emptyBackupDb({
  devices: [{ device_identifier: 'device-secret' }],
  refresh_tokens: [{ token: 'refresh-secret' }],
  auth_requests: [{ access_code: 'approval-secret' }],
  trusted_two_factor_device_tokens: [{ token: 'remember-secret' }],
  account_passkey_challenges: [{ challenge_hash: 'challenge-secret' }],
  used_attachment_download_tokens: [{ token_hash: 'download-secret' }],
});
const legacyArchive = archiveBytes(legacyDb, {
  devices: 1,
  refresh_tokens: 1,
  auth_requests: 1,
  trusted_two_factor_device_tokens: 1,
  account_passkey_challenges: 1,
  used_attachment_download_tokens: 1,
});
const parsedLegacy = parseBackupArchive(legacyArchive);
validateBackupPayloadContents(parsedLegacy.payload, parsedLegacy.files);
for (const table of forbiddenRuntimeTables) {
  assert(!(table in parsedLegacy.payload.db), `Legacy runtime table was not ignored: ${table}`);
}

const restoreMock = createD1Mock();
await importBackupArchiveBytes(legacyArchive, { DB: restoreMock.db }, 'actor', false);
for (const table of forbiddenRuntimeTables) {
  assert(
    !restoreMock.preparedSql.some((sql) => sqlTouchesTable(sql, table)),
    `Restore touched forbidden runtime table: ${table}`
  );
}

console.log('backup runtime authentication state exclusion: PASS');
