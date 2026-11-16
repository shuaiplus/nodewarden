// Fixture-based tests for instance-backup restore of organization data
// (audit finding cand:backup-restore-loses-org-data).
//
// The finding had two failure modes:
// 1. Cipher-row validation rejected every organization cipher (stored with a
//    null user_id), so restoring any archive containing an org cipher failed.
// 2. The parse allowlist silently dropped all six organization tables, so an
//    org-structure backup could "restore successfully" while erasing
//    organizations, memberships, wrapped org keys, and collections.
//
// These tests run the real restore pipeline (parse → validate → shadow-table
// import → swap) against a real SQLite database carrying the production
// schema, plus parse/validate checks on mutated archives.
import assert from 'node:assert/strict';
import test from 'node:test';
import { zipSync, strToU8 } from 'fflate';
import { DatabaseSync } from 'node:sqlite';

const { parseBackupArchive, validateBackupPayloadContents } = await import('../src/services/backup-archive');
const { importBackupArchiveBytes } = await import('../src/services/backup-import');

// ─── Fixtures ───────────────────────────────────────────────────────────────

type SqlRow = Record<string, string | number | null>;

const USER_A = '11111111-1111-4111-8111-111111111111';
const USER_B = '22222222-2222-4222-8222-222222222222';
const FOLDER_A = '33333333-3333-4333-8333-333333333333';
const ORG_ID = '44444444-4444-4444-8444-444444444444';
const ORG_USER_CONFIRMED = '55555555-5555-4555-8555-555555555555';
const ORG_USER_INVITED = '66666666-6666-4666-8666-666666666666';
const COLLECTION_ID = '77777777-7777-4777-8777-777777777777';
const CIPHER_PERSONAL = '88888888-8888-4888-8888-888888888888';
const CIPHER_ORG = '99999999-9999-4999-8999-999999999999';
const NOW = '2026-10-04T00:00:00.000Z';

function baseDb(): Record<string, SqlRow[]> {
  return {
    config: [],
    users: [
      {
        id: USER_A,
        email: 'a@example.com',
        name: 'User A',
        master_password_hash: 'hash-a',
        key: 'user-key-a',
        kdf_type: 0,
        kdf_iterations: 600000,
        security_stamp: 'stamp-a',
        role: 'user',
        status: 'active',
        created_at: NOW,
        updated_at: NOW,
      },
      {
        id: USER_B,
        email: 'b@example.com',
        name: 'User B',
        master_password_hash: 'hash-b',
        key: 'user-key-b',
        kdf_type: 0,
        kdf_iterations: 600000,
        security_stamp: 'stamp-b',
        role: 'user',
        status: 'active',
        created_at: NOW,
        updated_at: NOW,
      },
    ],
    domain_settings: [],
    user_revisions: [
      { user_id: USER_A, revision_date: NOW },
      { user_id: USER_B, revision_date: NOW },
    ],
    folders: [
      { id: FOLDER_A, user_id: USER_A, name: 'folder-a', created_at: NOW, updated_at: NOW },
    ],
    ciphers: [
      {
        id: CIPHER_PERSONAL,
        user_id: USER_A,
        organization_id: null,
        type: 1,
        folder_id: FOLDER_A,
        name: 'personal-login',
        favorite: 0,
        data: '2.aXZpdml2aXZpdml2|ZGF0YWRhdGFkYXRh|bWFjbWFjbWFjbWFj',
        created_at: NOW,
        updated_at: NOW,
        archived_at: null,
        deleted_at: null,
      },
      {
        id: CIPHER_ORG,
        user_id: null,
        organization_id: ORG_ID,
        type: 1,
        folder_id: null,
        name: 'shared-login',
        favorite: 0,
        data: '4.aXZpdml2aXZpdml2|ZGF0YWRhdGFkYXRh|bWFjbWFjbWFjbWFj',
        created_at: NOW,
        updated_at: NOW,
        archived_at: null,
        deleted_at: null,
      },
    ],
    attachments: [],
    webauthn_credentials: [],
    organizations: [
      {
        id: ORG_ID,
        name: 'Acme Corp',
        private_key: '4.org-private-key',
        public_key: 'org-public-key',
        billing_email: 'billing@example.com',
        creation_date: NOW,
        revision_date: NOW,
      },
    ],
    organization_users: [
      {
        id: ORG_USER_CONFIRMED,
        organization_id: ORG_ID,
        user_id: USER_B,
        email: 'b@example.com',
        key: 'wrapped-org-key-for-b',
        status: 2,
        type: 0,
        access_all: 1,
        creation_date: NOW,
        revision_date: NOW,
      },
      {
        id: ORG_USER_INVITED,
        organization_id: ORG_ID,
        user_id: null,
        email: 'invited@example.com',
        key: null,
        status: 0,
        type: 2,
        access_all: 0,
        creation_date: NOW,
        revision_date: NOW,
      },
    ],
    cipher_user_folders: [
      {
        cipher_id: CIPHER_ORG,
        user_id: USER_A,
        folder_id: FOLDER_A,
        created_at: NOW,
        updated_at: NOW,
      },
    ],
    collections: [
      {
        id: COLLECTION_ID,
        organization_id: ORG_ID,
        name: '2.collection-name',
        external_id: null,
        creation_date: NOW,
        revision_date: NOW,
      },
    ],
    collection_users: [
      {
        collection_id: COLLECTION_ID,
        organization_user_id: ORG_USER_CONFIRMED,
        read_only: 0,
        hide_passwords: 1,
      },
    ],
    cipher_collections: [
      { cipher_id: CIPHER_ORG, collection_id: COLLECTION_ID },
    ],
  };
}

function tableCounts(db: Record<string, SqlRow[]>): Record<string, number> {
  return Object.fromEntries(Object.entries(db).map(([table, rows]) => [table, rows.length]));
}

function buildManifest(db: Record<string, SqlRow[]>) {
  return {
    formatVersion: 1,
    exportedAt: NOW,
    appVersion: 'test',
    storageKind: null,
    tableCounts: tableCounts(db),
    includes: { attachments: true },
    blobSummary: { attachmentFiles: 0, totalBytes: 0, largestObjectBytes: 0 },
    attachmentBlobs: [],
  };
}

function buildArchive(db: Record<string, SqlRow[]>, manifest = buildManifest(db)): Uint8Array {
  return zipSync({
    'manifest.json': strToU8(JSON.stringify(manifest, null, 2)),
    'db.json': strToU8(JSON.stringify(db, null, 2)),
  });
}

function mutateArchive(
  db: Record<string, SqlRow[]>,
  mutate: (draft: Record<string, SqlRow[]>) => void,
  options: { manifest?: (manifest: { tableCounts: Record<string, number> }) => void } = {}
): Uint8Array {
  const draft = JSON.parse(JSON.stringify(db)) as Record<string, SqlRow[]>;
  mutate(draft);
  const manifest = buildManifest(db) as { tableCounts: Record<string, number> };
  manifest.tableCounts = tableCounts(draft);
  options.manifest?.(manifest);
  return buildArchive(draft, manifest);
}

async function parseAndValidate(bytes: Uint8Array): Promise<ReturnType<typeof parseBackupArchive>> {
  const parsed = parseBackupArchive(bytes);
  validateBackupPayloadContents(parsed.payload, parsed.files);
  return parsed;
}

// ─── SQLite/D1 harness for the real restore pipeline ────────────────────────

class MockStatement {
  private params: unknown[] = [];
  constructor(
    private raw: DatabaseSync,
    private sql: string
  ) {}

  bind(...args: unknown[]): this {
    this.params = args;
    return this;
  }

  async run(): Promise<{ success: boolean }> {
    this.raw.prepare(this.sql).run(...this.params);
    return { success: true };
  }

  async first<T>(): Promise<T | null> {
    const row = this.raw.prepare(this.sql).get(...this.params);
    return (row ?? null) as T | null;
  }

  async all<T>(): Promise<{ results: T[] }> {
    const rows = this.raw.prepare(this.sql).all(...this.params);
    return { results: rows as unknown as T[] };
  }
}

class MockD1 {
  constructor(private raw: DatabaseSync) {}
  prepare(sql: string): MockStatement {
    return new MockStatement(this.raw, sql);
  }
  async batch(statements: MockStatement[]): Promise<unknown[]> {
    for (const statement of statements) {
      await statement.run();
    }
    return [];
  }
}

function openDatabase(): { raw: DatabaseSync; env: Env; d1: MockD1 } {
  const raw = new DatabaseSync(':memory:');
  const d1 = new MockD1(raw);
  return { raw, env: { DB: d1 } as unknown as Env, d1 };
}

// Builds the runtime schema with the server's own bootstrap (adds the runtime
// columns, e.g. users.yubikey_*, that the restore insert machinery binds).
async function openSchema(): Promise<ReturnType<typeof openDatabase>> {
  const { ensureStorageSchema } = await import('../src/services/storage-schema');
  const db = openDatabase();
  await ensureStorageSchema(db.env.DB as unknown as D1Database);
  return db;
}

function count(raw: DatabaseSync, table: string): number {
  return Number(raw.prepare(`SELECT COUNT(*) AS count FROM ${table}`).get()?.count ?? 0);
}

// ─── Parse + validate on the full fixture ───────────────────────────────────

test('parse keeps the six organization tables from the archive', async () => {
  const db = baseDb();
  const parsed = await parseAndValidate(buildArchive(db));

  const orgTables = ['organizations', 'organization_users', 'cipher_user_folders', 'collections', 'collection_users', 'cipher_collections'] as const;
  for (const table of orgTables) {
    assert.equal(
      parsed.payload.db[table]?.length,
      db[table].length,
      `parse must preserve the ${table} table`
    );
  }
});

test('validation passes for an organization-bearing archive', async () => {
  const parsed = await parseAndValidate(buildArchive(baseDb()));
  // Organization ciphers (null user_id) must be accepted alongside personal ones.
  const orgCipher = parsed.payload.db.ciphers.find((row) => row.id === CIPHER_ORG);
  assert.ok(orgCipher, 'org cipher row parsed');
  assert.equal(orgCipher.user_id, null);
  assert.equal(orgCipher.organization_id, ORG_ID);
});

// ─── Cipher-row validation ──────────────────────────────────────────────────

test('personal ciphers with unknown users are still rejected', async () => {
  const db = baseDb();
  const bytes = mutateArchive(db, (draft) => {
    draft.ciphers.find((row) => row.id === CIPHER_PERSONAL)!.user_id = 'unknown-user';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid cipher row/);
});

test('organization ciphers with unknown organizations are rejected', async () => {
  const db = baseDb();
  const bytes = mutateArchive(db, (draft) => {
    draft.ciphers.find((row) => row.id === CIPHER_ORG)!.organization_id = 'unknown-org';
  });
  await assert.rejects(() => parseAndValidate(bytes), /unknown organization/);
});

test('ciphers must reference a user or an organization', async () => {
  const db = baseDb();
  const bytes = mutateArchive(db, (draft) => {
    const row = draft.ciphers.find((row) => row.id === CIPHER_PERSONAL)!;
    row.user_id = null;
    row.organization_id = null;
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid cipher row/);
});

test('a hybrid cipher pointing at an unknown organization is rejected', async () => {
  const db = baseDb();
  const bytes = mutateArchive(db, (draft) => {
    const row = draft.ciphers.find((row) => row.id === CIPHER_PERSONAL)!;
    row.organization_id = 'unknown-org';
  });
  await assert.rejects(() => parseAndValidate(bytes), /unknown organization/);
});

// ─── Organization-table referential validation ──────────────────────────────

test('organization members must reference a known organization', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.organization_users.find((row) => row.id === ORG_USER_CONFIRMED)!.organization_id = 'unknown-org';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid organization member row/);
});

test('organization members with an unknown user are rejected', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.organization_users.find((row) => row.id === ORG_USER_CONFIRMED)!.user_id = 'unknown-user';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid organization member row/);
});

test('invited members with a null user are accepted', async () => {
  // Already part of the base fixture: ORG_USER_INVITED has user_id null.
  await parseAndValidate(buildArchive(baseDb()));
});

test('collections must reference a known organization', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.collections.find((row) => row.id === COLLECTION_ID)!.organization_id = 'unknown-org';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid collection row/);
});

test('collection assignments must reference known collections and members', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.collection_users[0].organization_user_id = 'unknown-org-user';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid collection assignment row/);

  const bytes2 = mutateArchive(baseDb(), (draft) => {
    draft.collection_users[0].collection_id = 'unknown-collection';
  });
  await assert.rejects(() => parseAndValidate(bytes2), /invalid collection assignment row/);
});

test('cipher-collection links must reference known ciphers and collections', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.cipher_collections[0].cipher_id = 'unknown-cipher';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid cipher collection row/);

  const bytes2 = mutateArchive(baseDb(), (draft) => {
    draft.cipher_collections[0].collection_id = 'unknown-collection';
  });
  await assert.rejects(() => parseAndValidate(bytes2), /invalid cipher collection row/);
});

test('per-user cipher filing must reference known ciphers, users, and folders', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.cipher_user_folders[0].folder_id = 'unknown-folder';
  });
  await assert.rejects(() => parseAndValidate(bytes), /invalid cipher filing row/);

  const bytes2 = mutateArchive(baseDb(), (draft) => {
    draft.cipher_user_folders[0].user_id = 'unknown-user';
  });
  await assert.rejects(() => parseAndValidate(bytes2), /invalid cipher filing row/);
});

test('duplicate organization ids are rejected', async () => {
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.organizations.push({ ...draft.organizations[0] });
  });
  await assert.rejects(() => parseAndValidate(bytes), /duplicate organization id/);
});

// ─── The silent-drop regression ─────────────────────────────────────────────

test('a missing organization table fails loudly against the manifest counts', async () => {
  // A minimal archive: one user and one organization, no org ciphers. The
  // parser/allowlist drops all six organization tables from db.json while the
  // manifest (written at export time) still records their rows — exactly what
  // the old 8-table allowlist did. Restore must fail loudly, not report
  // success with the org layer erased.
  const db = baseDb();
  const draft: Record<string, SqlRow[]> = {
    config: [],
    users: db.users.slice(0, 1),
    domain_settings: [],
    user_revisions: [db.user_revisions[0]],
    folders: [],
    ciphers: [],
    attachments: [],
    webauthn_credentials: [],
    organizations: db.organizations,
    organization_users: [],
    cipher_user_folders: [],
    collections: [],
    collection_users: [],
    cipher_collections: [],
  };
  const manifest = buildManifest(draft);
  for (const table of ['organizations', 'organization_users', 'cipher_user_folders', 'collections', 'collection_users', 'cipher_collections']) {
    delete draft[table];
  }
  const bytes = buildArchive(draft, manifest);
  await assert.rejects(() => parseAndValidate(bytes), /manifest is inconsistent with its database payload: organizations/);
});

// ─── End-to-end restore through the real pipeline ───────────────────────────

test('restore of an org-bearing archive preserves the full organization layer', async () => {
  const { raw, env } = await openSchema();
  const bytes = buildArchive(baseDb());

  const result = await importBackupArchiveBytes(bytes, env, USER_A, false);

  const imported = result.result.imported;
  assert.equal(imported.organizations, 1);
  assert.equal(imported.organizationUsers, 2);
  assert.equal(imported.collections, 1);
  assert.equal(imported.collectionUsers, 1);
  assert.equal(imported.cipherCollections, 1);
  assert.equal(imported.cipherUserFolders, 1);
  assert.equal(imported.ciphers, 2);
  assert.equal(imported.folders, 1);
  assert.equal(imported.users, 2);

  // Verify the swapped-in live tables, not just the result body.
  assert.equal(count(raw, 'organizations'), 1);
  assert.equal(count(raw, 'organization_users'), 2);
  assert.equal(count(raw, 'collections'), 1);
  assert.equal(count(raw, 'collection_users'), 1);
  assert.equal(count(raw, 'cipher_collections'), 1);
  assert.equal(count(raw, 'cipher_user_folders'), 1);

  // Membership with the wrapped org key survived intact.
  const membership = raw
    .prepare('SELECT user_id, key, status FROM organization_users WHERE id = ?')
    .get(ORG_USER_CONFIRMED) as { user_id: string; key: string; status: number };
  assert.equal(membership.user_id, USER_B);
  assert.equal(membership.key, 'wrapped-org-key-for-b');

  // The invited member kept its null user (not silently dropped or re-bound).
  const invited = raw
    .prepare('SELECT user_id FROM organization_users WHERE id = ?')
    .get(ORG_USER_INVITED) as { user_id: string | null };
  assert.equal(invited.user_id, null);

  // The organization cipher was restored with a null user and its org.
  const orgCipher = raw
    .prepare('SELECT user_id, organization_id FROM ciphers WHERE id = ?')
    .get(CIPHER_ORG) as { user_id: string | null; organization_id: string };
  assert.equal(orgCipher.user_id, null);
  assert.equal(orgCipher.organization_id, ORG_ID);
});

test('restore of an archive with an invalid org cipher fails before mutating anything', async () => {
  const { raw, env } = await openSchema();
  const bytes = mutateArchive(baseDb(), (draft) => {
    draft.ciphers.find((row) => row.id === CIPHER_ORG)!.organization_id = 'unknown-org';
  });

  await assert.rejects(() => importBackupArchiveBytes(bytes, env, USER_A, false), /unknown organization/);

  assert.equal(count(raw, 'users'), 0);
  assert.equal(count(raw, 'ciphers'), 0);
  assert.equal(count(raw, 'organizations'), 0);
});

test('restore refuses to overwrite live organization data without replaceExisting', async () => {
  const { raw, env } = await openSchema();
  // An instance that only holds organization structure is still not fresh.
  raw
    .prepare('INSERT INTO organizations (id, name, private_key, billing_email, creation_date, revision_date) VALUES (?, ?, ?, ?, ?, ?)')
    .run('live-org', 'Live Org', 'key', 'live@example.com', NOW, NOW);

  await assert.rejects(
    () => importBackupArchiveBytes(buildArchive(baseDb()), env, USER_A, false),
    /fresh instance/
  );

  const live = raw.prepare('SELECT name FROM organizations WHERE id = ?').get('live-org') as { name: string };
  assert.equal(live.name, 'Live Org');
});
