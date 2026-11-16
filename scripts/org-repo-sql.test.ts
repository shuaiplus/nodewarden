// Functional SQL tests for the owner-preconditioned organization storage
// statements, executed against a real SQLite database via node:sqlite.
//
// WHY THIS FILE EXISTS: these statements previously built their SQL from
// single-quoted strings containing literal `${...}` text (valid TypeScript,
// invalid SQL), so every call threw "unrecognized token" and surfaced as a
// 500 from the API — collection deletes, organization deletes, and the
// last-owner guards all failed. The source-pattern suite cannot catch that
// class of bug; these tests actually execute the SQL (mirroring the prod
// schema, FK cascades included) so a malformed statement fails loudly.
import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';

const { deleteCollectionForOwner } = await import('../src/services/storage-collection-repo');
const { acceptOrganizationInvitesByEmail } = await import('../src/services/storage-org-repo');
const {
  countConfirmedOrganizationOwners,
  deleteOrganizationForOwner,
} = await import('../src/services/storage-org-repo');
const { ORG_USER_STATUS, ORG_USER_TYPE } = await import('../src/config/org');

// Minimal D1 surface used by the statements under test:
// prepare(sql).bind(...args).run() / .first()
interface DbHarness {
  d1: unknown;
  raw: DatabaseSync;
  insertUser(id: string, userId: string, status: number, type: number): void;
}

function makeDb(): DbHarness {
  const raw = new DatabaseSync(':memory:');
  raw.exec('PRAGMA foreign_keys = ON');
  raw.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, email TEXT NOT NULL, name TEXT, master_password_hash TEXT, key TEXT,
      kdf_type INTEGER NOT NULL DEFAULT 0, kdf_iterations INTEGER NOT NULL,
      private_key TEXT, public_key TEXT, security_stamp TEXT, status INTEGER NOT NULL,
      master_password_hint TEXT, totp_secret TEXT, role INTEGER NOT NULL, created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE organizations (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, private_key TEXT, public_key TEXT,
      billing_email TEXT, creation_date TEXT NOT NULL, revision_date TEXT NOT NULL
    );
    CREATE TABLE organization_users (
      id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, user_id TEXT, email TEXT NOT NULL,
      key TEXT, status INTEGER NOT NULL, type INTEGER NOT NULL, access_all INTEGER NOT NULL DEFAULT 0,
      creation_date TEXT NOT NULL, revision_date TEXT NOT NULL,
      FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE ciphers (
      id TEXT PRIMARY KEY, user_id TEXT, organization_id TEXT, type INTEGER NOT NULL,
      folder_id TEXT, name TEXT NOT NULL, notes TEXT, favorite INTEGER NOT NULL DEFAULT 0,
      data TEXT NOT NULL, reprompt INTEGER NOT NULL DEFAULT 0, key TEXT,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL, archived_at TEXT, deleted_at TEXT
    );
    CREATE TABLE collections (
      id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, name TEXT NOT NULL, external_id TEXT,
      creation_date TEXT NOT NULL, revision_date TEXT NOT NULL,
      FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
    );
    CREATE TABLE collection_users (
      collection_id TEXT NOT NULL, organization_user_id TEXT NOT NULL,
      read_only INTEGER NOT NULL DEFAULT 0, hide_passwords INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (collection_id, organization_user_id),
      FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE,
      FOREIGN KEY (organization_user_id) REFERENCES organization_users(id) ON DELETE CASCADE
    );
    CREATE TABLE cipher_collections (
      cipher_id TEXT NOT NULL, collection_id TEXT NOT NULL,
      PRIMARY KEY (cipher_id, collection_id),
      FOREIGN KEY (cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
      FOREIGN KEY (collection_id) REFERENCES collections(id) ON DELETE CASCADE
    );
  `);
  const now = new Date().toISOString();
  raw.prepare('INSERT INTO organizations (id, name, creation_date, revision_date) VALUES (?, ?, ?, ?)')
    .run('org-1', 'Org', now, now);

  const insertUser = raw.prepare(
    'INSERT INTO organization_users (id, organization_id, user_id, email, status, type, creation_date, revision_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  );
  const insertUsersRow = raw.prepare('INSERT INTO users (id, email, kdf_iterations, status, role, created_at, updated_at) VALUES (?, ?, 100000, 0, 0, ?, ?)');
  const harness: DbHarness = {
    d1: {
      prepare(sql: string) {
        const stmt = raw.prepare(sql);
        return {
          bind(...args: unknown[]) {
            return {
              async run() {
                const result = stmt.run(...(args as any[]));
                return { meta: { changes: Number(result.changes ?? 0) } };
              },
              async first() {
                return stmt.get(...(args as any[])) ?? null;
              },
            };
          },
        };
      },
    },
    raw,
    insertUser(id, userId, status, type) {
      insertUsersRow.run(userId, `${userId}@example.com`, now, now);
      insertUser.run(id, 'org-1', userId, `${userId}@example.com`, status, type, now, now);
    },
  };
  harness.insertUser('ou-owner', 'user-owner', ORG_USER_STATUS.CONFIRMED, ORG_USER_TYPE.OWNER);
  harness.insertUser('ou-admin', 'user-admin', ORG_USER_STATUS.CONFIRMED, ORG_USER_TYPE.ADMIN);

  const insertCollection = raw.prepare(
    'INSERT INTO collections (id, organization_id, name, creation_date, revision_date) VALUES (?, ?, ?, ?, ?)'
  );
  insertCollection.run('coll-1', 'org-1', 'enc-name-1', now, now);
  insertCollection.run('coll-2', 'org-1', 'enc-name-2', now, now);
  raw.prepare('INSERT INTO ciphers (id, organization_id, type, name, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run('cipher-1', 'org-1', 1, 'enc-cipher', 'data', now, now);
  raw.prepare('INSERT INTO cipher_collections (cipher_id, collection_id) VALUES (?, ?)').run('cipher-1', 'coll-1');
  return harness;
}

function count(raw: DatabaseSync, sql: string, ...args: unknown[]): number {
  return Number((raw.prepare(sql).get(...(args as any[])) as any)?.n ?? 0);
}

test('countConfirmedOrganizationOwners counts only confirmed owners', async () => {
  const db = makeDb();
  assert.equal(await countConfirmedOrganizationOwners(db.d1, 'org-1'), 1, 'the single confirmed owner');
  assert.equal(await countConfirmedOrganizationOwners(db.d1, 'missing-org'), 0, 'an unknown organization');

  db.insertUser('ou-invited-owner', 'user-invited-owner', ORG_USER_STATUS.INVITED, ORG_USER_TYPE.OWNER);
  assert.equal(
    await countConfirmedOrganizationOwners(db.d1, 'org-1'),
    1,
    'an invited-but-unconfirmed owner does not count'
  );

  db.insertUser('ou-second-owner', 'user-second-owner', ORG_USER_STATUS.CONFIRMED, ORG_USER_TYPE.OWNER);
  assert.equal(await countConfirmedOrganizationOwners(db.d1, 'org-1'), 2, 'two confirmed owners');
});

test('deleteCollectionForOwner is owner-gated and cascades assignments', async () => {
  const db = makeDb();
  assert.equal(
    await deleteCollectionForOwner(db.d1, 'coll-1', 'org-1', 'user-admin'),
    false,
    'a confirmed admin cannot delete a collection'
  );
  assert.equal(
    await deleteCollectionForOwner(db.d1, 'coll-1', 'other-org', 'user-owner'),
    false,
    'the wrong organization scope cannot delete'
  );
  assert.equal(
    await deleteCollectionForOwner(db.d1, 'coll-1', 'org-1', 'user-owner'),
    true,
    'the confirmed owner deletes the collection'
  );
  assert.equal(count(db.raw, "SELECT COUNT(*) AS n FROM collections WHERE id = 'coll-2'"), 1, 'the other collection survives');
  assert.equal(count(db.raw, "SELECT COUNT(*) AS n FROM cipher_collections WHERE collection_id = 'coll-1'"), 0, 'cipher assignments cascade away');
  assert.equal(count(db.raw, "SELECT COUNT(*) AS n FROM ciphers WHERE id = 'cipher-1'"), 1, 'the cipher itself is not deleted');
});

test('deleteOrganizationForOwner is owner-gated and cascades members', async () => {
  const db = makeDb();
  db.insertUser('ou-invited-owner', 'user-invited-owner', ORG_USER_STATUS.INVITED, ORG_USER_TYPE.OWNER);
  assert.equal(
    await deleteOrganizationForOwner(db.d1, 'org-1', 'user-admin'),
    false,
    'a non-owner cannot delete the organization'
  );
  assert.equal(
    await deleteOrganizationForOwner(db.d1, 'org-1', 'user-invited-owner'),
    false,
    'an unconfirmed owner cannot delete the organization'
  );
  assert.equal(
    await deleteOrganizationForOwner(db.d1, 'org-1', 'user-owner'),
    true,
    'the confirmed owner deletes the organization'
  );
  assert.equal(count(db.raw, 'SELECT COUNT(*) AS n FROM collections'), 0, 'collections cascade');
  assert.equal(count(db.raw, 'SELECT COUNT(*) AS n FROM organization_users'), 0, 'memberships cascade');
  assert.equal(count(db.raw, 'SELECT COUNT(*) AS n FROM cipher_collections'), 0, 'cipher assignments cascade');
});

test('acceptOrganizationInvitesByEmail links and auto-accepts pending invitations', async () => {
  const db = makeDb();
  // Unlinked invitation: the invitee had no account when invited. This row
  // must be linked to the new account and move INVITED -> ACCEPTED.
  const insertPending = db.raw.prepare(
    "INSERT INTO organization_users (id, organization_id, user_id, email, status, type, creation_date, revision_date) VALUES ('ou-pending', 'org-1', NULL, 'new-user@example.com', 0, 2, '2026-01-01', '2026-01-01')"
  );
  insertPending.run();
  // A revoked invitation for the SAME email must stay revoked and unlinked:
  // registration neither links nor resurrects it.
  db.raw.prepare(
    "INSERT INTO organization_users (id, organization_id, user_id, email, status, type, creation_date, revision_date) VALUES ('ou-revoked', 'org-1', NULL, 'new-user@example.com', -1, 2, '2026-01-01', '2026-01-01')"
  ).run();
  // Registration creates the account before linking, so provide the user row
  // the foreign key expects.
  db.raw.prepare(
    "INSERT INTO users (id, email, kdf_iterations, status, role, created_at, updated_at) VALUES ('user-new', 'new-user@example.com', 100000, 0, 0, '2026-01-01', '2026-01-01')"
  ).run();

  await acceptOrganizationInvitesByEmail(db.d1, 'user-new', 'new-user@example.com');

  const accepted = db.raw.prepare("SELECT user_id, status FROM organization_users WHERE id = 'ou-pending'").get() as { user_id: string; status: number };
  assert.equal(accepted.user_id, 'user-new', 'the invitation is linked to the new account');
  assert.equal(accepted.status, 1, 'the invitation moved INVITED -> ACCEPTED at registration');

  const revoked = db.raw.prepare("SELECT user_id, status FROM organization_users WHERE id = 'ou-revoked'").get() as { user_id: null; status: number };
  assert.equal(revoked.status, -1, 'revoked memberships are not resurrected');
  assert.equal(revoked.user_id, null, 'revoked memberships stay unlinked');

  // Re-running with a different account id must not re-link or flip the
  // membership that was already linked and accepted above.
  await acceptOrganizationInvitesByEmail(db.d1, 'user-new2', 'new-user@example.com');
  const again = db.raw.prepare("SELECT COUNT(*) AS n FROM organization_users WHERE id = 'ou-pending' AND user_id = 'user-new2'").get() as { n: number };
  assert.equal(again.n, 0, 'an already-linked membership is not re-linked');
});
