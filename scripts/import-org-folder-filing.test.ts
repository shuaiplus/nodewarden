import assert from 'node:assert/strict';
import test from 'node:test';
import { registerHooks } from 'node:module';

// ─── Organization import folder filing (server) ─────────────────────────────
// POST /api/ciphers/import with a target folder must file organization items
// per-user (cipher_user_folders) instead of dropping the folder: org cipher
// rows never persist a personal folder id, and sync overlays the per-user
// filing. Regression guard for the "org .json import ignores target folder"
// bug.

// The import handler graph imports the Workers-only 'cloudflare:workers'
// module (notifications-hub); stub it so node can load the handler.
const CLOUDFLARE_WORKERS_STUB =
  'data:text/javascript,' +
  encodeURIComponent(
    'export class DurableObject { constructor(ctx, env) { this.ctx = ctx; this.env = env; } }\n' +
    'export function waitUntil(promise) { try { Promise.resolve(promise).catch(() => {}) } catch {} }\n'
  );

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'cloudflare:workers') {
      return { url: CLOUDFLARE_WORKERS_STUB, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

const { handleCiphersImport } = await import('../src/handlers/import');
const { ORG_USER_STATUS } = await import('../src/config/org');
import type { Env } from '../src/types';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const ORG_ID = '22222222-2222-4222-8222-222222222222';
const ORG_USER_ID = '33333333-3333-4333-8333-333333333333';
const COLLECTION_ID = '44444444-4444-4444-8444-444444444444';
const TARGET_FOLDER_ID = '55555555-5555-4555-8555-555555555555';
const NOW = new Date().toISOString();
// Valid AesCbc256_HmacSha256_B64 EncString shape (type 2: iv|data|mac).
const ENC = '2.aXZpdml2aXZpdml2|ZGF0YWRhdGFkYXRh|bWFjbWFjbWFjbWFj';

interface Recorded {
  sql: string;
  params: unknown[];
}

class MockStatement {
  params: unknown[] = [];
  constructor(
    public db: MockDb,
    public sql: string
  ) {}

  bind(...args: unknown[]) {
    this.params = args;
    return this;
  }

  async run() {
    this.db.writes.push({ sql: this.sql, params: this.params });
    return { success: true, meta: {} };
  }

  async first<T>() {
    return this.db.readFirst<T>(this.sql, this.params);
  }

  async all<T>() {
    return { results: this.db.readAll<T>(this.sql, this.params) };
  }
}

class MockDb {
  writes: Recorded[] = [];

  prepare(sql: string) {
    return new MockStatement(this, sql);
  }

  async batch(statements: MockStatement[]) {
    for (const statement of statements) {
      await statement.run();
    }
  }

  readFirst<T>(sql: string, params: unknown[]): T | null {
    if (sql.includes('FROM organization_users WHERE organization_id = ? AND user_id = ?')) {
      assert.equal(params[0], ORG_ID);
      return {
        id: ORG_USER_ID,
        organization_id: ORG_ID,
        user_id: USER_ID,
        email: 'member@example.test',
        key: null,
        status: ORG_USER_STATUS.CONFIRMED,
        type: 0,
        access_all: 1,
        creation_date: NOW,
        revision_date: NOW,
      } as T;
    }
    if (sql.includes('FROM devices WHERE user_id = ? AND push_token')) {
      return null;
    }
    throw new Error(`Unexpected first() query in test: ${sql}`);
  }

  readAll<T>(sql: string, params: unknown[]): T[] {
    if (sql.includes('FROM collections WHERE organization_id = ?')) {
      return [
        {
          id: COLLECTION_ID,
          organization_id: ORG_ID,
          name: ENC,
          external_id: null,
          creation_date: NOW,
          revision_date: NOW,
        },
      ] as T[];
    }
    if (sql.includes('FROM folders WHERE user_id = ?')) {
      return [
        {
          id: TARGET_FOLDER_ID,
          user_id: USER_ID,
          name: ENC,
          created_at: NOW,
          updated_at: NOW,
        },
      ] as T[];
    }
    if (sql.includes('FROM organization_users WHERE organization_id = ? AND status =')) {
      return [{ id: ORG_USER_ID, user_id: USER_ID }] as T[];
    }
    throw new Error(`Unexpected all() query in test: ${sql}`);
  }
}

function createEnv(): { env: Env; db: MockDb } {
  const db = new MockDb();
  const env = {
    DB: db,
    JWT_SECRET: 'test-secret',
    NOTIFICATIONS_HUB: {
      idFromName: () => 'stub-id',
      get: () => ({ fetch: async () => new Response(null) }),
    },
    BACKUP_TRANSFER_RUNNER: {},
  } as unknown as Env;
  return { env, db };
}

function importRequest(body: unknown): Request {
  return new Request('https://test.internal/api/ciphers/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

const ORG_CIPHER = {
  type: 1,
  name: ENC,
  notes: null,
  favorite: false,
  reprompt: 0,
  login: { username: null, password: null, uris: null, totp: null },
  folderId: TARGET_FOLDER_ID,
  organizationId: ORG_ID,
  collectionIds: [COLLECTION_ID],
};

const PERSONAL_CIPHER = {
  type: 1,
  name: ENC,
  notes: null,
  favorite: false,
  reprompt: 0,
  login: { username: null, password: null, uris: null, totp: null },
  folderId: TARGET_FOLDER_ID,
};

function writes(db: MockDb, table: string): Recorded[] {
  return db.writes.filter((row) => new RegExp(`INSERT (?:OR \\w+ )?INTO ${table}\\b`).test(row.sql));
}

test('org import with target folder files per-user, shared row stays folderless', async () => {
  const { env, db } = createEnv();
  const response = await handleCiphersImport(importRequest({ ciphers: [ORG_CIPHER], folders: [], folderRelationships: [] }), env, USER_ID);
  assert.equal(response.status, 200);

  const cipherInserts = writes(db, 'ciphers');
  assert.equal(cipherInserts.length, 1, 'one cipher row inserted');
  assert.equal(cipherInserts[0].params[1], null, 'org cipher rows have no owning user');
  assert.equal(cipherInserts[0].params[2], ORG_ID, 'organization_id column');
  assert.equal(cipherInserts[0].params[4], null, 'shared org row never persists a personal folder id');

  const filings = writes(db, 'cipher_user_folders');
  assert.equal(filings.length, 1, 'org cipher filed into the target folder for the acting user');
  assert.equal(filings[0].params[0], cipherInserts[0].params[0], 'filing references the inserted cipher');
  assert.equal(filings[0].params[1], USER_ID, 'filing belongs to the acting user');
  assert.equal(filings[0].params[2], TARGET_FOLDER_ID, 'filing uses the selected target folder');

  const collectionLinks = writes(db, 'cipher_collections');
  assert.equal(collectionLinks.length, 1, 'cipher linked to the mapped collection');
  assert.equal(collectionLinks[0].params[0], cipherInserts[0].params[0]);
  assert.equal(collectionLinks[0].params[1], COLLECTION_ID);
});

test('personal import with target folder persists folder_id directly', async () => {
  const { env, db } = createEnv();
  const response = await handleCiphersImport(importRequest({ ciphers: [PERSONAL_CIPHER], folders: [], folderRelationships: [] }), env, USER_ID);
  assert.equal(response.status, 200);

  const cipherInserts = writes(db, 'ciphers');
  assert.equal(cipherInserts.length, 1);
  assert.equal(cipherInserts[0].params[1], USER_ID, 'user_id column');
  assert.equal(cipherInserts[0].params[2], null, 'organization_id column');
  assert.equal(cipherInserts[0].params[4], TARGET_FOLDER_ID, 'personal row stores the target folder id');
  assert.equal(writes(db, 'cipher_user_folders').length, 0, 'no per-user filing for personal rows');
});

test('org import without folder selection stays folderless', async () => {
  const { env, db } = createEnv();
  const cipher = { ...ORG_CIPHER, folderId: null };
  const response = await handleCiphersImport(importRequest({ ciphers: [cipher], folders: [], folderRelationships: [] }), env, USER_ID);
  assert.equal(response.status, 200);

  assert.equal(writes(db, 'ciphers')[0].params[4], null);
  assert.equal(writes(db, 'cipher_user_folders').length, 0);
});

test('org import rejects unknown target folder', async () => {
  const { env, db } = createEnv();
  const cipher = { ...ORG_CIPHER, folderId: 'missing-folder-id' };
  const response = await handleCiphersImport(importRequest({ ciphers: [cipher], folders: [], folderRelationships: [] }), env, USER_ID);
  // Import succeeds but the unresolvable folder id is dropped, not stored.
  assert.equal(response.status, 200);
  assert.equal(writes(db, 'ciphers')[0].params[4], null);
  assert.equal(writes(db, 'cipher_user_folders').length, 0);
});
