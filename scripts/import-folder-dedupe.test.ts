import assert from 'node:assert/strict';
import test from 'node:test';
import { registerHooks } from 'node:module';

// ─── Import folder dedupe (server) ─────────────────────────────────────────
// POST /api/ciphers/import must not create duplicate folders: payload folders
// whose (encrypted) name matches an existing vault folder reuse that folder's
// id, and duplicate names within one payload collapse into a single row.
// Folder names are opaque ciphertext, so matches are exact-string only; the
// first-party webapp additionally matches decrypted names client-side.

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
import type { Env } from '../src/types';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const EXISTING_FOLDER_ID = '66666666-6666-4666-8666-666666666666';
const NOW = new Date().toISOString();
// Valid AesCbc256_HmacSha256_B64 EncString shape (type 2: iv|data|mac).
const ENC_EXISTING = '2.aXZpdml2aXZpdml2|ZGF0YWRhdGFkYXRh|bWFjbWFjbWFjbWFj';
const ENC_NEW = '2.eml2aXZpdml2aXZp|ZGF0YWRhdGFkYXRh|bWFjbWFjbWFjbWFj';

interface Recorded {
  sql: string;
  params: unknown[];
}

interface FolderRow {
  id: string;
  user_id: string;
  name: string;
  created_at: string;
  updated_at: string;
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
    if (this.sql.includes('FROM devices WHERE user_id = ? AND push_token')) {
      return null;
    }
    throw new Error(`Unexpected first() query in test: ${this.sql}`);
  }

  async all<T>() {
    if (this.sql.includes('FROM folders WHERE user_id = ?')) {
      return { results: this.db.existingFolders as unknown as T[] };
    }
    throw new Error(`Unexpected all() query in test: ${this.sql}`);
  }
}

class MockDb {
  writes: Recorded[] = [];
  existingFolders: FolderRow[] = [];

  prepare(sql: string) {
    return new MockStatement(this, sql);
  }

  async batch(statements: MockStatement[]) {
    for (const statement of statements) {
      await statement.run();
    }
  }
}

function createEnv(existingFolders: FolderRow[]): { env: Env; db: MockDb } {
  const db = new MockDb();
  db.existingFolders = existingFolders;
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

function cipher(): Record<string, unknown> {
  return {
    type: 1,
    name: ENC_NEW,
    notes: null,
    favorite: false,
    reprompt: 0,
    login: { username: null, password: null, uris: null, totp: null },
  };
}

function writes(db: MockDb, table: string): Recorded[] {
  return db.writes.filter((row) => new RegExp(`INSERT (?:OR \\w+ )?INTO ${table}\\b`).test(row.sql));
}

test('payload folder matching an existing vault folder reuses it instead of duplicating', async () => {
  const { env, db } = createEnv([
    {
      id: EXISTING_FOLDER_ID,
      user_id: USER_ID,
      name: ENC_EXISTING,
      created_at: NOW,
      updated_at: NOW,
    },
  ]);
  const response = await handleCiphersImport(
    importRequest({
      ciphers: [cipher(), cipher()],
      folders: [{ name: ENC_EXISTING }, { name: ENC_NEW }],
      folderRelationships: [
        { key: 0, value: 0 },
        { key: 1, value: 1 },
      ],
    }),
    env,
    USER_ID
  );
  assert.equal(response.status, 200);

  const folderInserts = writes(db, 'folders');
  assert.equal(folderInserts.length, 1, 'only the unmatched folder is inserted');
  assert.equal(folderInserts[0].params[2], ENC_NEW, 'inserted folder keeps its own name');

  const cipherInserts = writes(db, 'ciphers');
  assert.equal(cipherInserts.length, 2);
  assert.equal(cipherInserts[0].params[4], EXISTING_FOLDER_ID, 'matching folder reuses the existing row id');
  assert.equal(cipherInserts[1].params[4], folderInserts[0].params[0], 'new folder id assigned via relationship');
});

test('duplicate folder names within one payload collapse into a single insert', async () => {
  const { env, db } = createEnv([]);
  const response = await handleCiphersImport(
    importRequest({
      ciphers: [cipher(), cipher()],
      folders: [{ name: ENC_NEW }, { name: ENC_NEW }],
      folderRelationships: [
        { key: 0, value: 0 },
        { key: 1, value: 1 },
      ],
    }),
    env,
    USER_ID
  );
  assert.equal(response.status, 200);

  const folderInserts = writes(db, 'folders');
  assert.equal(folderInserts.length, 1, 'duplicate payload names create one folder');

  const cipherInserts = writes(db, 'ciphers');
  assert.equal(cipherInserts.length, 2);
  assert.equal(cipherInserts[0].params[4], folderInserts[0].params[0]);
  assert.equal(cipherInserts[1].params[4], folderInserts[0].params[0], 'both ciphers share the single folder id');
});

test('ciphers without any folder association stay folderless', async () => {
  const { env, db } = createEnv([]);
  const response = await handleCiphersImport(
    importRequest({ ciphers: [cipher()], folders: [], folderRelationships: [] }),
    env,
    USER_ID
  );
  assert.equal(response.status, 200);
  assert.equal(writes(db, 'folders').length, 0);
  assert.equal(writes(db, 'ciphers')[0].params[4], null);
});
