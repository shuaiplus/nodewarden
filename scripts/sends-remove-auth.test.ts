import assert from 'node:assert/strict';
import test from 'node:test';

// Regression test for: "Send still requires password after removing auth
// (orphan passwordHash in handleRemoveSendAuth)".
// Run with: tsx --test --import ./scripts/test-bootstrap.mjs scripts/sends-remove-auth.test.ts
// (test-bootstrap.mjs shims the workerd-only `cloudflare:workers` module;
//  see scripts/test-stubs/cloudflare-workers.mjs)
import { handleRemoveSendAuth, handleRemoveSendPassword } from '../src/handlers/sends-private';
import { SendAuthType, type Env } from '../src/types';

const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const sendId = 'e86030f2-3e5f-49a9-c1d2-586e638f61a3';

// A persisted Send that currently requires a password (auth_type = Password).
// NOTE: the values below are synthetic fixtures, not real credentials —
// plain-English placeholders on purpose, so secret scanners don't mistake
// them for leaked material. Nothing on this code path decodes them.
function passwordProtectedSendRow() {
  const now = new Date().toISOString();
  return {
    id: sendId,
    user_id: userId,
    type: 0,
    name: 'test-fixture-name-not-a-secret',
    notes: null,
    data: 'test-fixture-data-not-a-secret',
    key: 'test-fixture-key-not-a-secret',
    password_hash: 'test-fixture-hash-not-a-secret',
    password_salt: 'test-fixture-salt-not-a-secret',
    password_iterations: 100_000,
    auth_type: SendAuthType.Password,
    emails: null,
    max_access_count: null,
    access_count: 0,
    disabled: 0,
    hide_email: null,
    created_at: now,
    updated_at: now,
    expiration_date: null,
    deletion_date: null,
  };
}

interface CapturedWrite {
  sql: string;
  values: unknown[];
}

function createFakeDb(sendRow: Record<string, unknown>) {
  const writes: CapturedWrite[] = [];
  const db = {
    prepare(sql: string) {
      const stmt = {
        params: [] as unknown[],
        bind(...params: unknown[]) {
          stmt.params = params;
          return stmt;
        },
        async first() {
          if (String(sql).includes('FROM sends')) return sendRow;
          return null;
        },
        async run() {
          writes.push({ sql: String(sql), values: stmt.params });
          return { success: true };
        },
        async all() {
          return { results: [] };
        },
      };
      return stmt;
    },
  };
  return { db, writes };
}

function createTestEnv(db: unknown): Env {
  return {
    DB: db,
    NOTIFICATIONS_HUB: {
      idFromName() {
        return {};
      },
      get() {
        return {
          async fetch() {
            return new Response('ok');
          },
        };
      },
    },
  } as unknown as Env;
}

function findSendUpsert(writes: CapturedWrite[]): unknown[] {
  const upsert = writes.find((w) => w.sql.startsWith('INSERT INTO sends'));
  assert.ok(upsert, 'expected the handler to persist the send');
  return upsert.values;
}

test('remove-auth clears the stored password hash/salt/iterations', async () => {
  const { db, writes } = createFakeDb(passwordProtectedSendRow());
  const res = await handleRemoveSendAuth(
    new Request(`https://vault.test/api/sends/${sendId}/remove-auth`, { method: 'PUT' }),
    createTestEnv(db),
    userId,
    sendId,
  );
  assert.equal(res.status, 200);

  // saveSend binds: id, userId, type, name, notes, data, key,
  //   passwordHash(7), passwordSalt(8), passwordIterations(9), authType(10), ...
  const values = findSendUpsert(writes);
  assert.equal(values[7], null);
  assert.equal(values[8], null);
  assert.equal(values[9], null);
  assert.equal(values[10], SendAuthType.None);

  const body = (await res.json()) as { authType: number; password: string | null };
  assert.equal(body.authType, SendAuthType.None);
  assert.equal(body.password, null);
});

test('remove-auth behaves like remove-password for password-protected sends', async () => {
  const { db: dbAuth, writes: writesAuth } = createFakeDb(passwordProtectedSendRow());
  await handleRemoveSendAuth(
    new Request(`https://vault.test/api/sends/${sendId}/remove-auth`, { method: 'PUT' }),
    createTestEnv(dbAuth),
    userId,
    sendId,
  );

  const { db: dbPassword, writes: writesPassword } = createFakeDb(passwordProtectedSendRow());
  const res = await handleRemoveSendPassword(
    new Request(`https://vault.test/api/sends/${sendId}/remove-password`, { method: 'PUT' }),
    createTestEnv(dbPassword),
    userId,
    sendId,
  );
  assert.equal(res.status, 200);

  // Both endpoints must leave the same password-free persisted state.
  assert.deepEqual(findSendUpsert(writesAuth).slice(7, 11), findSendUpsert(writesPassword).slice(7, 11));
});

test('remove-auth on someone else\u2019s send returns 404 and writes nothing', async () => {
  const { db, writes } = createFakeDb(passwordProtectedSendRow());
  const res = await handleRemoveSendAuth(
    new Request(`https://vault.test/api/sends/${sendId}/remove-auth`, { method: 'PUT' }),
    createTestEnv(db),
    '00000000-0000-4000-8000-000000000000',
    sendId,
  );
  assert.equal(res.status, 404);
  assert.equal(
    writes.filter((w) => w.sql.startsWith('INSERT INTO sends')).length,
    0,
  );
});
