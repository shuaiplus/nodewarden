import assert from 'node:assert/strict';
import test from 'node:test';

import { handleRemoveSendAuth } from '../src/handlers/sends-private';
import { validatePublicSendAccess } from '../src/handlers/sends-shared';
import type { Env, Send } from '../src/types';
import { SendAuthType, SendType } from '../src/types';

const userId = 'd75020e1-2de4-46e8-b8f1-475d127b51f2';
const sendId = '11111111-1111-4111-8111-111111111111';

test('remove-auth clears a password-protected send so public access no longer asks for a password', async () => {
  const sendUpserts: unknown[][] = [];
  const db = {
    prepare(sql: string) {
      const statement = {
        binds: [] as unknown[],
        bind(...values: unknown[]) {
          statement.binds = values;
          return statement;
        },
        async first() {
          if (!sql.includes('FROM sends WHERE id = ? AND user_id = ?')) return null;
          return {
            id: sendId,
            user_id: userId,
            type: SendType.Text,
            name: 'Text send',
            notes: null,
            data: '{}',
            key: 'send-key',
            password_hash: 'cGFzc3dvcmQtaGFzaA',
            password_salt: 'c2FsdA',
            password_iterations: 100000,
            auth_type: SendAuthType.Password,
            emails: null,
            max_access_count: null,
            access_count: 0,
            disabled: 0,
            hide_email: null,
            created_at: '2026-10-12T00:00:00.000Z',
            updated_at: '2026-10-12T00:00:00.000Z',
            expiration_date: null,
            deletion_date: '2026-11-12T00:00:00.000Z',
          };
        },
        async run() {
          if (sql.startsWith('INSERT INTO sends')) sendUpserts.push(statement.binds);
          return { success: true, meta: { changes: 0 } };
        },
      };
      return statement;
    },
  } as unknown as D1Database;

  const response = await handleRemoveSendAuth(
    new Request(`https://vault.example.test/api/sends/${sendId}/remove-auth`, { method: 'POST' }),
    {
      DB: db,
      NOTIFICATIONS_HUB: {
        idFromName(name: string) {
          return name;
        },
        get() {
          return { async fetch() { return new Response(null, { status: 204 }); } };
        },
      },
    } as unknown as Env,
    userId,
    sendId,
  );
  const body = await response.json() as { authType: number; password: string | null; emails: string | null };
  const binds = sendUpserts[0];
  const saved = {
    authType: binds[10],
    passwordHash: binds[7],
    passwordSalt: binds[8],
    passwordIterations: binds[9],
    emails: binds[11],
  } as Send;

  assert.equal(response.status, 200);
  assert.equal(body.authType, SendAuthType.None);
  assert.equal(body.password, null);
  assert.equal(body.emails, null);
  assert.equal(saved.passwordHash, null);
  assert.equal(saved.passwordSalt, null);
  assert.equal(saved.passwordIterations, null);
  assert.deepEqual(await validatePublicSendAccess(saved, {}), { ok: true });
});
