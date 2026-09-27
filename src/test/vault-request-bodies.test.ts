import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// Vault item and folder bodies as official clients send them to /api/ciphers, its bulk and attachment
// routes, and /api/folders.
const ENCRYPTED = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const LOGIN_TYPE = 1;
const ARCHIVED_AT = '2026-01-02T03:04:05.000Z';

interface CipherBody {
  id: string;
  archivedDate: string | null;
  futureField?: unknown;
  login: { futureLoginField?: unknown } | null;
}

interface ErrorBody {
  validationErrors: Record<string, string[]> | null;
}

async function send(env: Env, user: User, method: string, path: string, body: unknown): Promise<Response> {
  return authedFetch(env, { method, path, body, userId: user.id });
}

test('a created cipher keeps the fields a newer client adds, at the top level and inside login', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const response = await send(env, user, 'POST', '/api/ciphers', {
    type: LOGIN_TYPE,
    name: ENCRYPTED,
    futureField: { nested: true },
    login: { username: ENCRYPTED, futureLoginField: 7 },
  });
  assert.equal(response.status, 200);
  const created = (await response.json()) as CipherBody;

  const fetched = (await (
    await authedFetch(env, { path: `/api/ciphers/${created.id}`, userId: user.id })
  ).json()) as CipherBody;
  assert.deepEqual(fetched.futureField, { nested: true });
  assert.equal(fetched.login?.futureLoginField, 7);
});

test('a wrongly typed favorite or id list answers 400 with the field under validationErrors', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const favorite = await send(env, user, 'POST', '/api/ciphers', {
    type: LOGIN_TYPE,
    name: ENCRYPTED,
    favorite: 'yes',
  });
  assert.equal(favorite.status, 400);
  assert.deepEqual(Object.keys(((await favorite.json()) as ErrorBody).validationErrors ?? {}), ['favorite']);

  const ids = await send(env, user, 'POST', '/api/ciphers/delete', { ids: 'not-a-list' });
  assert.equal(ids.status, 400);
  assert.deepEqual(((await ids.json()) as ErrorBody).validationErrors, { ids: ['ids array is required'] });
});

test('a full update clears the archive only when archivedAt or archivedDate is sent', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const created = (await (
    await send(env, user, 'POST', '/api/ciphers', {
      type: LOGIN_TYPE,
      name: ENCRYPTED,
      archivedDate: ARCHIVED_AT,
    })
  ).json()) as CipherBody;
  assert.equal(created.archivedDate, ARCHIVED_AT);

  const path = `/api/ciphers/${created.id}`;
  const kept = (await (await send(env, user, 'PUT', path, { type: LOGIN_TYPE, name: ENCRYPTED })).json()) as CipherBody;
  assert.equal(kept.archivedDate, ARCHIVED_AT);

  // A sent archivedAt wins over the archivedDate alias, even when it is null.
  const cleared = (await (
    await send(env, user, 'PUT', path, {
      type: LOGIN_TYPE,
      name: ENCRYPTED,
      archivedAt: null,
      archivedDate: ARCHIVED_AT,
    })
  ).json()) as CipherBody;
  assert.equal(cleared.archivedDate, null);
});

test('attachment v2 reads the numeric-string fileSize Android sends and requires fileName and key', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const created = (await (
    await send(env, user, 'POST', '/api/ciphers', { type: LOGIN_TYPE, name: ENCRYPTED })
  ).json()) as CipherBody;
  const path = `/api/ciphers/${created.id}/attachment/v2`;

  const response = await send(env, user, 'POST', path, { fileName: ENCRYPTED, key: ENCRYPTED, fileSize: '2048' });
  assert.equal(response.status, 200);
  const { cipherResponse } = (await response.json()) as { cipherResponse: { attachments: Array<{ size: string }> } };
  assert.deepEqual(
    cipherResponse.attachments.map((attachment) => attachment.size),
    ['2048'],
  );

  const missing = await send(env, user, 'POST', path, { fileName: ENCRYPTED, fileSize: 1 });
  assert.equal(missing.status, 400);
  assert.deepEqual(((await missing.json()) as ErrorBody).validationErrors, { key: ['fileName and key are required'] });
});

test('folder bodies answer a missing or non-string name and a missing id list with their messages', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  for (const [path, body, field, message] of [
    ['/api/folders', { name: 5 }, 'name', 'Name is required'],
    ['/api/folders', {}, 'name', 'Name is required'],
    ['/api/folders/delete', { ids: [' '] }, 'ids', 'Folder ids are required'],
  ] as const) {
    const response = await send(env, user, 'POST', path, body);
    assert.equal(response.status, 400);
    assert.deepEqual(((await response.json()) as ErrorBody).validationErrors, { [field]: [message] });
  }
});
