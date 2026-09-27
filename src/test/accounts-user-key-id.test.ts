import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';

// Official clients 2026.9 POST the user key id once, then expect every /api/sync to echo it in
// UserDecryption.UserKeyId. A missing echo makes the SDK clear its copy and POST again, so the
// id must survive the 30 s sync cache and must never be overwritten.
const USER_KEY_ID_PATH = '/api/accounts/key-management/user-key-id';
const RECORDED_KEY_ID = '000102030405060708090a0b0c0d0e0f';
const COMPETING_KEY_ID = 'fedcba9876543210fedcba9876543210';

interface SyncUserKeyIds {
  UserDecryption: { UserKeyId: string | null };
  userDecryption: { userKeyId: string | null };
}

async function syncUserKeyIds(env: Env, userId: string): Promise<SyncUserKeyIds> {
  const response = await authedFetch(env, { path: '/api/sync', userId });
  assert.equal(response.status, 200);
  return await response.json() as SyncUserKeyIds;
}

async function errorMessage(response: Response): Promise<string> {
  const body = await response.json() as { ErrorModel: { Message: string } };
  return body.ErrorModel.Message;
}

test('posting a user key id without an access token is rejected', async () => {
  const env = await createTestEnv();

  const response = await authedFetch(env, { method: 'POST', path: USER_KEY_ID_PATH, body: { userKeyId: RECORDED_KEY_ID } });

  assert.equal(response.status, 401);
});

test('a missing, malformed or uppercase user key id is rejected without being stored', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const rejectedBodies = [
    { body: {}, message: 'The UserKeyId field is required.' },
    { body: { userKeyId: '' }, message: 'The UserKeyId field is required.' },
    { body: { userKeyId: 'not-a-key-id' }, message: 'UserKeyId is not a valid key id.' },
    { body: { userKeyId: RECORDED_KEY_ID.toUpperCase() }, message: 'UserKeyId is not a valid key id.' },
  ];

  for (const { body, message } of rejectedBodies) {
    const response = await authedFetch(env, { method: 'POST', path: USER_KEY_ID_PATH, body, userId: user.id });
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(await errorMessage(response), message);
  }

  const synced = await syncUserKeyIds(env, user.id);
  assert.equal(synced.UserDecryption.UserKeyId, null);
  assert.equal(synced.userDecryption.userKeyId, null);
});

test('a recorded user key id reaches the next sync despite the sync cache and is never overwritten', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  // Prime the sync cache, as the CLI does with fullSync(true) right before the backfill.
  assert.equal((await syncUserKeyIds(env, user.id)).UserDecryption.UserKeyId, null);

  const recorded = await authedFetch(env, { method: 'POST', path: USER_KEY_ID_PATH, body: { userKeyId: RECORDED_KEY_ID }, userId: user.id });
  assert.equal(recorded.status, 200);
  assert.equal(await recorded.text(), '');

  const afterBackfill = await syncUserKeyIds(env, user.id);
  assert.equal(afterBackfill.UserDecryption.UserKeyId, RECORDED_KEY_ID);
  assert.equal(afterBackfill.userDecryption.userKeyId, RECORDED_KEY_ID);

  const competing = await authedFetch(env, { method: 'POST', path: USER_KEY_ID_PATH, body: { userKeyId: COMPETING_KEY_ID }, userId: user.id });
  assert.equal(competing.status, 400);
  assert.equal(await errorMessage(competing), 'User key id is already set.');
  assert.equal((await syncUserKeyIds(env, user.id)).UserDecryption.UserKeyId, RECORDED_KEY_ID);
});

test('a PascalCase UserKeyId body is accepted like the camelCase one', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);

  const recorded = await authedFetch(env, { method: 'POST', path: USER_KEY_ID_PATH, body: { UserKeyId: RECORDED_KEY_ID }, userId: user.id });

  assert.equal(recorded.status, 200);
  assert.equal((await syncUserKeyIds(env, user.id)).UserDecryption.UserKeyId, RECORDED_KEY_ID);
});
