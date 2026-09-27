import assert from 'node:assert/strict';
import test from 'node:test';
import { inArray } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { usedAttachmentDownloadTokens } from '../db/schema';
import { bound } from '../db/sql';
import { D1_MAX_BOUND_PARAMETERS } from './support/d1-sqlite';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('authenticated sync through the Worker returns the seeded profile', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);

  const response = await authedFetch(env, { path: '/api/sync', userId: user.id });

  assert.equal(response.status, 200);
  const body = (await response.json()) as { profile: { id: string } };
  assert.equal(body.profile.id, user.id);
});

test('sync without an access token is rejected', async () => {
  const env = await createTestEnv();

  const response = await authedFetch(env, { path: '/api/sync' });

  assert.equal(response.status, 401);
});

test('the SQLite D1 keeps D1 batch atomicity, INTEGER binding and the bound-parameter cap', async () => {
  const orm = getOrm((await createTestEnv()).DB);
  // A TEXT primary key: bound as INTEGER, 1 is stored as '1'; bound as REAL it would be '1.0'.
  const insert = (jti: unknown) => orm.insert(usedAttachmentDownloadTokens).values({ jti: bound(jti), expiresAt: 0 });

  await assert.rejects(orm.batch([insert('kept'), insert(true), insert('kept')]), /UNIQUE constraint failed/);
  assert.equal(await orm.$count(usedAttachmentDownloadTokens), 0);

  await insert(1);
  assert.deepEqual(
    await orm.select({ jti: usedAttachmentDownloadTokens.jti }).from(usedAttachmentDownloadTokens).values(),
    [['1']],
  );

  const tooManyBindings = D1_MAX_BOUND_PARAMETERS + 1;
  const overCap = orm
    .select()
    .from(usedAttachmentDownloadTokens)
    .where(inArray(usedAttachmentDownloadTokens.jti, Array(tooManyBindings).fill('probe')));
  // drizzle wraps a failed direct query; the D1 error is its cause.
  await assert.rejects(overCap, (error: Error) => /too many SQL variables/.test(String(error.cause)));
});
