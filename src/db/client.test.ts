import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { DrizzleQueryError, eq, type SQL } from 'drizzle-orm';

import { createTestEnv, seedUser } from '../test/support/env';
import { abortUnlessChanged, getOrm, userRowMatches, withoutQueryParams } from './client';
import { users } from './schema';
import { SINGLE_ROW } from './sql';

test('abortUnlessChanged rolls a batch back only when the guarded write matched no rows', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  const rename = (id: string, name: string) => orm.update(users).set({ name }).where(eq(users.id, id));
  await assert.rejects(orm.batch([rename(user.id, 'Lost'), rename('missing', 'Nobody'), abortUnlessChanged(orm, 'stale')]), /malformed JSON|JSON/i);
  assert.equal((await orm.select({ name: users.name }).from(users).where(eq(users.id, user.id)).get())?.name, user.name);
  await orm.batch([rename(user.id, 'Kept'), abortUnlessChanged(orm, 'stale')]);
  assert.equal((await orm.select({ name: users.name }).from(users).where(eq(users.id, user.id)).get())?.name, 'Kept');
});

test('userRowMatches holds only while the user row exists and meets every given condition', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  const holds = async (userId: string, ...conditions: (SQL | undefined)[]) =>
    (await orm.select({ holds: userRowMatches(orm, userId, ...conditions).mapWith(Boolean) }).from(SINGLE_ROW).get())?.holds;
  assert.equal(await holds(user.id), true);
  assert.equal(await holds(user.id, eq(users.securityStamp, user.securityStamp), undefined), true);
  assert.equal(await holds(user.id, eq(users.securityStamp, 'rotated-elsewhere')), false);
  assert.equal(await holds('missing-user'), false);
});

test('withoutQueryParams keeps the statement and driver error but never the bound values', async () => {
  const secret = 'p@ssw0rd-hash-value';
  const failure = new DrizzleQueryError('update "users" set "master_password_hash" = ?', [secret], new Error('D1_ERROR: disk full'));
  const logged = withoutQueryParams(failure) as Error;
  assert.equal(logged.message, 'Failed query: update "users" set "master_password_hash" = ?');
  assert.equal((logged.cause as Error).message, 'D1_ERROR: disk full');
  assert.doesNotMatch(inspect(logged, { depth: 5 }), new RegExp(secret));
  const plain = new Error('unrelated');
  assert.equal(withoutQueryParams(plain), plain);
});
