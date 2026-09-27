import assert from 'node:assert/strict';
import { test } from 'node:test';
import { inspect } from 'node:util';
import { DrizzleQueryError, and, eq, inArray, type SQL } from 'drizzle-orm';

import { createTestEnv, seedUser } from '../test/support/env';
import {
  D1_MAX_BOUND_PARAMETERS,
  abortUnlessChanged,
  getOrm,
  statementChunks,
  userRowMatches,
  withoutQueryParams,
} from './client';
import { ciphers, users } from './schema';
import { SINGLE_ROW, jsonExtract } from './sql';

test('abortUnlessChanged rolls a batch back only when the guarded write matched no rows', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  const rename = (id: string, name: string) => orm.update(users).set({ name }).where(eq(users.id, id));
  await assert.rejects(
    orm.batch([rename(user.id, 'Lost'), rename('missing', 'Nobody'), abortUnlessChanged(orm, 'stale')]),
    /malformed JSON|JSON/i,
  );
  assert.equal(
    (await orm.select({ name: users.name }).from(users).where(eq(users.id, user.id)).get())?.name,
    user.name,
  );
  await orm.batch([rename(user.id, 'Kept'), abortUnlessChanged(orm, 'stale')]);
  assert.equal((await orm.select({ name: users.name }).from(users).where(eq(users.id, user.id)).get())?.name, 'Kept');
});

test('userRowMatches holds only while the user row exists and meets every given condition', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  const holds = async (userId: string, ...conditions: (SQL | undefined)[]) =>
    (
      await orm
        .select({ holds: userRowMatches(orm, userId, ...conditions).mapWith(Boolean) })
        .from(SINGLE_ROW)
        .get()
    )?.holds;
  assert.equal(await holds(user.id), true);
  assert.equal(await holds(user.id, eq(users.securityStamp, user.securityStamp), undefined), true);
  assert.equal(await holds(user.id, eq(users.securityStamp, 'rotated-elsewhere')), false);
  assert.equal(await holds('missing-user'), false);
});

test('statementChunks fills each chunk up to the parameter cap, counting what the statement binds besides its items', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const orm = getOrm(env.DB);
  // The NULL in SET, the user id and the JSON path left of IN all bind; an empty render would drop the path.
  const unfile = (chunk: string[]) =>
    orm
      .update(ciphers)
      .set({ folderId: null })
      .where(and(eq(ciphers.userId, user.id), inArray(jsonExtract(ciphers.data, '$.folderId'), chunk)));
  const ids = Array.from({ length: 250 }, (_, index) => `folder-${index}`);
  const chunks = statementChunks(ids, unfile);
  assert.deepEqual(chunks.flat(), ids);
  assert.ok(chunks.every((chunk) => unfile(chunk).toSQL().params.length <= D1_MAX_BOUND_PARAMETERS));
  assert.ok(unfile(ids.slice(0, chunks[0].length + 1)).toSQL().params.length > D1_MAX_BOUND_PARAMETERS);
  const statements = chunks.map(unfile);
  await orm.batch(statements as [(typeof statements)[0], ...typeof statements]);
  assert.deepEqual(statementChunks([], unfile), []);
  assert.deepEqual(statementChunks(['only'], unfile), [['only']]);
  assert.throws(() => statementChunks(ids, () => orm.select().from(users)), /binds nothing per item/);
});

test('withoutQueryParams keeps the statement and driver error but never the bound values', async () => {
  const secret = 'p@ssw0rd-hash-value';
  const failure = new DrizzleQueryError(
    'update "users" set "master_password_hash" = ?',
    [secret],
    new Error('D1_ERROR: disk full'),
  );
  const logged = withoutQueryParams(failure) as Error;
  assert.equal(logged.message, 'Failed query: update "users" set "master_password_hash" = ?');
  assert.equal((logged.cause as Error).message, 'D1_ERROR: disk full');
  assert.doesNotMatch(inspect(logged, { depth: 5 }), new RegExp(secret));
  const plain = new Error('unrelated');
  assert.equal(withoutQueryParams(plain), plain);
});
