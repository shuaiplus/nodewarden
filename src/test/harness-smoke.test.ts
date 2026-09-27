import assert from 'node:assert/strict';
import test from 'node:test';

import { D1_MAX_BOUND_PARAMETERS } from './support/d1-sqlite';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('authenticated sync through the Worker returns the seeded profile', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);

  const response = await authedFetch(env, { path: '/api/sync', userId: user.id });

  assert.equal(response.status, 200);
  const body = await response.json() as { profile: { id: string } };
  assert.equal(body.profile.id, user.id);
});

test('sync without an access token is rejected', async () => {
  const env = await createTestEnv();

  const response = await authedFetch(env, { path: '/api/sync' });

  assert.equal(response.status, 401);
});

test('the SQLite D1 keeps D1 batch atomicity, INTEGER binding and the bound-parameter cap', async () => {
  const { DB } = await createTestEnv();
  await DB.exec('CREATE TABLE probe (id INTEGER PRIMARY KEY, label TEXT UNIQUE)');
  const insert = DB.prepare('INSERT INTO probe (label) VALUES (?)');

  await assert.rejects(DB.batch([insert.bind('kept'), insert.bind(true), insert.bind('kept')]), /UNIQUE constraint failed/);
  assert.equal(await DB.prepare('SELECT count(*) AS total FROM probe').first('total'), 0);

  await insert.bind(1).run();
  assert.deepEqual(await DB.prepare('SELECT label FROM probe').raw(), [['1']]);

  const tooManyBindings = D1_MAX_BOUND_PARAMETERS + 1;
  const placeholders = Array.from({ length: tooManyBindings }, () => '?').join(', ');
  await assert.rejects(DB.prepare(`SELECT ${placeholders}`).bind(...Array(tooManyBindings).fill(0)).all(), /too many SQL variables/);
});
