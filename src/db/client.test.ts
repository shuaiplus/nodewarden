import assert from 'node:assert/strict';
import { test } from 'node:test';
import { eq } from 'drizzle-orm';

import { createTestEnv, seedUser } from '../test/support/env';
import { abortUnlessChanged, getOrm } from './client';
import { users } from './schema';

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
