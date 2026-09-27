import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { D1_MAX_BOUND_PARAMETERS, getOrm } from '../db/client';
import { ciphers, folders } from '../db/schema';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const PAST = '2020-01-01T00:00:00.000Z';

test('folder deletes unfile the user\'s personal ciphers by column or either JSON key, chunked within D1\'s parameter cap', async () => {
  const env = await createTestEnv();
  const orm = getOrm(env.DB);
  const user = await seedUser(env);
  const other = await seedUser(env);
  const single = crypto.randomUUID();
  const bulk = crypto.randomUUID();
  await orm.insert(folders).values([single, bulk].map((id) => ({ id, userId: user.id, name: 'enc', createdAt: PAST, updatedAt: PAST })));
  const addCipher = async (filed: Record<string, string>, row: { userId?: string; organizationId?: string; folderId?: string } = {}) => {
    const id = crypto.randomUUID();
    const data = JSON.stringify({ ...filed, updatedAt: PAST, revisionDate: PAST, name: 'enc' });
    await orm.insert(ciphers).values({ id, userId: user.id, type: 1, data, createdAt: PAST, updatedAt: PAST, ...row });
    return id;
  };
  const camelCase = await addCipher({ folderId: single });
  const snakeCase = await addCipher({ folder_id: bulk });
  const column = await addCipher({}, { folderId: bulk });
  const organization = await addCipher({ folderId: bulk }, { organizationId: crypto.randomUUID(), folderId: bulk });
  const foreign = await addCipher({ folderId: bulk }, { userId: other.id, folderId: bulk });

  assert.equal((await authedFetch(env, { method: 'DELETE', path: `/api/folders/${single}`, userId: user.id })).status, 204);
  const ids = [bulk, ...Array.from({ length: D1_MAX_BOUND_PARAMETERS }, () => crypto.randomUUID())];
  assert.equal((await authedFetch(env, { method: 'POST', path: '/api/folders/delete', userId: user.id, body: { ids } })).status, 204);

  const filing = (id: string) => orm.select({ folderId: ciphers.folderId, data: ciphers.data }).from(ciphers).where(eq(ciphers.id, id)).get();
  for (const id of [camelCase, snakeCase, column]) assert.deepEqual(await filing(id), { folderId: null, data: '{"name":"enc"}' });
  for (const id of [organization, foreign]) assert.equal((await filing(id))?.folderId, bulk);
  assert.deepEqual(await orm.select({ id: folders.id }).from(folders), []);
});
