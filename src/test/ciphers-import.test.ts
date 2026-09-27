import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { ciphers, folders } from '../db/schema';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const ENC = '2.dGVzdA==|dGVzdA==|dGVzdA==';

test('cipher import accepts PascalCase bodies, files ciphers into imported folders and defaults absent fields', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/ciphers/import?returnCipherMap=1',
    userId: user.id,
    body: {
      Folders: [{ Name: ENC }],
      Ciphers: [
        { Id: ' source-1 ', Type: 1, Name: ENC, Login: { Username: ENC, Uris: [{ Uri: ENC }] }, ClientOnly: 'kept' },
      ],
      FolderRelationships: [{ Key: 0, Value: 0 }],
    },
  });
  assert.equal(response.status, 200);
  const { cipherMap } = (await response.json()) as {
    cipherMap: Array<{ index: number; sourceId: string | null; id: string }>;
  };
  assert.equal(cipherMap[0].sourceId, 'source-1');

  const row = await getOrm(env.DB)
    .select({ folderId: ciphers.folderId, data: ciphers.data })
    .from(ciphers)
    .where(eq(ciphers.id, cipherMap[0].id))
    .get();
  const folder = await getOrm(env.DB).select({ id: folders.id }).from(folders).where(eq(folders.userId, user.id)).get();
  assert.equal(row?.folderId, folder?.id);
  const data = JSON.parse(row?.data ?? '{}');
  assert.equal(data.clientOnly, 'kept');
  assert.deepEqual([data.notes, data.favorite, data.reprompt, data.card, data.fields], [null, false, 0, null, null]);
  assert.deepEqual(data.login.uris, [{ uri: ENC, uriChecksum: null, match: null }]);
  assert.equal(data.login.password, null);
});

test('cipher import rejects malformed entries before writing anything', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/ciphers/import',
    userId: user.id,
    body: { folders: [{ name: ENC }], ciphers: [{ name: ENC }], folderRelationships: [] },
  });
  assert.equal(response.status, 400);
  const { validationErrors } = (await response.json()) as { validationErrors: Record<string, string[]> };
  assert.deepEqual(Object.keys(validationErrors), ['ciphers.0.type']);
  assert.equal(await getOrm(env.DB).$count(folders, eq(folders.userId, user.id)), 0);
});
