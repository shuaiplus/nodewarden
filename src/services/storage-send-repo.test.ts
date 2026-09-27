import assert from 'node:assert/strict';
import test from 'node:test';

import { createTestEnv, seedUser } from '../test/support/env';
import { SendAuthType, SendType } from '../types';
import { getSend, incrementSendAccessCount, saveSend } from './storage-send-repo';

const DAY_MS = 86_400_000;

test('a Send access counts only while the Send is under its maximum access count', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const now = new Date().toISOString();
  for (const [id, maxAccessCount, accepted] of [['capped', 2, [true, true, false]], ['unlimited', null, [true, true, true]]] as const) {
    await saveSend(env.DB, {
      id, userId: user.id, type: SendType.Text, name: 'name', notes: null, data: '{}', key: 'key', passwordHash: null, passwordSalt: null,
      passwordIterations: null, authType: SendAuthType.None, emails: null, maxAccessCount, accessCount: 0, disabled: false, hideEmail: null,
      createdAt: now, updatedAt: now, expirationDate: null, deletionDate: new Date(Date.now() + DAY_MS).toISOString(),
    });
    for (const expected of accepted) assert.equal(await incrementSendAccessCount(env.DB, id), expected, id);
    assert.equal((await getSend(env.DB, id))?.accessCount, accepted.filter(Boolean).length, id);
  }
});
