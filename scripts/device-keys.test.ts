import assert from 'node:assert/strict';
import test from 'node:test';

import { authedFetch, createTestEnv, seedUser } from './support/env';

test('device registration validates its fields and a key update keeps the keys it leaves out', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);

  const missingType = await authedFetch(env, { method: 'POST', path: '/api/devices', userId: user.id, body: { identifier: 'device-1', name: 'Phone' } });
  assert.equal(missingType.status, 400);
  assert.equal((await missingType.json() as { message: string }).message, 'Device identifier and type are required');

  const registered = await authedFetch(env, {
    method: 'POST', path: '/api/devices', userId: user.id,
    body: { Identifier: 'device-1', Name: 'Phone', Type: 0, EncryptedUserKey: '4.user', EncryptedPublicKey: '2.iv|data|mac' },
  });
  assert.equal(registered.status, 200);
  const { type, encryptedUserKey, encryptedPublicKey } = await registered.json() as Record<string, unknown>;
  assert.deepEqual({ type, encryptedUserKey, encryptedPublicKey }, { type: 0, encryptedUserKey: '4.user', encryptedPublicKey: '2.iv|data|mac' });

  const updated = await authedFetch(env, { method: 'PUT', path: '/api/devices/device-1/keys', userId: user.id, body: { encryptedUserKey: null } });
  const device = await updated.json() as { encryptedUserKey: string | null; encryptedPublicKey: string | null };
  assert.equal(device.encryptedUserKey, null);
  assert.equal(device.encryptedPublicKey, '2.iv|data|mac');
});
