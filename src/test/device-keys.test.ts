import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { D1_MAX_BOUND_PARAMETERS, getOrm } from '../db/client';
import { devices } from '../db/schema';
import * as deviceRepo from '../services/storage-device-repo';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('device registration validates its fields and a key update keeps the keys it leaves out', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);

  const missingType = await authedFetch(env, {
    method: 'POST',
    path: '/api/devices',
    userId: user.id,
    body: { identifier: 'device-1', name: 'Phone' },
  });
  assert.equal(missingType.status, 400);
  assert.equal(((await missingType.json()) as { message: string }).message, 'Device identifier and type are required');

  const registered = await authedFetch(env, {
    method: 'POST',
    path: '/api/devices',
    userId: user.id,
    body: {
      Identifier: 'device-1',
      Name: 'Phone',
      Type: 0,
      EncryptedUserKey: '4.user',
      EncryptedPublicKey: '2.iv|data|mac',
    },
  });
  assert.equal(registered.status, 200);
  const { type, encryptedUserKey, encryptedPublicKey } = (await registered.json()) as Record<string, unknown>;
  assert.deepEqual(
    { type, encryptedUserKey, encryptedPublicKey },
    { type: 0, encryptedUserKey: '4.user', encryptedPublicKey: '2.iv|data|mac' },
  );

  const updated = await authedFetch(env, {
    method: 'PUT',
    path: '/api/devices/device-1/keys',
    userId: user.id,
    body: { encryptedUserKey: null },
  });
  const device = (await updated.json()) as { encryptedUserKey: string | null; encryptedPublicKey: string | null };
  assert.equal(device.encryptedUserKey, null);
  assert.equal(device.encryptedPublicKey, '2.iv|data|mac');
});

test('re-registering a device keeps its session stamp and the keys it leaves out, filling only an empty stamp', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const stored = async () => {
    const device = await deviceRepo.getDevice(env.DB, user.id, 'device-1');
    return {
      sessionStamp: device?.sessionStamp,
      keys: [device?.encryptedUserKey, device?.encryptedPublicKey, device?.encryptedPrivateKey],
    };
  };
  await deviceRepo.upsertDevice(env.DB, user.id, 'device-1', 'Phone', 0, 'stamp-1', {
    encryptedUserKey: '4.user',
    encryptedPublicKey: '2.public',
    encryptedPrivateKey: '2.private',
  });
  await deviceRepo.upsertDevice(env.DB, user.id, 'device-1', 'Phone', 0, 'stamp-2');
  assert.deepEqual(await stored(), { sessionStamp: 'stamp-1', keys: ['4.user', '2.public', '2.private'] });
  await deviceRepo.upsertDevice(env.DB, user.id, 'device-1', 'Phone', 0, undefined, { encryptedUserKey: '4.rotated' });
  assert.deepEqual(await stored(), { sessionStamp: 'stamp-1', keys: ['4.rotated', '2.public', '2.private'] });

  for (const [emptied, next] of [
    [null, 'stamp-3'],
    ['', 'stamp-4'],
  ] as const) {
    await getOrm(env.DB).update(devices).set({ sessionStamp: emptied }).where(eq(devices.deviceIdentifier, 'device-1'));
    await deviceRepo.upsertDevice(env.DB, user.id, 'device-1', 'Phone', 0, next);
    assert.equal((await stored()).sessionStamp, next);
  }
});

test('untrusting more devices than one D1 statement can bind clears the keys of every listed device', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  await deviceRepo.upsertDevice(env.DB, user.id, 'device-1', 'Phone', 0, 'stamp-1', {
    encryptedUserKey: '4.user',
    encryptedPublicKey: '2.public',
    encryptedPrivateKey: '2.private',
  });
  const identifiers = [
    ...Array.from({ length: D1_MAX_BOUND_PARAMETERS }, (_, index) => `unknown-${index}`),
    'device-1',
  ];
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/devices/untrust',
    userId: user.id,
    body: { devices: identifiers },
  });
  assert.deepEqual(await response.json(), { success: true, removed: 1 });
  const device = await deviceRepo.getDevice(env.DB, user.id, 'device-1');
  assert.deepEqual(
    [device?.encryptedUserKey, device?.encryptedPublicKey, device?.encryptedPrivateKey],
    [null, null, null],
  );
});
