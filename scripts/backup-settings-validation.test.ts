import assert from 'node:assert/strict';
import test from 'node:test';

import { hashPassword } from '../src/services/auth-password';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const PASSWORD = 'client-derived-password-hash';

test('backup settings saves answer the first rule broken with every issue under its path', async () => {
  const env = await createTestEnv();
  const admin = await seedUser(env, { role: 'admin', masterPasswordHash: await hashPassword(PASSWORD) });
  const save = (body: unknown) => authedFetch(env, { method: 'PUT', path: '/api/admin/backup/settings', userId: admin.id, body });

  const notAnObject = await save([]);
  assert.equal(notAnObject.status, 400);
  assert.equal((await notAnObject.json() as { message: string }).message, 'Backup settings payload is invalid');

  const invalid = await save({
    masterPasswordHash: PASSWORD,
    destinations: [{ id: 'd1', type: 'webdav', schedule: { enabled: true, intervalHours: 0, startTime: '25:00' }, destination: {} }],
  });
  assert.equal(invalid.status, 400);
  const { message, validationErrors } = await invalid.json() as { message: string; validationErrors: Record<string, string[]> };
  assert.deepEqual({ message, validationErrors }, {
    message: 'Backup interval hours must be between 1 and 99',
    validationErrors: {
      'destinations.0.schedule.intervalHours': ['Backup interval hours must be between 1 and 99'],
      'destinations.0.schedule.startTime': ['Backup start time must be in HH:mm format'],
      'destinations.0.destination.baseUrl': ['WebDAV server URL is required'],
      'destinations.0.destination.username': ['WebDAV username is required'],
      'destinations.0.destination.password': ['WebDAV password is required'],
    },
  });
});
