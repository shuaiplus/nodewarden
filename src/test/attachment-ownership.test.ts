import assert from 'node:assert/strict';
import test from 'node:test';

import { getOrm } from '../db/client';
import { ciphers } from '../db/schema';
import * as attachmentRepo from '../services/storage-attachment-repo';
import { createTestEnv, seedUser } from './support/env';

const PAST = '2020-01-01T00:00:00.000Z';

test('attachment saves, moves and deletes stay within one user\'s personal ciphers', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const other = await seedUser(env);
  const addCipher = async (userId: string, organizationId: string | null = null) => {
    const id = crypto.randomUUID();
    await getOrm(env.DB).insert(ciphers).values({ id, userId, organizationId, type: 1, data: '{}', createdAt: PAST, updatedAt: PAST });
    return id;
  };
  const first = await addCipher(owner.id);
  const second = await addCipher(owner.id);
  const foreign = await addCipher(other.id);
  const organization = await addCipher(owner.id, crypto.randomUUID());
  const attach = async (cipherId: string, id: string = crypto.randomUUID()) => {
    await attachmentRepo.saveAttachment(env.DB, { id, cipherId, fileName: 'f', size: 1, sizeName: '1 Bytes', key: null });
    return id;
  };
  const cipherOf = async (...ids: string[]) => Promise.all(ids.map(async (id) => (await attachmentRepo.getAttachment(env.DB, id))?.cipherId ?? null));

  // Re-saving an existing id moves it between the owner's ciphers, never onto another user's.
  const moved = await attach(first);
  await attach(second, moved);
  await attach(foreign, moved);
  assert.deepEqual(await cipherOf(moved), [second]);

  // Moving needs both the current and the target cipher to be the user's personal ciphers.
  const organizationAttachment = await attach(organization);
  const foreignAttachment = await attach(foreign);
  for (const [attachmentId, target] of [[moved, foreign], [moved, organization], [organizationAttachment, first], [foreignAttachment, first]]) {
    await attachmentRepo.addAttachmentToCipherForUser(env.DB, target, attachmentId, owner.id);
  }
  assert.deepEqual(await cipherOf(moved, organizationAttachment, foreignAttachment), [second, organization, foreign]);
  await attachmentRepo.addAttachmentToCipherForUser(env.DB, first, moved, owner.id);
  assert.deepEqual(await cipherOf(moved), [first]);

  for (const attachmentId of [organizationAttachment, foreignAttachment, moved]) {
    await attachmentRepo.deleteAttachmentForUser(env.DB, attachmentId, owner.id);
  }
  assert.deepEqual(await cipherOf(organizationAttachment, foreignAttachment, moved), [organization, foreign, null]);
});
