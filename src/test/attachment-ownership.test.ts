import assert from 'node:assert/strict';
import test from 'node:test';

import { D1_MAX_BOUND_PARAMETERS, getOrm } from '../db/client';
import { ciphers } from '../db/schema';
import * as attachmentRepo from '../services/storage-attachment-repo';
import type { Env } from '../types';
import { createTestEnv, seedUser } from './support/env';

const PAST = '2020-01-01T00:00:00.000Z';

async function addCipher(env: Env, userId: string, organizationId: string | null = null) {
  const id = crypto.randomUUID();
  await getOrm(env.DB)
    .insert(ciphers)
    .values({ id, userId, organizationId, type: 1, data: '{}', createdAt: PAST, updatedAt: PAST });
  return id;
}

async function attach(env: Env, cipherId: string, id: string = crypto.randomUUID()) {
  await attachmentRepo.saveAttachment(env.DB, { id, cipherId, fileName: 'f', size: 1, sizeName: '1 Bytes', key: null });
  return id;
}

test("attachment saves, moves and deletes stay within one user's personal ciphers", async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const other = await seedUser(env);
  const first = await addCipher(env, owner.id);
  const second = await addCipher(env, owner.id);
  const foreign = await addCipher(env, other.id);
  const organization = await addCipher(env, owner.id, crypto.randomUUID());
  const cipherOf = async (...ids: string[]) =>
    Promise.all(ids.map(async (id) => (await attachmentRepo.getAttachment(env.DB, id))?.cipherId ?? null));

  // Re-saving an existing id moves it between the owner's ciphers, never onto another user's.
  const moved = await attach(env, first);
  await attach(env, second, moved);
  await attach(env, foreign, moved);
  assert.deepEqual(await cipherOf(moved), [second]);

  // Moving needs both the current and the target cipher to be the user's personal ciphers.
  const organizationAttachment = await attach(env, organization);
  const foreignAttachment = await attach(env, foreign);
  for (const [attachmentId, target] of [
    [moved, foreign],
    [moved, organization],
    [organizationAttachment, first],
    [foreignAttachment, first],
  ]) {
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

test('bulk attachment reads and deletes take more ids than one D1 statement can bind', async () => {
  const env = await createTestEnv();
  const cipherId = await addCipher(env, (await seedUser(env)).id);
  const attachmentId = await attach(env, cipherId);
  const unknownIds = Array.from({ length: D1_MAX_BOUND_PARAMETERS }, () => crypto.randomUUID());
  const read = await attachmentRepo.getAttachmentsByCipherIds(env.DB, [...unknownIds, cipherId]);
  assert.deepEqual(
    read.get(cipherId)?.map(({ id }) => id),
    [attachmentId],
  );
  await attachmentRepo.bulkDeleteAttachmentsByIds(env.DB, [...unknownIds, attachmentId]);
  assert.equal(await attachmentRepo.getAttachment(env.DB, attachmentId), null);
});
