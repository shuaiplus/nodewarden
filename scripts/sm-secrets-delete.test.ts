import assert from 'node:assert/strict';
import test from 'node:test';

import * as smRepo from '../src/services/storage-secret-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, seedSmOrg } from './support/sm';

async function createSecret(env: Env, orgId: string, owner: User): Promise<string> {
  const created = await authedFetch(env, {
    method: 'POST',
    path: `/api/organizations/${orgId}/secrets`,
    body: { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD, projectIds: [] },
    userId: owner.id,
  });
  assert.equal(created.status, 200);
  return (await created.json() as { id: string }).id;
}

// Official web and the SDK (`bws secret delete`) post the ids as a bare JSON array, as upstream's
// `[FromBody] List<Guid> ids` binds them.
test('an owner deleting [id] soft-deletes the secret and gets a BulkDeleteResponseModel list', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const secretId = await createSecret(env, orgId, owner);

  const deleted = await authedFetch(env, { method: 'POST', path: '/api/secrets/delete', body: [secretId], userId: owner.id });
  assert.equal(deleted.status, 200);
  assert.deepEqual(await deleted.json(), {
    data: [{ id: secretId, error: null, object: 'BulkDeleteResponseModel' }],
    object: 'list',
    continuationToken: null,
  });
  assert.notEqual((await smRepo.getSecret(env.DB, secretId))?.deletedAt ?? null, null);
});

const INVALID_BODIES = [
  ['an {ids} object', (id: string) => ({ ids: [id] })],
  ['a non-id element', () => [{}]],
  ['a non-GUID id', () => ['not-a-guid']],
  // No body at all, so the JSON parse itself fails.
  ['no JSON', () => undefined],
] as const;

for (const [shape, body] of INVALID_BODIES) {
  test(`a delete body with ${shape} is 400 and deletes nothing`, async () => {
    const env = await createTestEnv();
    const { orgId, owner } = await seedSmOrg(env);
    const secretId = await createSecret(env, orgId, owner);

    const deleted = await authedFetch(env, { method: 'POST', path: '/api/secrets/delete', body: body(secretId), userId: owner.id });
    assert.equal(deleted.status, 400);
    assert.equal((await smRepo.getSecret(env.DB, secretId))?.deletedAt, null);
  });
}
