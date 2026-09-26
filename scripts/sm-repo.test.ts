import assert from 'node:assert/strict';
import test from 'node:test';

import { columnCount, D1_MAX_BOUND_PARAMETERS } from '../src/db/client';
import { smSecretProjects } from '../src/db/schema';
import * as smRepo from '../src/services/storage-secret-repo';
import type { Env } from '../src/types';
import { createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, seedSmOrg } from './support/sm';

// One link more than a single INSERT holds for the narrower link table, so every writer chunks.
const MANY_PROJECT_COUNT = Math.floor(D1_MAX_BOUND_PARAMETERS / columnCount(smSecretProjects)) + 1;

async function seedProjects(env: Env, orgId: string, count: number): Promise<string[]> {
  const now = new Date().toISOString();
  const projects = Array.from({ length: count }, () => ({ id: crypto.randomUUID(), orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now }));
  await Promise.all(projects.map((project) => smRepo.saveProject(env.DB, project)));
  return projects.map(({ id }) => id);
}

// Each writer replaces a target's project links. A secret save also rewrites the secret, and
// clears its note, so a save that fails must leave the row as well as the links untouched.
const LINK_WRITERS = [
  ['saveSecret', async (env: Env, orgId: string, projectIds: string[]) => {
    const now = new Date().toISOString();
    const secret = { id: crypto.randomUUID(), orgId, key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD, projectIds, createdAt: now, updatedAt: now, deletedAt: null };
    await smRepo.saveSecret(env.DB, secret);
    return {
      write: (nextProjectIds: string[]) => smRepo.saveSecret(env.DB, { ...secret, note: null, projectIds: nextProjectIds }),
      read: async () => {
        const saved = await smRepo.getSecret(env.DB, secret.id);
        return { ...saved, projectIds: new Set(saved?.projectIds) };
      },
    };
  }],
  ['replaceServiceAccountProjects', async (env: Env, orgId: string, projectIds: string[]) => {
    const now = new Date().toISOString();
    const account = { id: crypto.randomUUID(), orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now };
    await smRepo.saveServiceAccount(env.DB, account);
    await smRepo.replaceServiceAccountProjects(env.DB, account.id, projectIds);
    return {
      write: (nextProjectIds: string[]) => smRepo.replaceServiceAccountProjects(env.DB, account.id, nextProjectIds),
      read: async () => ({ projectIds: new Set(await smRepo.listReadableServiceAccountProjectIds(env.DB, account.id)) }),
    };
  }],
] as const;

async function seedLinkedTarget(seedTarget: typeof LINK_WRITERS[number][1]) {
  const env = await createTestEnv();
  const { orgId } = await seedSmOrg(env);
  const [firstProjectId, ...manyProjectIds] = await seedProjects(env, orgId, MANY_PROJECT_COUNT + 1);
  return { target: await seedTarget(env, orgId, [firstProjectId]), manyProjectIds };
}

for (const [writer, seedTarget] of LINK_WRITERS) {
  test(`${writer} replaces one project link with ${MANY_PROJECT_COUNT}`, async () => {
    const { target, manyProjectIds } = await seedLinkedTarget(seedTarget);
    await target.write(manyProjectIds);
    assert.deepEqual((await target.read()).projectIds, new Set(manyProjectIds));
  });

  // D1 runs a batch as one transaction, so a link failing in the last chunk also undoes the
  // earlier chunks and the delete of the previous links.
  test(`${writer} with a missing project in its last chunk leaves the previous links intact`, async () => {
    const { target, manyProjectIds } = await seedLinkedTarget(seedTarget);
    const before = await target.read();
    await assert.rejects(target.write([...manyProjectIds, crypto.randomUUID()]), /FOREIGN KEY/);
    assert.deepEqual(await target.read(), before);
  });
}
