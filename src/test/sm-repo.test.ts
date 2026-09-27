import assert from 'node:assert/strict';
import test from 'node:test';

import { columnCount, D1_MAX_BOUND_PARAMETERS } from '../db/client';
import { smSecretProjects } from '../db/schema';
import * as smRepo from '../services/storage-secret-repo';
import type { Env } from '../types';
import { createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, seedSmOrg } from './support/sm';

// One link more than a single INSERT holds for the narrower link table, so every writer chunks.
const MANY_PROJECT_COUNT = Math.floor(D1_MAX_BOUND_PARAMETERS / columnCount(smSecretProjects)) + 1;

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
  const now = new Date().toISOString();
  const projects = Array.from({ length: MANY_PROJECT_COUNT + 1 }, () => ({ id: crypto.randomUUID(), orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now }));
  await Promise.all(projects.map((project) => smRepo.saveProject(env.DB, project)));
  const [firstProjectId, ...manyProjectIds] = projects.map(({ id }) => id);
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

// More ids than one statement can bind, so every id-list statement must chunk around its own fixed parameters.
const BULK_ID_COUNT = D1_MAX_BOUND_PARAMETERS + D1_MAX_BOUND_PARAMETERS / 2;

const seedProjects = (env: Env, orgId: string, ids: string[], now: string) =>
  Promise.all(ids.map((id) => smRepo.saveProject(env.DB, { id, orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now })));
const seedServiceAccounts = (env: Env, orgId: string, ids: string[], now: string) =>
  Promise.all(ids.map((id) => smRepo.saveServiceAccount(env.DB, { id, orgId, name: ENCRYPTED_FIELD, createdAt: now, updatedAt: now })));
const seedSecrets = (env: Env, orgId: string, ids: string[], now: string, deletedAt: string | null) =>
  Promise.all(ids.map((id) => smRepo.saveSecret(env.DB, { id, orgId, key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: null, projectIds: [], createdAt: now, updatedAt: now, deletedAt })));
const idsOf = (rows: { id: string }[]) => rows.map(({ id }) => id);

// Each operation seeds a row per id, reaches them all in one call and returns the ids it read or changed.
const BULK_OPERATIONS: [string, (env: Env, orgId: string, ids: string[], now: string) => Promise<string[]>][] = [
  ['projectsInOrg', async (env, orgId, ids, now) => {
    await seedProjects(env, orgId, ids, now);
    return [...await smRepo.projectsInOrg(env.DB, orgId, ids)];
  }],
  ['getProjectsByIds', async (env, orgId, ids, now) => {
    await seedProjects(env, orgId, ids, now);
    return idsOf(await smRepo.getProjectsByIds(env.DB, ids));
  }],
  ['deleteProjects', async (env, orgId, ids, now) => {
    await seedProjects(env, orgId, ids, now);
    return smRepo.deleteProjects(env.DB, orgId, ids);
  }],
  ['getSecretsByIds', async (env, orgId, ids, now) => {
    await seedSecrets(env, orgId, ids, now, null);
    return idsOf(await smRepo.getSecretsByIds(env.DB, ids));
  }],
  ['deleteSecrets', async (env, orgId, ids, now) => {
    await seedSecrets(env, orgId, ids, now, null);
    return smRepo.deleteSecrets(env.DB, orgId, ids);
  }],
  ['changeSecretsTrash restore', async (env, orgId, ids, now) => {
    await seedSecrets(env, orgId, ids, now, now);
    return smRepo.changeSecretsTrash(env.DB, orgId, ids, true);
  }],
  ['changeSecretsTrash empty', async (env, orgId, ids, now) => {
    await seedSecrets(env, orgId, ids, now, now);
    return smRepo.changeSecretsTrash(env.DB, orgId, ids, false);
  }],
  ['getServiceAccountsByIds', async (env, orgId, ids, now) => {
    await seedServiceAccounts(env, orgId, ids, now);
    return idsOf(await smRepo.getServiceAccountsByIds(env.DB, ids));
  }],
  ['deleteServiceAccounts', async (env, orgId, ids, now) => {
    await seedServiceAccounts(env, orgId, ids, now);
    return smRepo.deleteServiceAccounts(env.DB, orgId, ids);
  }],
  ['revokeAccessTokens', async (env, orgId, ids, now) => {
    const serviceAccountId = crypto.randomUUID();
    await seedServiceAccounts(env, orgId, [serviceAccountId], now);
    await Promise.all(ids.map((id) => smRepo.saveAccessToken(env.DB, { id, serviceAccountId, name: ENCRYPTED_FIELD, clientSecretHash: 'hash', expireAt: null, revokedAt: null, createdAt: now })));
    await smRepo.revokeAccessTokens(env.DB, serviceAccountId, ids);
    const remaining = new Set(idsOf(await smRepo.listAccessTokens(env.DB, serviceAccountId)));
    return ids.filter((id) => !remaining.has(id));
  }],
];

for (const [operation, reachAll] of BULK_OPERATIONS) {
  test(`${operation} reaches ${BULK_ID_COUNT} ids in chunks within the D1 parameter cap`, async () => {
    const env = await createTestEnv();
    const { orgId } = await seedSmOrg(env);
    const ids = Array.from({ length: BULK_ID_COUNT }, () => crypto.randomUUID());
    assert.deepEqual(new Set(await reachAll(env, orgId, ids, new Date().toISOString())), new Set(ids));
  });
}
