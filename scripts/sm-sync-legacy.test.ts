import assert from 'node:assert/strict';
import test from 'node:test';

import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg } from './support/sm';

interface SyncFixture {
  env: Env;
  orgId: string;
  owner: User;
  projectIds: string[];
  // One secret per project, in `projectIds` order, then one outside every project.
  secretIds: string[];
}

interface MachineToken {
  serviceAccountId: string;
  authorization: string;
}

async function seedSyncFixture(): Promise<SyncFixture> {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const createProject = async () => (await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD })).id;
  const projectIds = [await createProject(), await createProject()];
  const createSecret = async (secretProjectIds: string[]) => (await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, {
    key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD, projectIds: secretProjectIds,
  })).id;
  const secretIds = [...await Promise.all(projectIds.map((projectId) => createSecret([projectId]))), await createSecret([])];
  return { env, orgId, owner, projectIds, secretIds };
}

// A token of a new machine account granted `grantedProjectIds`, as the raw `clientId:clientSecret`
// bearer the legacy sync route authenticates.
async function issueMachineToken({ env, orgId, owner }: SyncFixture, grantedProjectIds: string[]): Promise<MachineToken> {
  const { id: serviceAccountId } = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD, projectIds: grantedProjectIds });
  const token = await postJson<{ clientId: string; clientSecret: string }>(env, owner, `/api/service-accounts/${serviceAccountId}/access-tokens`, { name: ENCRYPTED_FIELD });
  return { serviceAccountId, authorization: `Bearer ${token.clientId}:${token.clientSecret}` };
}

async function syncedSecretIds({ env, orgId }: SyncFixture, { authorization }: MachineToken): Promise<string[]> {
  const synced = await authedFetch(env, { path: `/api/organizations/${orgId}/secrets/sync`, headers: { Authorization: authorization } });
  assert.equal(synced.status, 200);
  return (await synced.json() as { secrets: { id: string }[] }).secrets.map((secret) => secret.id);
}

// Upstream lets a machine account read a secret only through a Read policy on it or its project.
test('a machine account with no project grants syncs no secrets', async () => {
  const fixture = await seedSyncFixture();
  assert.deepEqual(await syncedSecretIds(fixture, await issueMachineToken(fixture, [])), []);
});

test('a machine account granted one project syncs only that project\'s secrets', async () => {
  const fixture = await seedSyncFixture();
  const token = await issueMachineToken(fixture, [fixture.projectIds[0]]);
  assert.deepEqual(await syncedSecretIds(fixture, token), [fixture.secretIds[0]]);
});

test('a project grant without read access syncs nothing', async () => {
  const fixture = await seedSyncFixture();
  const token = await issueMachineToken(fixture, [fixture.projectIds[0]]);
  await fixture.env.DB.prepare('UPDATE sm_service_account_projects SET read_access = 0 WHERE service_account_id = ?')
    .bind(token.serviceAccountId).run();
  assert.deepEqual(await syncedSecretIds(fixture, token), []);
});
