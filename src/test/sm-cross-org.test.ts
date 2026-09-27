import assert from 'node:assert/strict';
import test from 'node:test';

import { ensureStorageSchema } from '../db/migrate';
import * as smRepo from '../services/storage-secret-repo';
import type { Env, User } from '../types';
import { D1_MAX_BOUND_PARAMETERS } from './support/d1-sqlite';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg, TEST_ORG_KEY } from './support/sm';

// Enough secrets that one id per bound parameter no longer fits a single statement.
const LARGE_ORG_SECRET_COUNT = D1_MAX_BOUND_PARAMETERS + D1_MAX_BOUND_PARAMETERS / 2;

// Upstream NotFoundException text; missing and foreign projects fail alike, so nothing is probed.
const RESOURCE_NOT_FOUND = 'Resource not found.';

const SECRET_FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };

interface CrossOrgFixture {
  env: Env;
  // An Admin of org Y who also owns org X, so it passes the SM gate in both.
  admin: User;
  yOrgId: string;
  yProjectId: string;
  ySecretId: string;
  xProjectId: string;
}

async function createProject(env: Env, user: User, orgId: string): Promise<string> {
  return (await postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD })).id;
}

async function seedCrossOrg(): Promise<CrossOrgFixture> {
  const env = await createTestEnv();
  const { orgId: yOrgId, admin } = await seedSmOrg(env);
  const { id: xOrgId } = await postJson<{ id: string }>(env, admin, '/api/organizations', { name: 'Acme', key: TEST_ORG_KEY });
  const yProjectId = await createProject(env, admin, yOrgId);
  const { id: ySecretId } = await postJson<{ id: string }>(env, admin, `/api/organizations/${yOrgId}/secrets`, { ...SECRET_FIELDS, projectIds: [yProjectId] });
  return { env, admin, yOrgId, yProjectId, ySecretId, xProjectId: await createProject(env, admin, xOrgId) };
}

async function getJson<T>(env: Env, user: User, path: string): Promise<T> {
  const response = await authedFetch(env, { path, userId: user.id });
  assert.equal(response.status, 200, `${path} answered ${response.status}`);
  return await response.json() as T;
}

// Y's secrets with their project links, and Y's machine accounts, as the API reports them.
async function yOrgState({ env, admin, yOrgId }: CrossOrgFixture) {
  const { secrets } = await getJson<{ secrets: unknown[] }>(env, admin, `/api/organizations/${yOrgId}/secrets`);
  const { data: serviceAccounts } = await getJson<{ data: unknown[] }>(env, admin, `/api/organizations/${yOrgId}/service-accounts`);
  return { secrets, serviceAccounts };
}

const PROJECT_WRITES = [
  ['creating a secret', ({ env, admin, yOrgId }: CrossOrgFixture, projectIds: string[]) =>
    authedFetch(env, { method: 'POST', path: `/api/organizations/${yOrgId}/secrets`, body: { ...SECRET_FIELDS, projectIds }, userId: admin.id })],
  ['moving a secret', ({ env, admin, ySecretId }: CrossOrgFixture, projectIds: string[]) =>
    authedFetch(env, { method: 'PUT', path: `/api/secrets/${ySecretId}`, body: { ...SECRET_FIELDS, projectIds }, userId: admin.id })],
] as const;

const REJECTED_PROJECT_IDS = [
  ['another org\'s project', (fixture: CrossOrgFixture) => [fixture.xProjectId]],
  ['a nonexistent project', () => [crypto.randomUUID()]],
  ['Y\'s project twice', (fixture: CrossOrgFixture) => [fixture.yProjectId, fixture.yProjectId]],
] as const;

// Upstream ProjectsAreInOrganization: a secret project must belong to the target's org.
for (const [write, send] of PROJECT_WRITES) {
  for (const [target, projectIds] of REJECTED_PROJECT_IDS) {
    test(`an Admin of Y who owns X ${write} in Y with ${target} is rejected and changes nothing`, async () => {
      const fixture = await seedCrossOrg();
      const before = await yOrgState(fixture);

      const response = await send(fixture, projectIds(fixture));
      const tooMany = target === "Y's project twice";
      assert.equal(response.status, tooMany ? 400 : 404);
      assert.equal((await response.json() as { message: string }).message, tooMany ? 'Only one project assignment is supported.' : RESOURCE_NOT_FOUND);
      assert.deepEqual(await yOrgState(fixture), before);
    });
  }
}

// Every chunk also binds the org id, so ids filling the whole cap must still split.
test('projectsInOrg keeps only the org\'s projects from a cap-length id list', async () => {
  const { env, yOrgId, yProjectId, xProjectId } = await seedCrossOrg();
  const ids = [yProjectId, xProjectId];
  const missingIds = Array.from({ length: D1_MAX_BOUND_PARAMETERS - ids.length }, () => crypto.randomUUID());
  assert.deepEqual(await smRepo.projectsInOrg(env.DB, yOrgId, [...ids, ...missingIds]), new Set([yProjectId]));
});

async function linkedProjectIds(env: Env, table: 'sm_secret_projects' | 'sm_service_account_projects', column: 'secret_id' | 'service_account_id', id: string): Promise<string[]> {
  const { results } = await env.DB.prepare(`SELECT project_id FROM ${table} WHERE ${column} = ?`).bind(id).all<{ project_id: string }>();
  return results.map((row) => row.project_id);
}

// Earlier builds stored any posted project id, so a link can already point across organizations.
test('a seeded cross-org secret link never appears in projects[], and the schema step removes it', async () => {
  const { env, admin, yOrgId, yProjectId, ySecretId, xProjectId } = await seedCrossOrg();
  await env.DB.prepare('INSERT INTO sm_secret_projects (secret_id, project_id) VALUES (?, ?)').bind(ySecretId, xProjectId).run();

  const secret = await getJson<{ projects: { id: string }[] }>(env, admin, `/api/secrets/${ySecretId}`);
  assert.deepEqual(secret.projects.map((project) => project.id), [yProjectId]);
  const { secrets } = await getJson<{ secrets: { id: string; projects: { id: string }[] }[] }>(env, admin, `/api/organizations/${yOrgId}/secrets`);
  assert.deepEqual(secrets.map((listed) => [listed.id, listed.projects.map((project) => project.id)]), [[ySecretId, [yProjectId]]]);

  await ensureStorageSchema(env.DB);
  assert.deepEqual(await linkedProjectIds(env, 'sm_secret_projects', 'secret_id', ySecretId), [yProjectId]);
  await ensureStorageSchema(env.DB);
  assert.deepEqual(await linkedProjectIds(env, 'sm_secret_projects', 'secret_id', ySecretId), [yProjectId]);
});

test('the schema step removes cross-org and unreadable machine-account project grants and replays cleanly', async () => {
  const { env, admin, yOrgId, yProjectId, xProjectId } = await seedCrossOrg();
  const createAccount = async () => {
    const { id } = await postJson<{ id: string }>(env, admin, `/api/organizations/${yOrgId}/service-accounts`, { name: ENCRYPTED_FIELD });
    await smRepo.replaceServiceAccountProjects(env.DB, id, [yProjectId]);
    return id;
  };
  const [granted, unreadable] = [await createAccount(), await createAccount()];
  await env.DB.prepare('INSERT INTO sm_service_account_projects (service_account_id, project_id, read_access, write_access) VALUES (?, ?, 1, 0)').bind(granted, xProjectId).run();
  await env.DB.prepare('UPDATE sm_service_account_projects SET read_access = 0 WHERE service_account_id = ?').bind(unreadable).run();

  const assertOnlyReadableSameOrgGrants = async () => {
    assert.deepEqual(await linkedProjectIds(env, 'sm_service_account_projects', 'service_account_id', granted), [yProjectId]);
    assert.deepEqual(await linkedProjectIds(env, 'sm_service_account_projects', 'service_account_id', unreadable), []);
  };
  await ensureStorageSchema(env.DB);
  await assertOnlyReadableSameOrgGrants();
  await ensureStorageSchema(env.DB);
  await assertOnlyReadableSameOrgGrants();
});

test(`an owner lists ${LARGE_ORG_SECRET_COUNT} secrets without exceeding D1 parameters`, async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const projectId = await createProject(env, owner, orgId);
  const now = new Date().toISOString();
  await Promise.all(Array.from({ length: LARGE_ORG_SECRET_COUNT }, () => smRepo.saveSecret(env.DB, {
    id: crypto.randomUUID(), orgId, ...SECRET_FIELDS, projectIds: [projectId], createdAt: now, updatedAt: now, deletedAt: null,
  })));

  const { secrets } = await getJson<{ secrets: unknown[] }>(env, owner, `/api/organizations/${orgId}/secrets`);
  assert.equal(secrets.length, LARGE_ORG_SECRET_COUNT);

});
