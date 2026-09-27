import assert from 'node:assert/strict';
import test from 'node:test';

import { and, eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { orgGroupMembers, orgGroups, smSecrets, smSecretServiceAccounts, smServiceAccountGroups, smServiceAccountMembers, smServiceAccountProjects } from '../db/schema';
import { handleCreateServiceAccount } from '../handlers/secrets-manager';
import * as orgRepo from '../services/storage-org-repo';
import * as smRepo from '../services/storage-secret-repo';
import { abortWrites, authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smLogin, smUser, TOKEN_FIELDS } from './support/sm';

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const { user: b } = await seedMember(env, orgId);
  const path = `/api/organizations/${orgId}/service-accounts`;
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  const account = (user = a, projectIds: string[] = []) => postJson<{ id: string }>(env, user, path, { name: ENCRYPTED_FIELD, projectIds });
  return { env, orgId, owner, a, b, path, request, account };
}

test('machine-account creator and group policies gate management, and revocation hard-deletes only that account token', async () => {
  const { env, orgId, a, b, path, request, account } = await setup();
  const sa = await account();
  const detailPath = `/api/service-accounts/${sa.id}`;
  const aMember = await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId);
  const orm = getOrm(env.DB);
  assert.ok(await orm.select().from(smServiceAccountMembers).where(and(eq(smServiceAccountMembers.serviceAccountId, sa.id), eq(smServiceAccountMembers.membershipId, aMember!.id))).get());
  assert.deepEqual((await (await request(a.id, path)).json() as any).data.map((item: any) => item.id), [sa.id]);
  assert.deepEqual((await (await request(b.id, path)).json() as any).data, []);
  for (const [suffix, method] of [['', 'GET'], ['', 'PUT'], ['/access-tokens', 'GET'], ['/access-tokens', 'POST'], ['/access-tokens/revoke', 'POST']]) {
    assert.equal((await request(b.id, detailPath + suffix, method, method === 'GET' ? undefined : { name: ENCRYPTED_FIELD, ids: [] })).status, 404);
  }
  assert.deepEqual(await (await request(b.id, `${detailPath}/sm-counts`)).json(), { projects: 0, people: 0, accessTokens: 0, object: 'serviceAccountCounts' });
  const groupId = crypto.randomUUID();
  const bMember = await orgRepo.getMembershipByUserAndOrg(env.DB, b.id, orgId);
  const now = new Date().toISOString();
  await orm.batch([
    orm.insert(orgGroups).values({ id: groupId, orgId, name: 'Operators', createdAt: now, updatedAt: now }),
    orm.insert(orgGroupMembers).values({ groupId, membershipId: bMember!.id }),
    orm.insert(smServiceAccountGroups).values({ serviceAccountId: sa.id, groupId }),
  ]);
  assert.equal((await request(b.id, detailPath)).status, 200);
  assert.equal((await request(b.id, detailPath, 'PUT', { name: ENCRYPTED_FIELD })).status, 200);
  assert.equal((await request(a.id, detailPath, 'PUT', { name: 'plaintext' })).status, 400);
  const token = await postJson<{ id: string; clientSecret: string }>(env, b, `${detailPath}/access-tokens`, TOKEN_FIELDS);
  const other = await account();
  const otherToken = await postJson<{ id: string }>(env, a, `/api/service-accounts/${other.id}/access-tokens`, TOKEN_FIELDS);
  assert.equal((await smLogin(env, token.id, token.clientSecret)).status, 200);
  assert.deepEqual(await (await request(a.id, `${detailPath}/sm-counts`)).json(), { projects: 0, people: 2, accessTokens: 1, object: 'serviceAccountCounts' });
  const revoked = await request(b.id, `${detailPath}/access-tokens/revoke`, 'POST', { ids: [token.id, otherToken.id] });
  assert.equal(revoked.status, 200);
  assert.equal(await revoked.text(), '');
  assert.equal(await smRepo.getAccessToken(env.DB, token.id), null);
  assert.ok(await smRepo.getAccessToken(env.DB, otherToken.id));
  assert.deepEqual((await (await request(a.id, `${detailPath}/access-tokens`)).json() as any).data, []);
  const rejectedLogin = await smLogin(env, token.id, token.clientSecret);
  assert.equal(rejectedLogin.status, 400);
  assert.equal((await rejectedLogin.json() as any).error, 'invalid_client');
});

test('machine accessToSecrets is distinct across direct and project policies, and org counts equal visible lists', async () => {
  const { env, orgId, owner, a, b, path, request, account } = await setup();
  const project = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  await postJson(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const sa = await account();
  await account(owner);
  const fields = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };
  const throughProject = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/secrets`, { ...fields, projectIds: [project.id] });
  const direct = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, fields);
  const trashed = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/secrets`, { ...fields, projectIds: [project.id] });
  const orm = getOrm(env.DB);
  await orm.batch([
    orm.insert(smServiceAccountProjects).values({ serviceAccountId: sa.id, projectId: project.id, readAccess: 1, writeAccess: 0 }),
    orm.insert(smSecretServiceAccounts).values([throughProject.id, direct.id, trashed.id].map(secretId => ({ secretId, serviceAccountId: sa.id, writeAccess: 0 }))),
    orm.update(smSecrets).set({ deletedAt: new Date().toISOString() }).where(eq(smSecrets.id, trashed.id)),
  ]);
  const listed = await request(a.id, path);
  assert.equal(listed.status, 200);
  assert.equal((await listed.json() as any).data[0].accessToSecrets, 2);
  const accountCounts = await request(a.id, `/api/service-accounts/${sa.id}/sm-counts`);
  assert.equal(accountCounts.status, 200);
  assert.deepEqual(await accountCounts.json(), { projects: 1, people: 1, accessTokens: 0, object: 'serviceAccountCounts' });
  for (const user of [a, b, owner]) {
    const projects = await (await request(user.id, `/api/organizations/${orgId}/projects`)).json() as any;
    const secrets = await (await request(user.id, `/api/organizations/${orgId}/secrets`)).json() as any;
    const accounts = await (await request(user.id, path)).json() as any;
    const counts = await request(user.id, `/api/organizations/${orgId}/sm-counts`);
    assert.equal(counts.status, 200);
    assert.deepEqual(await counts.json(), { projects: projects.data.length, secrets: secrets.secrets.length, serviceAccounts: accounts.data.length, object: 'organizationCounts' });
  }
});

test('machine creation ignores legacy projectIds, rolls back creator grants atomically, and bulk delete returns per-item results', async () => {
  const { env, orgId, owner, a, path, request, account } = await setup();
  const ownProject = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const deniedProject = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  assert.equal((await request(a.id, path, 'POST', { name: 'plaintext' })).status, 400);
  const removeFault = await abortWrites(env, { table: smServiceAccountMembers, event: 'INSERT' }, 'test machine rollback');
  await assert.rejects(async () => handleCreateServiceAccount(new Request('https://vault.example.test', { method: 'POST', body: JSON.stringify({ name: ENCRYPTED_FIELD, projectIds: [ownProject.id] }) }), env, await smUser(env, a), orgId), /test machine rollback/);
  assert.equal((await smRepo.listServiceAccounts(env.DB, orgId)).length, 0);
  assert.equal(await getOrm(env.DB).$count(smServiceAccountMembers), 0);
  await removeFault();
  const own = await account(a, [ownProject.id, deniedProject.id, crypto.randomUUID()]);
  const denied = await account(owner);
  const token = await postJson<{ id: string }>(env, a, `/api/service-accounts/${own.id}/access-tokens`, TOKEN_FIELDS);
  assert.deepEqual(await smRepo.listReadableServiceAccountProjectIds(env.DB, own.id), []);
  const foreign = await seedSmOrg(env);
  const foreignAccount = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  assert.equal((await request(owner.id, '/api/service-accounts/delete', 'POST', [own.id, foreignAccount.id])).status, 404);
  assert.ok(await smRepo.getServiceAccount(env.DB, own.id));
  const deleted = await request(a.id, '/api/service-accounts/delete', 'POST', [own.id, denied.id]);
  assert.equal(deleted.status, 200);
  const data = (await deleted.json() as any).data;
  assert.deepEqual(new Map(data.map((item: any) => [item.id, item.error])), new Map([[own.id, null], [denied.id, 'access denied']]));
  assert.ok(data.every((item: any) => item.object === 'BulkDeleteResponseModel'));
  assert.equal(await smRepo.getServiceAccount(env.DB, own.id), null);
  assert.equal(await smRepo.getAccessToken(env.DB, token.id), null);
  assert.ok(await smRepo.getServiceAccount(env.DB, denied.id));
});
