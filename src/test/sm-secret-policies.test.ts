import assert from 'node:assert/strict';
import test from 'node:test';

import { and, eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { orgGroupMembers, orgGroups, smSecretMembers, smSecrets, smSecretServiceAccounts, smServiceAccounts } from '../db/schema';
import { handleUpdateSecret } from '../handlers/secrets-manager';
import * as orgRepo from '../services/storage-org-repo';
import * as smRepo from '../services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smUser } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };
const CHANGED = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';
const policy = (granteeId: string, write = false) => ({ granteeId, read: true, write });
const policies = (users: ReturnType<typeof policy>[] = [], groups: ReturnType<typeof policy>[] = [], accounts: ReturnType<typeof policy>[] = []) => ({ userAccessPolicyRequests: users, groupAccessPolicyRequests: groups, serviceAccountAccessPolicyRequests: accounts });

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const { user: b } = await seedMember(env, orgId);
  const aMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  const bMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, b.id, orgId))!;
  const project = (user = owner) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const account = (user = owner) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  return { env, orgId, owner, a, b, aMember, bMember, project, account, request };
}

test('projectless secrets are visible through direct member or group policies, and policy reads require write', async () => {
  const { env, orgId, owner, a, b, aMember, bMember, account, request } = await setup();
  const groupId = crypto.randomUUID();
  const now = new Date().toISOString();
  const orm = getOrm(env.DB);
  await orm.batch([
    orm.insert(orgGroups).values({ id: groupId, orgId, name: 'Readers', createdAt: now, updatedAt: now }),
    orm.insert(orgGroupMembers).values({ groupId, membershipId: bMember.id }),
  ]);
  const machine = await account();
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds: [], accessPoliciesRequests: policies([policy(aMember.id)], [policy(groupId)], [policy(machine.id, true)]) });
  for (const user of [a, b]) {
    const listed = await request(user.id, `/api/organizations/${orgId}/secrets`);
    assert.equal(listed.status, 200);
    assert.deepEqual((await listed.json() as any).secrets.map((item: any) => [item.id, item.write]), [[secret.id, false]]);
    assert.equal((await request(user.id, `/api/secrets/${secret.id}`)).status, 200);
    assert.equal((await request(user.id, `/api/secrets/${secret.id}/access-policies`)).status, 404);
  }
  const response = await request(owner.id, `/api/secrets/${secret.id}/access-policies`);
  assert.equal(response.status, 200);
  const body = await response.json() as any;
  assert.equal(body.object, 'secretAccessPolicies');
  assert.deepEqual(body.userAccessPolicies.map((item: any) => [item.organizationUserId, item.read, item.write]), [[aMember.id, true, false]]);
  assert.deepEqual(body.groupAccessPolicies.map((item: any) => [item.groupId, item.read, item.write]), [[groupId, true, false]]);
  assert.deepEqual(body.serviceAccountAccessPolicies, [{ serviceAccountId: machine.id, serviceAccountName: ENCRYPTED_FIELD, read: true, write: true, object: 'serviceAccountProjectAccessPolicy' }]);
  assert.equal((await orm.select({ writeAccess: smSecretServiceAccounts.writeAccess }).from(smSecretServiceAccounts).where(and(eq(smSecretServiceAccounts.secretId, secret.id), eq(smSecretServiceAccounts.serviceAccountId, machine.id))).get())!.writeAccess, 1);
});

test('secret policy omission preserves grants, all three present lists are required, and existing SA grants need only secret write', async () => {
  const { env, orgId, owner, a, bMember, project, account, request } = await setup();
  const p = await project(a);
  const machine = await account();
  const accessPoliciesRequests = policies([policy(bMember.id)], [], [policy(machine.id)]);
  const path = `/api/organizations/${orgId}/secrets`;
  assert.equal((await request(a.id, path, 'POST', { ...FIELDS, projectIds: [p.id], accessPoliciesRequests })).status, 404);
  assert.equal((await smRepo.listSecrets(env.DB, orgId)).length, 0);
  const secret = await postJson<{ id: string }>(env, owner, path, { ...FIELDS, projectIds: [p.id], accessPoliciesRequests });
  const detailPath = `/api/secrets/${secret.id}`;
  const before = await (await request(owner.id, `${detailPath}/access-policies`)).json();
  for (const extra of [{}, { accessPoliciesRequests: null }]) {
    assert.equal((await request(a.id, detailPath, 'PUT', { ...FIELDS, projectIds: [p.id], ...extra })).status, 200);
    assert.deepEqual(await (await request(owner.id, `${detailPath}/access-policies`)).json(), before);
  }
  const complete = policies();
  for (const key of Object.keys(complete)) {
    const partial = { ...complete } as Record<string, unknown>;
    delete partial[key];
    assert.equal((await request(a.id, detailPath, 'PUT', { ...FIELDS, projectIds: [p.id], accessPoliciesRequests: partial })).status, 400);
  }
  assert.deepEqual(await (await request(owner.id, `${detailPath}/access-policies`)).json(), before);
  const changed = await request(a.id, detailPath, 'PUT', { ...FIELDS, projectIds: [p.id], accessPoliciesRequests: policies([policy(bMember.id)], [], [policy(machine.id, true)]) });
  assert.equal(changed.status, 200);
  const removed = await request(a.id, detailPath, 'PUT', { ...FIELDS, projectIds: [p.id], accessPoliciesRequests: policies([policy(bMember.id)]) });
  assert.equal(removed.status, 200);
  const orm = getOrm(env.DB);
  assert.equal(await orm.select().from(smSecretServiceAccounts).where(eq(smSecretServiceAccounts.secretId, secret.id)).get(), undefined);
  assert.ok(await orm.select().from(smSecretMembers).where(and(eq(smSecretMembers.secretId, secret.id), eq(smSecretMembers.membershipId, bMember.id))).get());
});

test('secret-policy conflicts roll back the secret edit, project move, people changes, and SA revision', async () => {
  const { env, orgId, owner, aMember, bMember, project, account, request } = await setup();
  const p = await project();
  const q = await project();
  const machine = await account();
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds: [p.id], accessPoliciesRequests: policies([policy(bMember.id)]) });
  const original = await smRepo.getSecret(env.DB, secret.id);
  const before = '2020-01-01T00:00:00.000Z';
  const orm = getOrm(env.DB);
  await orm.update(smServiceAccounts).set({ updatedAt: before }).where(eq(smServiceAccounts.id, machine.id));
  const batch = env.DB.batch.bind(env.DB);
  let raced = false;
  env.DB.batch = (async (statements: D1PreparedStatement[]) => {
    if (!raced && statements.some(statement => /INSERT\s+INTO\s+["`]?sm_secret_service_accounts/i.test((statement as unknown as { query: string }).query))) {
      raced = true;
      await orm.insert(smSecretServiceAccounts).values({ secretId: secret.id, serviceAccountId: machine.id, writeAccess: 0 });
    }
    return batch(statements);
  }) as D1Database['batch'];
  const response = await request(owner.id, `/api/secrets/${secret.id}`, 'PUT', { ...FIELDS, value: CHANGED, projectIds: [q.id], accessPoliciesRequests: policies([policy(aMember.id, true)], [], [policy(machine.id, true)]) });
  env.DB.batch = batch;
  assert.equal(raced, true);
  assert.equal(response.status, 409);
  assert.deepEqual(await smRepo.getSecret(env.DB, secret.id), original);
  const users = await orm.select({ membershipId: smSecretMembers.membershipId }).from(smSecretMembers).where(eq(smSecretMembers.secretId, secret.id));
  assert.deepEqual(users.map(row => row.membershipId), [bMember.id]);
  assert.equal((await orm.select({ writeAccess: smSecretServiceAccounts.writeAccess }).from(smSecretServiceAccounts).where(and(eq(smSecretServiceAccounts.secretId, secret.id), eq(smSecretServiceAccounts.serviceAccountId, machine.id))).get())!.writeAccess, 0);
  assert.equal((await smRepo.getServiceAccount(env.DB, machine.id))!.updatedAt, before);
});

test('a stale secret snapshot aborts new and removed policies together with its encrypted field changes', async () => {
  const { env, orgId, owner, aMember, bMember, account, request } = await setup();
  const machine = await account();
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, accessPoliciesRequests: policies([policy(aMember.id)]) });
  const before = '2020-01-01T00:00:00.000Z';
  const orm = getOrm(env.DB);
  await orm.update(smServiceAccounts).set({ updatedAt: before }).where(eq(smServiceAccounts.id, machine.id));
  const put = new Request('https://vault.example.test', { method: 'PUT' });
  put.json = async () => {
    await orm.update(smSecrets).set({ deletedAt: before }).where(eq(smSecrets.id, secret.id));
    return { ...FIELDS, value: CHANGED, projectIds: [], accessPoliciesRequests: policies([policy(bMember.id, true)], [], [policy(machine.id)]) };
  };
  assert.equal((await handleUpdateSecret(put, env, await smUser(env, owner), secret.id)).status, 404);
  const persisted = (await smRepo.getSecret(env.DB, secret.id))!;
  assert.equal(persisted.deletedAt, before);
  assert.equal(persisted.value, ENCRYPTED_FIELD);
  const users = await orm.select({ membershipId: smSecretMembers.membershipId }).from(smSecretMembers).where(eq(smSecretMembers.secretId, secret.id));
  assert.deepEqual(users.map(row => row.membershipId), [aMember.id]);
  assert.equal(await orm.select().from(smSecretServiceAccounts).where(eq(smSecretServiceAccounts.secretId, secret.id)).get(), undefined);
  assert.equal((await smRepo.getServiceAccount(env.DB, machine.id))!.updatedAt, before);
  assert.equal((await request(owner.id, `/api/secrets/${secret.id}/access-policies`)).status, 404);
});
