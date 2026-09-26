import assert from 'node:assert/strict';
import test from 'node:test';

import { handleUpdateSecret } from '../src/handlers/secrets-manager';
import { MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import * as smRepo from '../src/services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smUser } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };
const CHANGED = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';
const policy = (granteeId: string, write = false) => ({ granteeId, read: true, write });
const policies = (users: ReturnType<typeof policy>[] = [], groups: ReturnType<typeof policy>[] = [], accounts: ReturnType<typeof policy>[] = []) => ({ userAccessPolicyRequests: users, groupAccessPolicyRequests: groups, serviceAccountAccessPolicyRequests: accounts });

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const a = await seedMember(env, orgId, MembershipType.User);
  const b = await seedMember(env, orgId, MembershipType.User);
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
  await env.DB.batch([
    env.DB.prepare('INSERT INTO org_groups (id, org_id, name, access_all, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)').bind(groupId, orgId, 'Readers', now, now),
    env.DB.prepare('INSERT INTO org_group_members (group_id, membership_id) VALUES (?, ?)').bind(groupId, bMember.id),
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
  assert.equal((await env.DB.prepare('SELECT write_access FROM sm_secret_service_accounts WHERE secret_id = ? AND service_account_id = ?').bind(secret.id, machine.id).first<{ write_access: number }>())!.write_access, 1);
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
  assert.equal(await env.DB.prepare('SELECT 1 FROM sm_secret_service_accounts WHERE secret_id = ?').bind(secret.id).first(), null);
  assert.ok(await env.DB.prepare('SELECT 1 FROM sm_secret_members WHERE secret_id = ? AND membership_id = ?').bind(secret.id, bMember.id).first());
});

test('secret-policy conflicts roll back the secret edit, project move, people changes, and SA revision', async () => {
  const { env, orgId, owner, aMember, bMember, project, account, request } = await setup();
  const p = await project();
  const q = await project();
  const machine = await account();
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds: [p.id], accessPoliciesRequests: policies([policy(bMember.id)]) });
  const original = await smRepo.getSecret(env.DB, secret.id);
  const before = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(before, machine.id).run();
  const batch = env.DB.batch.bind(env.DB);
  let raced = false;
  env.DB.batch = (async (statements: D1PreparedStatement[]) => {
    if (!raced && statements.some(statement => /INSERT\s+INTO\s+["`]?sm_secret_service_accounts/i.test((statement as unknown as { query: string }).query))) {
      raced = true;
      await env.DB.prepare('INSERT INTO sm_secret_service_accounts (secret_id, service_account_id, write_access) VALUES (?, ?, 0)').bind(secret.id, machine.id).run();
    }
    return batch(statements);
  }) as D1Database['batch'];
  const response = await request(owner.id, `/api/secrets/${secret.id}`, 'PUT', { ...FIELDS, value: CHANGED, projectIds: [q.id], accessPoliciesRequests: policies([policy(aMember.id, true)], [], [policy(machine.id, true)]) });
  env.DB.batch = batch;
  assert.equal(raced, true);
  assert.equal(response.status, 409);
  assert.deepEqual(await smRepo.getSecret(env.DB, secret.id), original);
  const users = await env.DB.prepare('SELECT membership_id FROM sm_secret_members WHERE secret_id = ?').bind(secret.id).all<{ membership_id: string }>();
  assert.deepEqual(users.results.map(row => row.membership_id), [bMember.id]);
  assert.equal((await env.DB.prepare('SELECT write_access FROM sm_secret_service_accounts WHERE secret_id = ? AND service_account_id = ?').bind(secret.id, machine.id).first<{ write_access: number }>())!.write_access, 0);
  assert.equal((await smRepo.getServiceAccount(env.DB, machine.id))!.updatedAt, before);
});

test('a stale secret snapshot aborts new and removed policies together with its encrypted field changes', async () => {
  const { env, orgId, owner, aMember, bMember, account, request } = await setup();
  const machine = await account();
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, accessPoliciesRequests: policies([policy(aMember.id)]) });
  const before = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(before, machine.id).run();
  const put = new Request('https://vault.example.test', { method: 'PUT' });
  put.json = async () => {
    await env.DB.prepare('UPDATE sm_secrets SET deleted_at = ? WHERE id = ?').bind(before, secret.id).run();
    return { ...FIELDS, value: CHANGED, projectIds: [], accessPoliciesRequests: policies([policy(bMember.id, true)], [], [policy(machine.id)]) };
  };
  assert.equal((await handleUpdateSecret(put, env, await smUser(env, owner), secret.id)).status, 404);
  const persisted = (await smRepo.getSecret(env.DB, secret.id))!;
  assert.equal(persisted.deletedAt, before);
  assert.equal(persisted.value, ENCRYPTED_FIELD);
  const users = await env.DB.prepare('SELECT membership_id FROM sm_secret_members WHERE secret_id = ?').bind(secret.id).all<{ membership_id: string }>();
  assert.deepEqual(users.results.map(row => row.membership_id), [aMember.id]);
  assert.equal(await env.DB.prepare('SELECT 1 FROM sm_secret_service_accounts WHERE secret_id = ?').bind(secret.id).first(), null);
  assert.equal((await smRepo.getServiceAccount(env.DB, machine.id))!.updatedAt, before);
  assert.equal((await request(owner.id, `/api/secrets/${secret.id}/access-policies`)).status, 404);
});
