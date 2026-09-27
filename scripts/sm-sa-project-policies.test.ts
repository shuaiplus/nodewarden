import assert from 'node:assert/strict';
import test from 'node:test';

import * as orgRepo from '../src/services/storage-org-repo';
import * as smRepo from '../src/services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

const policy = (granteeId: string, write = false) => ({ granteeId, read: true, write });
const granted = (grantedId: string, write = false) => ({ grantedId, read: true, write });

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const project = (user = a) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const account = (user = a) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  return { env, orgId, owner, a, project, account, request };
}

test('project policies require machine write only for creates, preserve exact shape, and list writable potential grantees', async () => {
  const { env, orgId, owner, a, project, account, request } = await setup();
  const ownProject = await project();
  const otherProject = await project(owner);
  const ownAccount = await account();
  const otherAccount = await account(owner);
  const member = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  await env.DB.prepare('INSERT INTO sm_project_members (project_id, membership_id, write_access) VALUES (?, ?, 0)').bind(otherProject.id, member.id).run();
  for (const [kind, expected] of [['service-accounts', ownAccount.id], ['projects', ownProject.id]]) {
    const response = await request(a.id, `/api/organizations/${orgId}/access-policies/${kind}/potential-grantees`);
    assert.equal(response.status, 200);
    const body = await response.json() as any;
    assert.equal(body.object, 'list');
    assert.deepEqual(body.data.map((item: any) => item.id), [expected]);
    assert.equal(body.data[0].name, ENCRYPTED_FIELD);
    assert.equal(body.data[0].type, kind === 'projects' ? 'project' : 'serviceAccount');
  }
  const path = `/api/projects/${ownProject.id}/access-policies/service-accounts`;
  assert.equal((await request(a.id, path, 'PUT', { serviceAccountAccessPolicyRequests: [policy(otherAccount.id)] })).status, 404);
  assert.equal((await request(a.id, `/api/projects/${otherProject.id}/access-policies/service-accounts`)).status, 404);
  const assigned = await request(owner.id, path, 'PUT', { serviceAccountAccessPolicyRequests: [policy(otherAccount.id)] });
  assert.equal(assigned.status, 200);
  assert.deepEqual(await assigned.json(), { serviceAccountAccessPolicies: [{ serviceAccountId: otherAccount.id, serviceAccountName: ENCRYPTED_FIELD, read: true, write: false, object: 'serviceAccountProjectAccessPolicy' }], object: 'ProjectServiceAccountsAccessPolicies' });
  const before = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE org_id = ?').bind(before, orgId).run();
  const updated = await request(a.id, path, 'PUT', { serviceAccountAccessPolicyRequests: [policy(otherAccount.id, true)] });
  assert.equal(updated.status, 200);
  assert.equal((await updated.json() as any).serviceAccountAccessPolicies[0].write, true);
  assert.ok((await smRepo.getServiceAccount(env.DB, otherAccount.id))!.updatedAt > before);
  assert.equal((await request(a.id, path, 'PUT', { serviceAccountAccessPolicyRequests: [] })).status, 200);
  assert.deepEqual((await (await request(a.id, path)).json() as any).serviceAccountAccessPolicies, []);
  const foreign = await seedSmOrg(env);
  const foreignAccount = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  assert.equal((await request(owner.id, path, 'PUT', { serviceAccountAccessPolicyRequests: [policy(foreignAccount.id)] })).status, 404);
});

test('granted-project diffs authorize every touched project but accept unchanged inaccessible policies', async () => {
  const { env, owner, a, project, account, request } = await setup();
  const writable = await project();
  const inaccessible = await project(owner);
  const sa = await account();
  await smRepo.replaceServiceAccountProjects(env.DB, sa.id, [inaccessible.id]);
  const path = `/api/service-accounts/${sa.id}/granted-policies`;
  const existing = await request(a.id, path);
  assert.equal(existing.status, 200);
  assert.deepEqual(await existing.json(), {
    grantedProjectPolicies: [{ accessPolicy: { grantedProjectId: inaccessible.id, grantedProjectName: ENCRYPTED_FIELD, read: true, write: false, object: 'grantedProjectAccessPolicy' }, hasPermission: false, object: 'grantedProjectAccessPolicyPermissionDetails' }],
    object: 'ServiceAccountGrantedPoliciesPermissionDetails',
  });
  const accepted = await request(a.id, path, 'PUT', { projectGrantedPolicyRequests: [granted(inaccessible.id), granted(writable.id, true)] });
  assert.equal(accepted.status, 200);
  const response = await accepted.json() as any;
  assert.deepEqual(new Map(response.grantedProjectPolicies.map((item: any) => [item.accessPolicy.grantedProjectId, item.hasPermission])), new Map([[inaccessible.id, false], [writable.id, true]]));
  for (const policies of [[granted(inaccessible.id, true), granted(writable.id, true)], [granted(writable.id, true)]]) {
    assert.equal((await request(a.id, path, 'PUT', { projectGrantedPolicyRequests: policies })).status, 404);
  }
  assert.deepEqual(new Set(await smRepo.listReadableServiceAccountProjectIds(env.DB, sa.id)), new Set([inaccessible.id, writable.id]));
  const removeWritable = await request(a.id, path, 'PUT', { projectGrantedPolicyRequests: [granted(inaccessible.id)] });
  assert.equal(removeWritable.status, 200);
  assert.deepEqual(await smRepo.listReadableServiceAccountProjectIds(env.DB, sa.id), [inaccessible.id]);
});

test('a concurrent new machine grant causes 409 and rolls back deletions in the same policy batch', async () => {
  const { env, orgId, a, project, account, request } = await setup();
  const p = await project();
  const old = await account();
  const added = await account();
  await smRepo.replaceServiceAccountProjects(env.DB, old.id, [p.id]);
  const before = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE org_id = ?').bind(before, orgId).run();
  const batch = env.DB.batch.bind(env.DB);
  let raced = false;
  env.DB.batch = (async (statements: D1PreparedStatement[]) => {
    if (!raced && statements.some(statement => /INSERT\s+INTO\s+["`]?sm_service_account_projects/i.test((statement as unknown as { query: string }).query))) {
      raced = true;
      await env.DB.prepare('INSERT INTO sm_service_account_projects (service_account_id, project_id, read_access, write_access) VALUES (?, ?, 1, 0)').bind(added.id, p.id).run();
    }
    return batch(statements);
  }) as D1Database['batch'];
  const response = await request(a.id, `/api/projects/${p.id}/access-policies/service-accounts`, 'PUT', { serviceAccountAccessPolicyRequests: [policy(added.id, true)] });
  env.DB.batch = batch;
  assert.equal(raced, true);
  assert.equal(response.status, 409);
  assert.deepEqual(await smRepo.listReadableServiceAccountProjectIds(env.DB, old.id), [p.id]);
  assert.equal((await env.DB.prepare('SELECT write_access FROM sm_service_account_projects WHERE service_account_id = ? AND project_id = ?').bind(added.id, p.id).first<{ write_access: number }>())!.write_access, 0);
  assert.equal((await smRepo.getServiceAccount(env.DB, old.id))!.updatedAt, before);
});
