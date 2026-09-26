import assert from 'node:assert/strict';
import test from 'node:test';

import { handleCreateServiceAccount } from '../src/handlers/secrets-manager';
import { MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import * as smRepo from '../src/services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const a = await seedMember(env, orgId, MembershipType.User);
  const b = await seedMember(env, orgId, MembershipType.User);
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
  assert.ok(await env.DB.prepare('SELECT 1 FROM sm_service_account_members WHERE service_account_id = ? AND membership_id = ?').bind(sa.id, aMember!.id).first());
  assert.deepEqual((await (await request(a.id, path)).json() as any).data.map((item: any) => item.id), [sa.id]);
  assert.deepEqual((await (await request(b.id, path)).json() as any).data, []);
  for (const [suffix, method] of [['', 'GET'], ['', 'PUT'], ['/access-tokens', 'GET'], ['/access-tokens', 'POST'], ['/access-tokens/revoke', 'POST']]) {
    assert.equal((await request(b.id, detailPath + suffix, method, method === 'GET' ? undefined : { name: ENCRYPTED_FIELD, ids: [] })).status, 404);
  }
  assert.deepEqual(await (await request(b.id, `${detailPath}/sm-counts`)).json(), { projects: 0, people: 0, accessTokens: 0, object: 'serviceAccountCounts' });
  const groupId = crypto.randomUUID();
  const bMember = await orgRepo.getMembershipByUserAndOrg(env.DB, b.id, orgId);
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO org_groups (id, org_id, name, access_all, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)').bind(groupId, orgId, 'Operators', now, now),
    env.DB.prepare('INSERT INTO org_group_members (group_id, membership_id) VALUES (?, ?)').bind(groupId, bMember!.id),
    env.DB.prepare('INSERT INTO sm_service_account_groups (service_account_id, group_id) VALUES (?, ?)').bind(sa.id, groupId),
  ]);
  assert.equal((await request(b.id, detailPath)).status, 200);
  assert.equal((await request(b.id, detailPath, 'PUT', { name: ENCRYPTED_FIELD })).status, 200);
  assert.equal((await request(a.id, detailPath, 'PUT', { name: 'plaintext' })).status, 400);
  const token = await postJson<{ id: string; clientId: string; clientSecret: string }>(env, b, `${detailPath}/access-tokens`, { name: ENCRYPTED_FIELD });
  const other = await account();
  const otherToken = await postJson<{ id: string }>(env, a, `/api/service-accounts/${other.id}/access-tokens`, { name: ENCRYPTED_FIELD });
  const sync = () => authedFetch(env, { path: `/api/organizations/${orgId}/secrets/sync`, headers: { Authorization: `Bearer ${token.clientId}:${token.clientSecret}` } });
  assert.equal((await sync()).status, 200);
  assert.deepEqual(await (await request(a.id, `${detailPath}/sm-counts`)).json(), { projects: 0, people: 2, accessTokens: 1, object: 'serviceAccountCounts' });
  const revoked = await request(b.id, `${detailPath}/access-tokens/revoke`, 'POST', { ids: [token.id, otherToken.id] });
  assert.equal(revoked.status, 200);
  assert.equal(await revoked.text(), '');
  assert.equal(await smRepo.getAccessToken(env.DB, token.id), null);
  assert.ok(await smRepo.getAccessToken(env.DB, otherToken.id));
  assert.deepEqual((await (await request(a.id, `${detailPath}/access-tokens`)).json() as any).data, []);
  assert.equal((await sync()).status, 401);
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
  await env.DB.batch([
    env.DB.prepare('INSERT INTO sm_service_account_projects (service_account_id, project_id, read_access, write_access) VALUES (?, ?, 1, 0)').bind(sa.id, project.id),
    ...[throughProject.id, direct.id, trashed.id].map(id => env.DB.prepare('INSERT INTO sm_secret_service_accounts (secret_id, service_account_id, write_access) VALUES (?, ?, 0)').bind(id, sa.id)),
    env.DB.prepare('UPDATE sm_secrets SET deleted_at = ? WHERE id = ?').bind(new Date().toISOString(), trashed.id),
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
  await env.DB.exec("CREATE TRIGGER fail_machine_grant BEFORE INSERT ON sm_service_account_members BEGIN SELECT RAISE(ABORT, 'test machine rollback'); END;");
  await assert.rejects(() => handleCreateServiceAccount(new Request('https://vault.example.test', { method: 'POST', body: JSON.stringify({ name: ENCRYPTED_FIELD, projectIds: [ownProject.id] }) }), env, a.id, orgId), /test machine rollback/);
  assert.equal((await smRepo.listServiceAccounts(env.DB, orgId)).length, 0);
  assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM sm_service_account_members').first<{ n: number }>())!.n, 0);
  await env.DB.exec('DROP TRIGGER fail_machine_grant;');
  const own = await account(a, [ownProject.id, deniedProject.id, crypto.randomUUID()]);
  const denied = await account(owner);
  const token = await postJson<{ id: string }>(env, a, `/api/service-accounts/${own.id}/access-tokens`, { name: ENCRYPTED_FIELD });
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
