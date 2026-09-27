import assert from 'node:assert/strict';
import test from 'node:test';

import * as orgRepo from '../src/services/storage-org-repo';
import * as smRepo from '../src/services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  return { env, orgId, owner, a, account, request, trashPath: `/api/secrets/${orgId}/trash` };
}

test('trash is admin-only, validates the whole org set, restores policies, and empties by cascading grants', async () => {
  const { env, orgId, owner, a, account, request, trashPath } = await setup();
  const member = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, accessPoliciesRequests: { userAccessPolicyRequests: [{ granteeId: member.id, read: true, write: false }], groupAccessPolicyRequests: [], serviceAccountAccessPolicyRequests: [{ granteeId: account.id, read: true, write: false }] } });
  const active = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, FIELDS);
  assert.equal((await request(owner.id, '/api/secrets/delete', 'POST', [secret.id])).status, 200);
  for (const [path, method] of [[trashPath, 'GET'], [`${trashPath}/restore`, 'POST'], [`${trashPath}/empty`, 'POST']]) {
    assert.equal((await request(a.id, path, method, method === 'POST' ? [secret.id] : undefined)).status, 404);
  }
  const listed = await request(owner.id, trashPath);
  assert.equal(listed.status, 200);
  const body = await listed.json() as any;
  assert.equal(body.object, 'SecretsWithProjectsList');
  assert.deepEqual(body.secrets.map((item: any) => [item.id, item.read, item.write]), [[secret.id, true, true]]);
  assert.deepEqual(body.projects, []);
  assert.equal((await request(a.id, `/api/secrets/${secret.id}`)).status, 404);
  const foreign = await seedSmOrg(env);
  const outside = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/secrets`, FIELDS);
  assert.equal((await request(foreign.owner.id, '/api/secrets/delete', 'POST', [outside.id])).status, 200);
  for (const action of ['restore', 'empty']) {
    for (const ids of [[secret.id, active.id], [secret.id, outside.id], [secret.id, crypto.randomUUID()]]) {
      assert.equal((await request(owner.id, `${trashPath}/${action}`, 'POST', ids)).status, 404);
      assert.ok((await smRepo.getSecret(env.DB, secret.id))!.deletedAt);
    }
    assert.equal((await request(owner.id, `${trashPath}/${action}`, 'POST', { ids: [secret.id] })).status, 400);
  }
  const before = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(before, account.id).run();
  const restored = await request(owner.id, `${trashPath}/RESTORE`, 'POST', [secret.id]);
  assert.equal(restored.status, 200);
  assert.equal(await restored.text(), '');
  assert.equal((await request(a.id, `/api/secrets/${secret.id}`)).status, 200);
  assert.ok(await env.DB.prepare('SELECT 1 FROM sm_secret_members WHERE secret_id = ?').bind(secret.id).first());
  assert.ok(await env.DB.prepare('SELECT 1 FROM sm_secret_service_accounts WHERE secret_id = ?').bind(secret.id).first());
  assert.ok((await smRepo.getServiceAccount(env.DB, account.id))!.updatedAt > before);
  assert.deepEqual((await (await request(owner.id, trashPath)).json() as any).secrets, []);
  assert.equal((await request(owner.id, '/api/secrets/delete', 'POST', [secret.id])).status, 200);
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(before, account.id).run();
  const emptied = await request(owner.id, `${trashPath}/empty`, 'POST', [secret.id]);
  assert.equal(emptied.status, 200);
  assert.equal(await emptied.text(), '');
  assert.equal(await smRepo.getSecret(env.DB, secret.id), null);
  assert.equal(await env.DB.prepare('SELECT 1 FROM sm_secret_members WHERE secret_id = ?').bind(secret.id).first(), null);
  assert.equal(await env.DB.prepare('SELECT 1 FROM sm_secret_service_accounts WHERE secret_id = ?').bind(secret.id).first(), null);
  assert.ok((await smRepo.getServiceAccount(env.DB, account.id))!.updatedAt > before);
  assert.ok(await smRepo.getSecret(env.DB, outside.id));
});

test('emptying 150 trash rows stays under the D1 cap and rolls back every chunk and revision on failure', async () => {
  const { env, orgId, owner, account, request, trashPath } = await setup();
  const ids = Array.from({ length: 150 }, () => crypto.randomUUID()).sort();
  const before = '2020-01-01T00:00:00.000Z';
  const now = new Date().toISOString();
  await env.DB.batch([
    ...ids.map(id => env.DB.prepare('INSERT INTO sm_secrets (id, org_id, key, value, note, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(id, orgId, FIELDS.key, FIELDS.value, FIELDS.note, now, now, now)),
    env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(before, account.id),
  ]);
  await env.DB.exec(`CREATE TRIGGER fail_last_trash BEFORE DELETE ON sm_secrets WHEN OLD.id = '${ids.at(-1)}' BEGIN SELECT RAISE(ABORT, 'test trash rollback'); END;`);
  assert.equal((await request(owner.id, `${trashPath}/empty`, 'POST', ids)).status, 500);
  assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM sm_secrets WHERE org_id = ?').bind(orgId).first<{ n: number }>())!.n, ids.length);
  assert.equal((await smRepo.getServiceAccount(env.DB, account.id))!.updatedAt, before);
  await env.DB.exec('DROP TRIGGER fail_last_trash;');
  const response = await request(owner.id, `${trashPath}/empty`, 'POST', ids);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), '');
  assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM sm_secrets WHERE org_id = ?').bind(orgId).first<{ n: number }>())!.n, 0);
  assert.ok((await smRepo.getServiceAccount(env.DB, account.id))!.updatedAt > before);
});

test('scheduled trash purge removes 31-day rows while preserving 29-day trash and live secrets', async () => {
  const { env, orgId } = await setup();
  const now = Date.parse('2026-09-27T12:00:00.000Z');
  const day = 86_400_000;
  const ids = [crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()];
  await env.DB.batch([31, 29, null].map((age, index) => env.DB.prepare('INSERT INTO sm_secrets (id, org_id, key, value, note, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(ids[index], orgId, FIELDS.key, FIELDS.value, FIELDS.note, new Date(now - 40 * day).toISOString(), new Date(now - 40 * day).toISOString(), age === null ? null : new Date(now - age * day).toISOString())));
  await smRepo.purgeSecretsTrash(env.DB, now);
  assert.equal(await smRepo.getSecret(env.DB, ids[0]), null);
  assert.ok((await smRepo.getSecret(env.DB, ids[1]))!.deletedAt);
  assert.equal((await smRepo.getSecret(env.DB, ids[2]))!.deletedAt, null);
});
