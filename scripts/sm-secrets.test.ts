import assert from 'node:assert/strict';
import test from 'node:test';

import { handleDeleteSecrets, handleUpdateSecret } from '../src/handlers/secrets-manager';
import { MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import * as smRepo from '../src/services/storage-secret-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const a = await seedMember(env, orgId, MembershipType.User);
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  const project = async (user = owner) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const secret = async (projectIds: string[] = [], user = owner) => postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds });
  return { env, orgId, owner, a, request, project, secret };
}

test('secret lists combine project and direct grants, retain project names, and isolate project routes by org', async () => {
  const { env, orgId, owner, a, request, project, secret } = await setup();
  const own = await project(a);
  const shared = await project();
  const hidden = await project();
  const writable = await secret([own.id]);
  const readable = await secret([shared.id]);
  const unreadable = await secret([hidden.id]);
  const direct = await secret();
  const groupSecret = await secret();
  const membership = await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId);
  const groupId = crypto.randomUUID();
  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO org_groups (id, org_id, name, access_all, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)').bind(groupId, orgId, 'Readers', now, now),
    env.DB.prepare('INSERT INTO org_group_members (group_id, membership_id) VALUES (?, ?)').bind(groupId, membership!.id),
    env.DB.prepare('INSERT INTO sm_project_groups (project_id, group_id, write_access) VALUES (?, ?, 0)').bind(shared.id, groupId),
    env.DB.prepare('INSERT INTO sm_secret_members (secret_id, membership_id, write_access) VALUES (?, ?, 1)').bind(direct.id, membership!.id),
    env.DB.prepare('INSERT INTO sm_secret_groups (secret_id, group_id, write_access) VALUES (?, ?, 0)').bind(groupSecret.id, groupId),
  ]);
  const listed = await request(a.id, `/api/organizations/${orgId}/secrets`);
  assert.equal(listed.status, 200);
  const body = await listed.json() as any;
  assert.equal(body.object, 'SecretsWithProjectsList');
  assert.deepEqual(new Set(body.secrets.map((item: any) => item.id)), new Set([writable.id, readable.id, direct.id, groupSecret.id]));
  assert.deepEqual(new Set(body.projects.map((item: any) => item.id)), new Set([own.id, shared.id]));
  assert.ok(body.projects.every((item: any) => item.name === ENCRYPTED_FIELD));
  for (const item of body.secrets) {
    assert.equal(item.read, true);
    assert.equal(item.write, item.id === writable.id || item.id === direct.id);
    assert.equal('value' in item, false);
    assert.equal('note' in item, false);
    assert.ok(item.projects.every((p: any) => p.name === ENCRYPTED_FIELD));
  }
  const detail = await request(a.id, `/api/secrets/${readable.id}`);
  assert.equal(detail.status, 200);
  assert.deepEqual((await detail.json() as any).projects, [{ id: shared.id, name: ENCRYPTED_FIELD }]);
  assert.equal((await request(a.id, `/api/secrets/${unreadable.id}`)).status, 404);
  assert.equal((await request(a.id, `/api/secrets/${readable.id}`, 'PUT', { ...FIELDS, projectIds: [shared.id] })).status, 404);
  assert.equal((await request(a.id, `/api/secrets/${direct.id}`, 'PUT', { ...FIELDS, projectIds: [] })).status, 200);

  const foreign = await seedSmOrg(env);
  const foreignSecret = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/secrets`, FIELDS);
  await env.DB.prepare('INSERT INTO sm_secret_projects (secret_id, project_id) VALUES (?, ?)').bind(foreignSecret.id, own.id).run();
  const byProject = await request(owner.id, `/api/projects/${own.id}/secrets`);
  assert.equal(byProject.status, 200);
  assert.deepEqual((await byProject.json() as any).secrets.map((item: any) => item.id), [writable.id]);
  assert.equal((await request(foreign.owner.id, `/api/projects/${own.id}/secrets`)).status, 404);
});

test('secret create and move validate encrypted fields, one same-org project, and project write access', async () => {
  const { env, orgId, owner, a, request, project, secret } = await setup();
  const own = await project(a);
  const denied = await project();
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId);
  await env.DB.prepare('INSERT INTO sm_project_members (project_id, membership_id, write_access) VALUES (?, ?, 0)').bind(denied.id, member!.id).run();
  const path = `/api/organizations/${orgId}/secrets`;
  for (const body of [null, { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD }, { ...FIELDS, key: 'plaintext' }, { ...FIELDS, note: null }, { ...FIELDS, value: '2.' + 'a'.repeat(35000) + '|a|a' }]) {
    const response = await request(owner.id, path, 'POST', body);
    assert.equal(response.status, 400);
    assert.equal(typeof (await response.json() as any).message, 'string');
  }
  assert.equal((await request(a.id, path, 'POST', { ...FIELDS, projectIds: [] })).status, 404);
  assert.equal((await request(a.id, path, 'POST', { ...FIELDS, projectIds: [denied.id] })).status, 404);
  const many = await request(owner.id, path, 'POST', { ...FIELDS, projectIds: [own.id, denied.id] });
  assert.equal(many.status, 400);
  assert.deepEqual((await many.json() as any).validationErrors, { ProjectIds: ['Only one project assignment is supported.'] });
  const created = await secret([own.id], a);
  const secretPath = `/api/secrets/${created.id}`;
  for (const projectIds of [[denied.id], []]) assert.equal((await request(a.id, secretPath, 'PUT', { ...FIELDS, projectIds })).status, 404);
  const foreign = await seedSmOrg(env);
  const foreignProject = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/projects`, { name: ENCRYPTED_FIELD });
  assert.equal((await request(owner.id, secretPath, 'PUT', { ...FIELDS, projectIds: [foreignProject.id] })).status, 404);
  const removed = await request(owner.id, secretPath, 'PUT', { ...FIELDS, projectIds: [] });
  assert.equal(removed.status, 200);
  const updated = await removed.json() as any;
  assert.deepEqual(updated.projects, []);
  assert.equal(updated.read, true);
  assert.equal(updated.write, true);
  const projectless = await secret();
  assert.equal((await request(owner.id, `/api/secrets/${projectless.id}`)).status, 200);
});

test('get-by-ids and bulk delete reject incomplete or mixed-org sets before writing', async () => {
  const { env, orgId, owner, a, request, project, secret } = await setup();
  const own = await project(a);
  const allowed = await secret([own.id]);
  const denied = await secret();
  const get = await request(a.id, '/api/secrets/get-by-ids', 'POST', { ids: [allowed.id] });
  assert.equal(get.status, 200);
  const body = await get.json() as any;
  assert.equal(body.object, 'list');
  assert.equal(body.continuationToken, null);
  assert.equal(body.data[0].id, allowed.id);
  assert.equal(body.data[0].object, 'baseSecret');
  assert.equal(body.data[0].value, ENCRYPTED_FIELD);
  assert.equal('read' in body.data[0], false);
  assert.equal('write' in body.data[0], false);
  assert.equal((await request(a.id, '/api/secrets/get-by-ids', 'POST', { ids: [allowed.id, denied.id] })).status, 404);
  const foreign = await seedSmOrg(env);
  const outside = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/secrets`, FIELDS);
  for (const ids of [[], [allowed.id, allowed.id], [allowed.id, crypto.randomUUID()], [allowed.id, outside.id]]) {
    assert.equal((await request(owner.id, '/api/secrets/delete', 'POST', ids)).status, 404);
    assert.equal((await smRepo.getSecret(env.DB, allowed.id))!.deletedAt, null);
  }
  const deleted = await request(a.id, '/api/secrets/delete', 'POST', [allowed.id, denied.id]);
  assert.equal(deleted.status, 200);
  assert.deepEqual(new Map((await deleted.json() as any).data.map((item: any) => [item.id, item])), new Map([
    [allowed.id, { id: allowed.id, error: null, object: 'BulkDeleteResponseModel' }],
    [denied.id, { id: denied.id, error: 'access denied', object: 'BulkDeleteResponseModel' }],
  ]));
  assert.equal((await request(owner.id, `/api/secrets/${allowed.id}`)).status, 404);
  assert.equal((await request(owner.id, '/api/secrets/get-by-ids', 'POST', { ids: [allowed.id] })).status, 404);
  assert.equal((await request(owner.id, '/api/secrets/delete', 'POST', [allowed.id])).status, 404);
  assert.equal((await smRepo.getSecret(env.DB, denied.id))!.deletedAt, null);
  assert.deepEqual((await (await request(owner.id, `/api/organizations/${orgId}/secrets`)).json() as any).secrets.map((item: any) => item.id), [denied.id]);
});

test('secret PUT never revives a trashed or deleted row, or rewrites an unchanged stale project mapping', async () => {
  const { env, owner, request, project, secret } = await setup();
  const oldProject = await project();
  const newProject = await project();
  const trashed = await secret([oldProject.id]);
  const put = new Request('https://vault.example.test', { method: 'PUT' });
  const deletedAt = '2026-01-01T00:00:00.000Z';
  put.json = async () => {
    await env.DB.prepare('UPDATE sm_secrets SET deleted_at = ? WHERE id = ?').bind(deletedAt, trashed.id).run();
    return { ...FIELDS, projectIds: [newProject.id] };
  };
  assert.equal((await handleUpdateSecret(put, env, owner.id, trashed.id)).status, 404);
  const persisted = await smRepo.getSecret(env.DB, trashed.id);
  assert.equal(persisted!.deletedAt, deletedAt);
  assert.deepEqual(persisted!.projectIds, [oldProject.id]);
  assert.equal((await request(owner.id, `/api/secrets/${trashed.id}`)).status, 404);

  const removed = await secret([oldProject.id]);
  put.json = async () => {
    await env.DB.prepare('DELETE FROM sm_secrets WHERE id = ?').bind(removed.id).run();
    return { ...FIELDS, projectIds: [oldProject.id] };
  };
  assert.equal((await handleUpdateSecret(put, env, owner.id, removed.id)).status, 404);
  assert.equal(await smRepo.getSecret(env.DB, removed.id), null);

  const moved = await secret([oldProject.id]);
  put.json = async () => {
    await env.DB.prepare('UPDATE sm_secret_projects SET project_id = ? WHERE secret_id = ?').bind(newProject.id, moved.id).run();
    return { ...FIELDS, projectIds: [oldProject.id] };
  };
  assert.equal((await handleUpdateSecret(put, env, owner.id, moved.id)).status, 404);
  assert.deepEqual((await smRepo.getSecret(env.DB, moved.id))!.projectIds, [newProject.id]);
});

test('150-secret bulk delete chunks parameters and rolls back every chunk and SA revision on failure', async () => {
  const { env, orgId, owner, request } = await setup();
  const before = '2020-01-01T00:00:00.000Z';
  const accountId = crypto.randomUUID();
  await smRepo.saveServiceAccount(env.DB, { id: accountId, orgId, name: ENCRYPTED_FIELD, createdAt: before, updatedAt: before });
  const ids = Array.from({ length: 150 }, () => crypto.randomUUID());
  await env.DB.batch(ids.map(id => env.DB.prepare('INSERT INTO sm_secrets (id, org_id, key, value, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, orgId, FIELDS.key, FIELDS.value, FIELDS.note, before, before)));
  const get = await request(owner.id, '/api/secrets/get-by-ids', 'POST', { ids });
  assert.equal(get.status, 200);
  assert.equal((await get.json() as any).data.length, ids.length);
  await env.DB.exec(`CREATE TRIGGER fail_last_secret BEFORE UPDATE OF deleted_at ON sm_secrets WHEN NEW.id = '${ids.at(-1)}' BEGIN SELECT RAISE(ABORT, 'test bulk rollback'); END;`);
  const deleteRequest = () => new Request('https://vault.example.test', { method: 'POST', body: JSON.stringify(ids) });
  await assert.rejects(() => handleDeleteSecrets(deleteRequest(), env, owner.id), /test bulk rollback/);
  assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM sm_secrets WHERE deleted_at IS NOT NULL').first<{ n: number }>())!.n, 0);
  assert.equal((await smRepo.getServiceAccount(env.DB, accountId))!.updatedAt, before);
  await env.DB.exec('DROP TRIGGER fail_last_secret;');
  const deleted = await request(owner.id, '/api/secrets/delete', 'POST', ids);
  assert.equal(deleted.status, 200);
  const body = await deleted.json() as any;
  assert.equal(body.data.length, ids.length);
  assert.deepEqual(new Set(body.data.map((item: any) => item.id)), new Set(ids));
  assert.ok(body.data.every((item: any) => item.error === null && item.object === 'BulkDeleteResponseModel'));
  assert.equal((await env.DB.prepare('SELECT COUNT(*) AS n FROM sm_secrets WHERE deleted_at IS NOT NULL').first<{ n: number }>())!.n, ids.length);
  assert.ok((await smRepo.getServiceAccount(env.DB, accountId))!.updatedAt > before);
});

test('a stale member edit cannot overwrite a secret after its project moved or was deleted', async () => {
  const { env, orgId, owner, a, project, secret } = await setup();
  const readable = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const hidden = await project();
  const changed = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';
  for (const move of [true, false]) {
    const source = move ? readable : await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
    const target = await secret([source.id]);
    const put = new Request('https://vault.example.test', { method: 'PUT' });
    put.json = async () => {
      if (move) await env.DB.prepare('UPDATE sm_secret_projects SET project_id = ? WHERE secret_id = ?').bind(hidden.id, target.id).run();
      else await env.DB.prepare('DELETE FROM sm_projects WHERE id = ?').bind(source.id).run();
      return { ...FIELDS, value: changed, projectIds: move ? [source.id] : [readable.id] };
    };
    assert.equal((await handleUpdateSecret(put, env, a.id, target.id)).status, 404);
    const persisted = await smRepo.getSecret(env.DB, target.id);
    assert.equal(persisted!.value, ENCRYPTED_FIELD);
    assert.deepEqual(persisted!.projectIds, move ? [hidden.id] : []);
  }
});

test('a rejected secret snapshot aborts links, policies and machine revision in the same batch', async () => {
  const { env, orgId, owner, a, project, secret } = await setup();
  const p = await project();
  const q = await project();
  const target = await secret([p.id]);
  const before = (await smRepo.getSecret(env.DB, target.id))!;
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const previousAccount = await smRepo.getServiceAccount(env.DB, account.id);
  const member = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  await env.DB.prepare('UPDATE sm_secrets SET updated_at = ? WHERE id = ?').bind('2099-01-01T00:00:00.000Z', target.id).run();
  const policies = [env.DB.prepare('INSERT INTO sm_secret_members (secret_id, membership_id, write_access) VALUES (?, ?, 1)').bind(target.id, member.id)];
  assert.equal(await smRepo.updateSecret(env.DB, { ...before, value: '2.changed|value|mac', projectIds: [q.id], updatedAt: '2099-02-01T00:00:00.000Z' }, before.projectIds, before.updatedAt, policies), false);
  const after = (await smRepo.getSecret(env.DB, target.id))!;
  assert.equal(after.value, before.value);
  assert.deepEqual(after.projectIds, [p.id]);
  assert.equal(await env.DB.prepare('SELECT secret_id FROM sm_secret_members WHERE secret_id = ?').bind(target.id).first(), null);
  assert.deepEqual(await smRepo.getServiceAccount(env.DB, account.id), previousAccount);
});
