import { handleProject } from '../src/handlers/secrets-manager';
import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smUser } from './support/sm';
import * as orgRepo from '../src/services/storage-org-repo';

test('project routes enforce creator and group grants, bulk isolation, encrypted names and counts', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const { user: b } = await seedMember(env, orgId);
  const request = (userId: string, path: string, method = 'GET', body?: unknown) => authedFetch(env, { userId, path, method, body });
  const projectPath = `/api/organizations/${orgId}/projects`;
  assert.deepEqual((await (await request(a.id, projectPath)).json() as any).data, []);
  const p = await postJson<{ id: string }>(env, a, projectPath, { name: ENCRYPTED_FIELD });
  const q = await postJson<{ id: string }>(env, b, projectPath, { name: ENCRYPTED_FIELD });
  assert.equal((await (await request(a.id, `/api/projects/${p.id}`)).json() as any).write, true);
  assert.equal((await request(b.id, `/api/projects/${p.id}`)).status, 404);
  assert.equal((await request(b.id, `/api/projects/${p.id}`, 'PUT', { name: ENCRYPTED_FIELD })).status, 404);
  assert.deepEqual(await (await request(b.id, `/api/projects/${p.id}/sm-counts`)).json(), { secrets: 0, people: 0, serviceAccounts: 0, object: 'projectCounts' });
  assert.equal((await request(a.id, projectPath, 'POST', { name: 'plaintext' })).status, 400);
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, b.id, orgId);
  const group = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare('INSERT INTO org_groups (id, org_id, name, access_all, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?)').bind(group, orgId, 'group', new Date().toISOString(), new Date().toISOString()),
    env.DB.prepare('INSERT INTO org_group_members (group_id, membership_id) VALUES (?, ?)').bind(group, member!.id),
    env.DB.prepare('INSERT INTO sm_project_groups (project_id, group_id, write_access) VALUES (?, ?, 0)').bind(p.id, group),
  ]);
  assert.equal((await (await request(b.id, `/api/projects/${p.id}`)).json() as any).write, false);
  const foreign = await seedSmOrg(env);
  const x = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/projects`, { name: ENCRYPTED_FIELD });
  assert.equal((await request(owner.id, '/api/projects/delete', 'POST', [p.id, x.id])).status, 404);
  assert.equal((await request(foreign.owner.id, `/api/projects/${p.id}`)).status, 404);
  const result = await (await request(b.id, '/api/projects/delete', 'POST', [p.id, q.id])).json() as any;
  assert.deepEqual(result.data.map((item: any) => item.error), ['access denied', null]);
});

test('project updates cannot resurrect a concurrently deleted row and reject null JSON', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const p = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  assert.equal((await authedFetch(env, { userId: owner.id, method: 'PUT', path: `/api/projects/${p.id}`, body: null })).status, 400);
  const request = new Request(`https://example.test/api/projects/${p.id}`, { method: 'PUT' });
  request.json = async () => { await env.DB.prepare('DELETE FROM sm_projects WHERE id = ?').bind(p.id).run(); return { name: ENCRYPTED_FIELD }; };
  assert.equal((await handleProject(request, env, await smUser(env, owner), p.id)).status, 404);
  assert.equal(await env.DB.prepare('SELECT id FROM sm_projects WHERE id = ?').bind(p.id).first(), null);
});
