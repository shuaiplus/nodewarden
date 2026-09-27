import assert from 'node:assert/strict';
import test from 'node:test';

import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg, smLogin, TOKEN_FIELDS } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const token = await postJson<{ id: string; clientSecret: string }>(env, owner, `/api/service-accounts/${account.id}/access-tokens`, TOKEN_FIELDS);
  const login = await smLogin(env, token.id, token.clientSecret);
  assert.equal(login.status, 200);
  const jwt = (await login.json() as { access_token: string }).access_token;
  const sync = (date?: string, targetOrg = orgId) => authedFetch(env, { path: `/api/organizations/${targetOrg}/secrets/sync${date === undefined ? '' : `?lastSyncedDate=${encodeURIComponent(date)}`}`, headers: { Authorization: `Bearer ${jwt}` } });
  const project = () => postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const grant = (projectIds: string[]) => authedFetch(env, { userId: owner.id, path: `/api/service-accounts/${account.id}/granted-policies`, method: 'PUT', body: { projectGrantedPolicyRequests: projectIds.map(grantedId => ({ grantedId, read: true, write: false })) } });
  return { env, orgId, owner, account, token, sync, project, grant };
}

test('machine sync returns nested readable secrets and observes revisions, deletes, and grant revocation', async () => {
  const { env, orgId, owner, account, sync, project, grant } = await setup();
  const p = await project();
  const hidden = await project();
  const secret = (projectId: string) => postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds: [projectId] });
  const first = await secret(p.id);
  const second = await secret(p.id);
  await secret(hidden.id);
  const empty = await sync();
  assert.equal(empty.status, 200);
  assert.deepEqual(await empty.json(), { hasChanges: true, secrets: { data: [], object: 'list', continuationToken: null }, object: 'secretsSync' });
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind('2020-01-01T00:00:00.000Z', account.id).run();
  assert.deepEqual(await (await sync('2021-01-01T00:00:00.000Z')).json(), { hasChanges: false, secrets: null, object: 'secretsSync' });
  assert.equal((await (await sync('2020-01-01T01:00:00+01:00')).json() as any).hasChanges, true);
  assert.equal((await grant([p.id])).status, 200);
  const direct = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, accessPoliciesRequests: { userAccessPolicyRequests: [], groupAccessPolicyRequests: [], serviceAccountAccessPolicyRequests: [{ granteeId: account.id, read: true, write: false }] } });
  const granted = await sync('2021-01-01T00:00:00.000Z');
  assert.equal(granted.status, 200);
  const body = await granted.json() as any;
  assert.equal(body.hasChanges, true);
  assert.equal(body.secrets.object, 'list');
  assert.equal(body.secrets.continuationToken, null);
  assert.deepEqual(new Set(body.secrets.data.map((item: any) => item.id)), new Set([first.id, second.id, direct.id]));
  for (const item of body.secrets.data) {
    assert.equal(item.object, 'baseSecret');
    assert.equal(item.value, ENCRYPTED_FIELD);
    assert.equal(item.note, ENCRYPTED_FIELD);
    assert.equal('read' in item, false);
    assert.equal('write' in item, false);
  }
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind('2020-01-01T00:00:00.000Z', account.id).run();
  assert.equal((await authedFetch(env, { userId: owner.id, path: '/api/secrets/delete', method: 'POST', body: [first.id] })).status, 200);
  const afterDelete = await (await sync('2021-01-01T00:00:00.000Z')).json() as any;
  assert.equal(afterDelete.hasChanges, true);
  assert.deepEqual(new Set(afterDelete.secrets.data.map((item: any) => item.id)), new Set([second.id, direct.id]));
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind('2020-01-01T00:00:00.000Z', account.id).run();
  assert.equal((await grant([])).status, 200);
  const revoked = await (await sync('2021-01-01T00:00:00.000Z')).json() as any;
  assert.equal(revoked.hasChanges, true);
  assert.deepEqual(revoked.secrets.data.map((item: any) => item.id), [direct.id]);
});

test('sync validates dates before org access, rejects human callers appropriately, and never accepts raw credentials', async () => {
  const { env, orgId, owner, token, sync } = await setup();
  const unknownOrg = crypto.randomUUID();
  const future = new Date(Date.now() + 86_400_000).toISOString();
  for (const org of [orgId, unknownOrg]) {
    for (const date of ['not-a-date', future]) assert.equal((await sync(date, org)).status, 400);
  }
  assert.equal((await sync(undefined, unknownOrg)).status, 404);
  const human = await authedFetch(env, { userId: owner.id, path: `/api/organizations/${orgId}/secrets/sync` });
  assert.equal(human.status, 400);
  assert.equal((await human.json() as any).message, 'Only service accounts can sync secrets.');
  const outsider = await seedSmOrg(env);
  assert.equal((await authedFetch(env, { userId: outsider.owner.id, path: `/api/organizations/${orgId}/secrets/sync` })).status, 404);
  assert.equal((await authedFetch(env, { userId: outsider.owner.id, path: `/api/organizations/${orgId}/secrets/sync?lastSyncedDate=not-a-date` })).status, 400);
  const raw = await authedFetch(env, { path: `/api/organizations/${orgId}/secrets/sync`, headers: { Authorization: `Bearer ${token.id}:${token.clientSecret}` } });
  assert.equal(raw.status, 401);
});

test('machine sync returns all 150 granted secrets and project names without exceeding D1 parameters', async () => {
  const { env, orgId, sync, project, grant } = await setup();
  const p = await project();
  assert.equal((await grant([p.id])).status, 200);
  const ids = Array.from({ length: 150 }, () => crypto.randomUUID());
  const now = new Date().toISOString();
  await env.DB.batch(ids.flatMap(id => [
    env.DB.prepare('INSERT INTO sm_secrets (id, org_id, key, value, note, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').bind(id, orgId, FIELDS.key, FIELDS.value, FIELDS.note, now, now),
    env.DB.prepare('INSERT INTO sm_secret_projects (secret_id, project_id) VALUES (?, ?)').bind(id, p.id),
  ]));
  const response = await sync();
  assert.equal(response.status, 200);
  const body = await response.json() as any;
  assert.equal(body.hasChanges, true);
  assert.equal(body.secrets.data.length, ids.length);
  assert.deepEqual(new Set(body.secrets.data.map((item: any) => item.id)), new Set(ids));
  assert.ok(body.secrets.data.every((item: any) => item.projects.length === 1 && item.projects[0].id === p.id && item.projects[0].name === ENCRYPTED_FIELD));
});
