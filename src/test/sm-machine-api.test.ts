import assert from 'node:assert/strict';
import test from 'node:test';

import { and, eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { smAccessTokens, smProjects, smSecretServiceAccounts, smServiceAccountProjects } from '../db/schema';
import { signHs256Jwt } from '../utils/jwt';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg, smLogin, TOKEN_FIELDS } from './support/sm';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };
const CHANGED = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const token = await postJson<{ id: string; clientSecret: string }>(env, owner, `/api/service-accounts/${account.id}/access-tokens`, TOKEN_FIELDS);
  const login = await smLogin(env, token.id, token.clientSecret);
  assert.equal(login.status, 200);
  const { access_token: jwt } = await login.json() as { access_token: string };
  const request = (path: string, method = 'GET', body?: unknown, bearer = jwt) => authedFetch(env, { path, method, body, headers: { Authorization: `Bearer ${bearer}` } });
  const project = async () => postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  return { env, orgId, owner, account, token, jwt, request, project };
}

test('machine JWTs enforce project and direct secret grants across CRUD and preserve SDK-omitted policies', async () => {
  const { env, orgId, owner, account, request, project } = await setup();
  const writable = await project();
  const readonly = await project();
  const hidden = await project();
  const secret = async (projectId: string) => postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, projectIds: [projectId] });
  const visibleSecret = await secret(writable.id);
  const hiddenSecret = await secret(hidden.id);
  const grants = await authedFetch(env, { userId: owner.id, path: `/api/service-accounts/${account.id}/granted-policies`, method: 'PUT', body: { projectGrantedPolicyRequests: [{ grantedId: writable.id, read: true, write: true }, { grantedId: readonly.id, read: true, write: false }] } });
  assert.equal(grants.status, 200);
  const direct = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { ...FIELDS, accessPoliciesRequests: { userAccessPolicyRequests: [], groupAccessPolicyRequests: [], serviceAccountAccessPolicyRequests: [{ granteeId: account.id, read: true, write: true }] } });
  const listed = await request(`/api/organizations/${orgId}/projects`);
  assert.equal(listed.status, 200);
  assert.deepEqual(new Map((await listed.json() as any).data.map((p: any) => [p.id, p.write])), new Map([[writable.id, true], [readonly.id, false]]));
  assert.equal((await request(`/api/projects/${hidden.id}`)).status, 404);
  assert.equal((await request(`/api/secrets/${hiddenSecret.id}`)).status, 404);
  const list = await request(`/api/organizations/${orgId}/secrets`);
  assert.equal(list.status, 200);
  assert.deepEqual(new Set((await list.json() as any).secrets.map((s: any) => s.id)), new Set([visibleSecret.id, direct.id]));
  assert.equal((await request(`/api/projects/${writable.id}/secrets`)).status, 200);
  assert.equal((await request('/api/secrets/get-by-ids', 'POST', { ids: [visibleSecret.id, direct.id] })).status, 200);
  assert.equal((await request('/api/secrets/get-by-ids', 'POST', { ids: [visibleSecret.id, hiddenSecret.id] })).status, 404);
  assert.equal((await request(`/api/organizations/${orgId}/secrets`, 'POST', { ...FIELDS, projectIds: [readonly.id] })).status, 404);
  assert.equal((await request(`/api/organizations/${orgId}/secrets`, 'POST', FIELDS)).status, 404);
  const edited = await request(`/api/secrets/${direct.id}`, 'PUT', { ...FIELDS, value: CHANGED, projectIds: [] });
  assert.equal(edited.status, 200);
  assert.equal((await edited.json() as any).value, CHANGED);
  const orm = getOrm(env.DB);
  assert.ok(await orm.select().from(smSecretServiceAccounts).where(and(eq(smSecretServiceAccounts.secretId, direct.id), eq(smSecretServiceAccounts.serviceAccountId, account.id), eq(smSecretServiceAccounts.writeAccess, 1))).get());
  const policyWrite = await request(`/api/secrets/${direct.id}`, 'PUT', { ...FIELDS, projectIds: [], accessPoliciesRequests: { userAccessPolicyRequests: [], groupAccessPolicyRequests: [], serviceAccountAccessPolicyRequests: [{ granteeId: account.id, read: true, write: true }] } });
  assert.equal(policyWrite.status, 404);

  const createdProject = await request(`/api/organizations/${orgId}/projects`, 'POST', { name: ENCRYPTED_FIELD });
  assert.equal(createdProject.status, 200);
  const p = await createdProject.json() as { id: string };
  assert.ok(await orm.select().from(smServiceAccountProjects).where(and(eq(smServiceAccountProjects.projectId, p.id), eq(smServiceAccountProjects.serviceAccountId, account.id), eq(smServiceAccountProjects.readAccess, 1), eq(smServiceAccountProjects.writeAccess, 1))).get());
  assert.equal((await request(`/api/projects/${p.id}`, 'PUT', { name: CHANGED })).status, 200);
  assert.equal((await (await request(`/api/projects/${p.id}`)).json() as any).name, CHANGED);
  const createdSecret = await request(`/api/organizations/${orgId}/secrets`, 'POST', { ...FIELDS, projectIds: [p.id] });
  assert.equal(createdSecret.status, 200);
  const s = await createdSecret.json() as { id: string };
  assert.equal((await request(`/api/secrets/${s.id}`, 'PUT', { ...FIELDS, value: CHANGED, projectIds: [p.id] })).status, 200);
  const deleted = await request('/api/secrets/delete', 'POST', [s.id, hiddenSecret.id]);
  assert.equal(deleted.status, 200);
  assert.deepEqual(new Map((await deleted.json() as any).data.map((item: any) => [item.id, item.error])), new Map([[s.id, null], [hiddenSecret.id, 'access denied']]));
  assert.equal((await request('/api/projects/delete', 'POST', [p.id])).status, 200);
  assert.equal((await request(`/api/projects/${p.id}`)).status, 404);
});

test('machine allowlist rejects every human-only SM route and other org resources while user routes still work', async () => {
  const { env, orgId, owner, account, request, project } = await setup();
  const p = await project();
  const s = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, FIELDS);
  const orgPath = `/api/organizations/${orgId}`;
  const saPath = `/api/service-accounts/${account.id}`;
  const routes: [string, string][] = [
    ['GET', `${orgPath}/service-accounts`], ['POST', `${orgPath}/service-accounts`],
    ['GET', saPath], ['PUT', saPath], ['POST', '/api/service-accounts/delete'],
    ['GET', `${saPath}/access-tokens`], ['POST', `${saPath}/access-tokens`], ['POST', `${saPath}/access-tokens/revoke`],
    ['GET', `${orgPath}/access-policies/people/potential-grantees`], ['GET', `${orgPath}/access-policies/projects/potential-grantees`], ['GET', `${orgPath}/access-policies/service-accounts/potential-grantees`],
    ['GET', `/api/projects/${p.id}/access-policies/people`], ['PUT', `/api/projects/${p.id}/access-policies/people`],
    ['GET', `${saPath}/access-policies/people`], ['PUT', `${saPath}/access-policies/people`],
    ['GET', `/api/projects/${p.id}/access-policies/service-accounts`], ['PUT', `/api/projects/${p.id}/access-policies/service-accounts`],
    ['GET', `${saPath}/granted-policies`], ['PUT', `${saPath}/granted-policies`], ['GET', `/api/secrets/${s.id}/access-policies`],
    ['GET', `${orgPath}/sm-counts`], ['GET', `/api/projects/${p.id}/sm-counts`], ['GET', `${saPath}/sm-counts`],
    ['GET', `/api/secrets/${orgId}/trash`], ['POST', `/api/secrets/${orgId}/trash/empty`], ['POST', `/api/secrets/${orgId}/trash/restore`],
    ['PUT', `${orgPath}/users/enable-secrets-manager`], ['GET', `/api/sm/events/service-accounts/${account.id}`],
    ['GET', `/api/organization/${orgId}/secrets/${s.id}/events`], ['GET', `/api/organization/${orgId}/service-account/${account.id}/events`], ['GET', `/api/organization/${orgId}/projects/${p.id}/events`],
    ['GET', '/api/sync'], ['GET', '/api/accounts/profile'], ['PUT', '/api/accounts/profile'], ['GET', '/api/ciphers'],
    ['DELETE', `/api/projects/${p.id}`], ['DELETE', `/api/secrets/${s.id}`],
  ];
  for (const [method, path] of routes) assert.equal((await request(path, method, method === 'GET' ? undefined : {})).status, 404, `${method} ${path}`);
  const foreign = await seedSmOrg(env);
  const foreignProject = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/projects`, { name: ENCRYPTED_FIELD });
  const foreignSecret = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/secrets`, FIELDS);
  for (const path of [`/api/organizations/${foreign.orgId}/projects`, `/api/organizations/${foreign.orgId}/secrets`, `/api/projects/${foreignProject.id}`, `/api/projects/${foreignProject.id}/secrets`, `/api/secrets/${foreignSecret.id}`]) {
    assert.equal((await request(path)).status, 404, path);
  }
  for (const collection of ['projects', 'secrets']) assert.equal((await request(`/api/organizations/${foreign.orgId}/${collection}`, 'POST', { name: ENCRYPTED_FIELD, ...FIELDS })).status, 404);
  assert.equal((await request('/api/projects/delete', 'POST', [p.id, foreignProject.id])).status, 404);
  assert.equal((await request('/api/secrets/delete', 'POST', [s.id, foreignSecret.id])).status, 404);
  assert.equal((await authedFetch(env, { userId: owner.id, path: '/api/sync' })).status, 200);
  assert.equal((await authedFetch(env, { userId: owner.id, path: `${orgPath}/service-accounts` })).status, 200);
});

test('machine revocation, token expiry and account deletion take effect on the next API call and notifications reject machines', async () => {
  const { env, orgId, owner, account, token, jwt, request } = await setup();
  const path = `/api/organizations/${orgId}/projects`;
  assert.equal((await request(path)).status, 200);
  assert.equal((await request('/notifications/hub/negotiate', 'POST')).status, 401);
  const revoked = await authedFetch(env, { userId: owner.id, path: `/api/service-accounts/${account.id}/access-tokens/revoke`, method: 'POST', body: { ids: [token.id] } });
  assert.equal(revoked.status, 200);
  assert.equal((await request(path, 'GET', undefined, jwt)).status, 401);
  const nextToken = await postJson<{ id: string; clientSecret: string }>(env, owner, `/api/service-accounts/${account.id}/access-tokens`, TOKEN_FIELDS);
  const login = await smLogin(env, nextToken.id, nextToken.clientSecret);
  const nextJwt = (await login.json() as any).access_token;
  assert.equal((await request(path, 'GET', undefined, nextJwt)).status, 200);
  await getOrm(env.DB).update(smAccessTokens).set({ expireAt: '2020-01-01T00:00:00.000Z' }).where(eq(smAccessTokens.id, nextToken.id));
  assert.equal((await request(path, 'GET', undefined, nextJwt)).status, 401);
  await getOrm(env.DB).update(smAccessTokens).set({ expireAt: null }).where(eq(smAccessTokens.id, nextToken.id));
  assert.equal((await request(path, 'GET', undefined, nextJwt)).status, 200);
  assert.equal((await authedFetch(env, { userId: owner.id, path: '/api/service-accounts/delete', method: 'POST', body: [account.id] })).status, 200);
  assert.equal((await request(path, 'GET', undefined, nextJwt)).status, 401);
});

test('machine authentication rejects signed tokens with malformed or mismatched principal claims', async () => {
  const { env, orgId, owner, jwt, request } = await setup();
  const claims = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
  for (const patch of [
    { scope: 'api.secrets' }, { scope: [] }, { scope: ['api'] }, { scope: undefined },
    { organization: undefined }, { organization: {} }, { organization: crypto.randomUUID() },
    { client_id: undefined }, { client_id: {} }, { client_id: crypto.randomUUID() },
    { sub: owner.id }, { sub: undefined }, { type: 'serviceAccount' }, { exp: 1 },
  ]) {
    const invalid = await signHs256Jwt({ ...claims, ...patch }, env.JWT_SECRET);
    assert.equal((await request(`/api/organizations/${orgId}/projects`, 'GET', undefined, invalid)).status, 401, JSON.stringify(patch));
  }
});

test('machine mutation failures use the API error response and roll back creator grants', async () => {
  const { env, orgId, request } = await setup();
  // eslint-disable-next-line nodewarden/no-raw-sql -- a trigger is DDL with no drizzle builder; it fails the creator grant inside SQLite
  await env.DB.exec("CREATE TRIGGER fail_machine_project BEFORE INSERT ON sm_service_account_projects BEGIN SELECT RAISE(ABORT, 'test machine project failure'); END;");
  const response = await request(`/api/organizations/${orgId}/projects`, 'POST', { name: ENCRYPTED_FIELD });
  assert.equal(response.status, 500);
  assert.equal((await response.json() as any).message, 'Internal server error');
  assert.equal(await getOrm(env.DB).$count(smProjects, eq(smProjects.orgId, orgId)), 0);
});
