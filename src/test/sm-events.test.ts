import assert from 'node:assert/strict';
import test from 'node:test';
import { and, eq } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { events as eventLog, orgGroups, smSecrets, smServiceAccountMembers, smServiceAccounts } from '../db/schema';
import { abortWrites, authedFetch, createTestEnv, wrapStatements } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smLogin, TOKEN_FIELDS } from './support/sm';
import { MembershipType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';

const FIELDS = { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD };
const CHANGED = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';
const policy = (granteeId: string, write = true) => ({ granteeId, read: true, write });

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user } = await seedMember(env, orgId);
  const project = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, {
    name: ENCRYPTED_FIELD,
  });
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, FIELDS);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, {
    name: ENCRYPTED_FIELD,
  });
  const request = (path: string, method = 'GET', body?: unknown, userId = owner.id) =>
    authedFetch(env, { userId, path, method, body });
  const events = async (path: string, userId = owner.id) => {
    const response = await request(path, 'GET', undefined, userId);
    assert.equal(response.status, 200);
    const body = (await response.json()) as {
      data: Array<Record<string, any>>;
      object: string;
      continuationToken: string | null;
    };
    assert.equal(body.object, 'list');
    assert.equal(body.continuationToken, null);
    return body.data;
  };
  const count = () => getOrm(env.DB).$count(eventLog, eq(eventLog.organizationId, orgId));
  return { env, orgId, owner, user, project, secret, account, request, events, count };
}

test('SM event routes enforce audit permission, secret read access, tenant scope and deleted history', async () => {
  const { env, orgId, owner, user, project, secret, account, request, events } = await setup();
  const projectPath = `/api/organization/${orgId}/projects/${project.id}/events`;
  const secretPath = `/api/organization/${orgId}/secrets/${secret.id}/events`;
  const accountPath = `/api/organization/${orgId}/service-account/${account.id}/events`;
  const alternate = `/api/sm/events/service-accounts/${account.id}`;
  assert.deepEqual(
    (await events(projectPath)).map((e) => e.type),
    [2201],
  );
  assert.deepEqual(
    (await events(secretPath)).map((e) => e.type),
    [2101],
  );
  assert.deepEqual(new Set((await events(accountPath)).map((e) => e.type)), new Set([2300, 2304]));
  for (const path of [projectPath, secretPath, accountPath])
    assert.equal((await request(path, 'GET', undefined, user.id)).status, 404);
  assert.equal((await request(alternate, 'GET', undefined, user.id)).status, 404);
  const ownerMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!;
  const userMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId))!;
  assert.equal(
    (
      await request(`/api/service-accounts/${account.id}/access-policies/people`, 'PUT', {
        userAccessPolicyRequests: [policy(ownerMember.id), policy(userMember.id)],
      })
    ).status,
    200,
  );
  assert.ok((await events(alternate, user.id)).some((e) => e.type === 2304));
  assert.equal((await request(accountPath, 'GET', undefined, user.id)).status, 404);
  await orgRepo.saveMembership(env.DB, {
    ...userMember,
    type: MembershipType.Custom,
    permissions: { accessEventLogs: true } as any,
  });
  assert.equal((await request(projectPath, 'GET', undefined, user.id)).status, 200);
  assert.equal((await request(accountPath, 'GET', undefined, user.id)).status, 200);
  assert.equal((await request(secretPath, 'GET', undefined, user.id)).status, 404);
  assert.equal(
    (
      await request(`/api/secrets/${secret.id}`, 'PUT', {
        ...FIELDS,
        accessPoliciesRequests: {
          userAccessPolicyRequests: [policy(userMember.id, false)],
          groupAccessPolicyRequests: [],
          serviceAccountAccessPolicyRequests: [],
        },
      })
    ).status,
    200,
  );
  assert.equal((await request(secretPath, 'GET', undefined, user.id)).status, 200);
  const other = await postJson<{ id: string }>(env, owner, '/api/organizations', { name: 'Other', key: '4.dGVzdA==' });
  for (const [kind, id] of [
    ['projects', project.id],
    ['secrets', secret.id],
    ['service-account', account.id],
  ]) {
    assert.equal((await request(`/api/organization/${other.id}/${kind}/${id}/events`)).status, 404);
  }
  assert.equal((await request(`/api/organization/${crypto.randomUUID()}/projects/${project.id}/events`)).status, 404);
  assert.equal((await request('/api/projects/delete', 'POST', [project.id])).status, 200);
  assert.equal((await request('/api/service-accounts/delete', 'POST', [account.id])).status, 200);
  assert.equal((await request('/api/secrets/delete', 'POST', [secret.id])).status, 200);
  assert.ok((await events(projectPath, user.id)).some((e) => e.type === 2203));
  assert.ok((await events(accountPath, user.id)).some((e) => e.type === 2305));
  assert.ok((await events(secretPath)).some((e) => e.type === 2103));
  assert.equal((await request(secretPath, 'GET', undefined, user.id)).status, 404);
  assert.equal((await request(alternate)).status, 404);
  assert.equal((await request(`/api/secrets/${orgId}/trash/empty`, 'POST', [secret.id])).status, 200);
  assert.ok((await events(secretPath)).some((e) => e.type === 2104));
  assert.equal((await request(secretPath, 'GET', undefined, user.id)).status, 404);
  assert.deepEqual(await events(`/api/organization/${other.id}/secrets/${secret.id}/events`), []);
});

test('SM records completed lifecycle actions and partial bulk successes without encrypted payloads', async () => {
  const { env, orgId, owner, user, project, secret, request, events, count } = await setup();
  const beforeDenied = await count();
  assert.equal((await request(`/api/secrets/${secret.id}`, 'GET', undefined, user.id)).status, 404);
  assert.equal((await request(`/api/projects/${project.id}`, 'PUT', { name: 'plaintext' })).status, 400);
  assert.equal(await count(), beforeDenied);
  assert.equal(
    (await authedFetch(env, { userId: owner.id, path: `/api/secrets/${secret.id}`, headers: { 'Device-Type': '8' } }))
      .status,
    200,
  );
  assert.equal((await request('/api/secrets/get-by-ids', 'POST', { ids: [secret.id] })).status, 200);
  assert.equal((await request(`/api/secrets/${secret.id}`, 'PUT', { ...FIELDS, value: CHANGED })).status, 200);
  assert.equal((await request(`/api/projects/${project.id}`)).status, 200);
  assert.equal((await request(`/api/projects/${project.id}`, 'PUT', { name: CHANGED })).status, 200);
  assert.equal((await request('/api/secrets/delete', 'POST', [secret.id])).status, 200);
  const afterDelete = await count();
  assert.equal((await request('/api/secrets/delete', 'POST', [secret.id])).status, 404);
  assert.equal(await count(), afterDelete);
  assert.equal((await request(`/api/secrets/${orgId}/trash/restore`, 'POST', [secret.id])).status, 200);
  const rows = await events(`/api/organization/${orgId}/secrets/${secret.id}/events`);
  assert.deepEqual(rows.map((e) => e.type).sort(), [2100, 2100, 2101, 2102, 2103, 2105]);
  assert.ok(
    rows.every(
      (e) =>
        e.secretId === secret.id &&
        e.organizationId === orgId &&
        e.actingUserId === owner.id &&
        e.serviceAccountId === null,
    ),
  );
  assert.ok(rows.some((e) => e.type === 2100 && e.deviceType === 8));
  assert.deepEqual(
    (await events(`/api/organization/${orgId}/projects/${project.id}/events`)).map((e) => e.type).sort(),
    [2200, 2201, 2202],
  );
  const writable = await postJson<{ id: string }>(env, user, `/api/organizations/${orgId}/projects`, {
    name: ENCRYPTED_FIELD,
  });
  const allowed = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, {
    ...FIELDS,
    projectIds: [writable.id],
  });
  const partial = await request('/api/secrets/delete', 'POST', [secret.id, allowed.id], user.id);
  assert.equal(partial.status, 200);
  assert.deepEqual(
    ((await partial.json()) as any).data.map((r: any) => [r.id, r.error]).sort(),
    [
      [secret.id, 'access denied'],
      [allowed.id, null],
    ].sort(),
  );
  const orm = getOrm(env.DB);
  const deleted = await orm
    .select({ resourceId: eventLog.resourceId })
    .from(eventLog)
    .where(and(eq(eventLog.type, 2103), eq(eventLog.actingUserId, user.id)));
  assert.deepEqual(
    deleted.map((r) => r.resourceId),
    [allowed.id],
  );
  const serialized = JSON.stringify(await orm.select().from(eventLog).where(eq(eventLog.organizationId, orgId)));
  assert.ok(!serialized.includes(ENCRYPTED_FIELD) && !serialized.includes(CHANGED));
  await abortWrites(
    env,
    { table: smSecrets, event: 'UPDATE', column: smSecrets.deletedAt, rowId: secret.id },
    'audit rollback check',
  );
  const beforeFailure = await count();
  assert.equal((await request('/api/secrets/delete', 'POST', [secret.id])).status, 500);
  assert.equal(await count(), beforeFailure);
});

test('machine people policies record only added and removed users/groups', async () => {
  const { env, orgId, owner, user, account, request, events, count } = await setup();
  const ownerMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!;
  const userMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId))!;
  const group = crypto.randomUUID();
  const now = new Date().toISOString();
  await getOrm(env.DB).insert(orgGroups).values({ id: group, orgId, name: 'Team', createdAt: now, updatedAt: now });
  const path = `/api/service-accounts/${account.id}/access-policies/people`;
  const policies = {
    userAccessPolicyRequests: [policy(ownerMember.id), policy(userMember.id)],
    groupAccessPolicyRequests: [policy(group)],
  };
  assert.equal((await request(path, 'PUT', policies)).status, 200);
  const afterChange = await count();
  assert.equal((await request(path, 'PUT', policies)).status, 200);
  assert.equal((await request(path, 'PUT', { userAccessPolicyRequests: [policy(crypto.randomUUID())] })).status, 404);
  assert.equal(await count(), afterChange);
  assert.equal((await request(path, 'PUT', { userAccessPolicyRequests: [policy(ownerMember.id)] })).status, 200);
  const rows = await events(`/api/sm/events/service-accounts/${account.id}`);
  assert.deepEqual(rows.map((e) => e.type).sort(), [2300, 2300, 2301, 2302, 2303, 2304]);
  assert.ok(rows.some((e) => e.type === 2301 && e.userId === userMember.id && e.organizationUserId === userMember.id));
  assert.ok(rows.filter((e) => e.type === 2302 || e.type === 2303).every((e) => e.groupId === group));
  assert.ok(
    rows.every(
      (e) => e.grantedServiceAccountId === account.id && e.actingUserId === owner.id && e.serviceAccountId === null,
    ),
  );

  const batch = env.DB.batch.bind(env.DB);
  let replacing = false;
  const stopWatching = wrapStatements(env, (query, statement) => {
    if (/^DELETE\s+FROM\s+["`]?sm_service_account_members/i.test(query)) replacing = true;
    return statement;
  });
  env.DB.batch = async (statements) => {
    if (replacing) {
      replacing = false;
      await getOrm(env.DB)
        .insert(smServiceAccountMembers)
        .values({ serviceAccountId: account.id, membershipId: userMember.id });
    }
    return batch(statements);
  };
  const beforeRace = await count();
  try {
    assert.equal(
      (await request(path, 'PUT', { userAccessPolicyRequests: policies.userAccessPolicyRequests })).status,
      200,
    );
    assert.equal(await count(), beforeRace, 'a concurrently added, retained policy is not another addition');
  } finally {
    stopWatching();
    env.DB.batch = batch;
  }
});

test('machine retrieval audits only returned secrets and unchanged sync emits none', async () => {
  const { env, orgId, owner, project, secret, account, request, events, count } = await setup();
  const token = await postJson<{ id: string; clientSecret: string }>(
    env,
    owner,
    `/api/service-accounts/${account.id}/access-tokens`,
    TOKEN_FIELDS,
  );
  const login = await smLogin(env, token.id, token.clientSecret);
  assert.equal(login.status, 200);
  const jwt = ((await login.json()) as { access_token: string }).access_token;
  const machine = (path: string, method = 'GET', body?: unknown) =>
    authedFetch(env, { path, method, body, headers: { Authorization: `Bearer ${jwt}` } });
  assert.equal(
    (
      await request(`/api/service-accounts/${account.id}/granted-policies`, 'PUT', {
        projectGrantedPolicyRequests: [{ grantedId: project.id, read: true, write: true }],
      })
    ).status,
    200,
  );
  const visible = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, {
    ...FIELDS,
    projectIds: [project.id],
  });
  const beforeReads = await count();
  assert.equal((await machine(`/api/secrets/${secret.id}`)).status, 404);
  assert.equal((await machine('/api/secrets/get-by-ids', 'POST', { ids: [visible.id, secret.id] })).status, 404);
  assert.equal((await machine(`/api/organizations/${orgId}/secrets`)).status, 200);
  assert.equal(await count(), beforeReads);
  assert.equal((await machine(`/api/secrets/${visible.id}`)).status, 200);
  assert.equal((await machine(`/api/organizations/${orgId}/secrets/sync`)).status, 200);
  const afterReads = await count();
  await getOrm(env.DB)
    .update(smServiceAccounts)
    .set({ updatedAt: '2020-01-01T00:00:00.000Z' })
    .where(eq(smServiceAccounts.id, account.id));
  const unchanged = await machine(`/api/organizations/${orgId}/secrets/sync?lastSyncedDate=2021-01-01T00:00:00.000Z`);
  assert.equal(unchanged.status, 200);
  assert.equal(((await unchanged.json()) as any).hasChanges, false);
  for (const path of [
    `/api/sm/events/service-accounts/${account.id}`,
    `/api/organization/${orgId}/service-account/${account.id}/events`,
    `/api/organization/${orgId}/secrets/${visible.id}/events`,
  ])
    assert.equal((await machine(path)).status, 404);
  assert.equal(await count(), afterReads);
  const rows = (await events(`/api/sm/events/service-accounts/${account.id}`)).filter((e) => e.type === 2100);
  assert.equal(rows.length, 2);
  assert.ok(
    rows.every(
      (e) =>
        e.secretId === visible.id && e.serviceAccountId === account.id && e.actingUserId === null && e.userId === null,
    ),
  );
});
