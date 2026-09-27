import assert from 'node:assert/strict';
import test from 'node:test';

import { getOrm } from '../db/client';
import { orgGroupMembers, orgGroups } from '../db/schema';
import { MembershipStatus } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

const policy = (granteeId: string, write = false) => ({ granteeId, read: true, write });

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const { user: a } = await seedMember(env, orgId);
  const ownerMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!;
  const aMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  const project = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, {
    name: ENCRYPTED_FIELD,
  });
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, {
    name: ENCRYPTED_FIELD,
  });
  const groupId = crypto.randomUUID();
  const now = new Date().toISOString();
  const orm = getOrm(env.DB);
  await orm.batch([
    orm.insert(orgGroups).values({ id: groupId, orgId, name: 'Team', createdAt: now, updatedAt: now }),
    orm.insert(orgGroupMembers).values({ groupId, membershipId: ownerMember.id }),
  ]);
  const request = (userId: string, path: string, method = 'GET', body?: unknown) =>
    authedFetch(env, { userId, path, method, body });
  return { env, orgId, owner, a, ownerMember, aMember, project, account, groupId, request };
}

test('project people replacement updates permissions, clears omitted kinds, and reports current-user flags', async () => {
  const { orgId, owner, a, ownerMember, aMember, project, groupId, request } = await setup();
  const path = `/api/projects/${project.id}/access-policies/people`;
  const put = await request(owner.id, path, 'PUT', {
    userAccessPolicyRequests: [policy(ownerMember.id, true), policy(aMember.id)],
    groupAccessPolicyRequests: [policy(groupId, true)],
  });
  assert.equal(put.status, 200);
  const body = (await put.json()) as any;
  assert.equal(body.object, 'projectPeopleAccessPolicies');
  assert.deepEqual(
    new Map(
      body.userAccessPolicies.map((item: any) => [
        item.organizationUserId,
        [item.currentUser, item.read, item.write, item.object],
      ]),
    ),
    new Map([
      [ownerMember.id, [true, true, true, 'userAccessPolicy']],
      [aMember.id, [false, true, false, 'userAccessPolicy']],
    ]),
  );
  assert.deepEqual(body.groupAccessPolicies, [
    { groupId, groupName: 'Team', currentUserInGroup: true, read: true, write: true, object: 'groupAccessPolicy' },
  ]);
  const listed = await request(a.id, `/api/organizations/${orgId}/projects`);
  assert.equal(listed.status, 200);
  assert.deepEqual(
    ((await listed.json()) as any).data.map((item: any) => [item.id, item.write]),
    [[project.id, false]],
  );
  assert.equal((await request(a.id, path)).status, 404);
  assert.equal((await request(a.id, path, 'PUT', {})).status, 404);

  const changed = await request(owner.id, path, 'PUT', { userAccessPolicyRequests: [policy(aMember.id, true)] });
  assert.equal(changed.status, 200);
  const changedBody = (await changed.json()) as any;
  assert.deepEqual(changedBody.groupAccessPolicies, []);
  assert.deepEqual(
    changedBody.userAccessPolicies.map((item: any) => [item.organizationUserId, item.write]),
    [[aMember.id, true]],
  );
  assert.equal((await request(a.id, path)).status, 200);
  const cleared = await request(owner.id, path, 'PUT', { groupAccessPolicyRequests: [] });
  assert.equal(cleared.status, 200);
  assert.deepEqual(await cleared.json(), {
    userAccessPolicies: [],
    groupAccessPolicies: [],
    object: 'projectPeopleAccessPolicies',
  });
  assert.equal((await request(a.id, `/api/projects/${project.id}`)).status, 404);
});

test('people policies reject duplicates, invalid permissions, and foreign memberships or groups without replacing existing grants', async () => {
  const { env, owner, aMember, project, account, groupId, request } = await setup();
  const projectPath = `/api/projects/${project.id}/access-policies/people`;
  const accountPath = `/api/service-accounts/${account.id}/access-policies/people`;
  const original = await (await request(owner.id, projectPath)).json();
  const rejected = [
    [projectPath, { userAccessPolicyRequests: [policy(aMember.id), policy(aMember.id)] }, 'Resources must be unique'],
    [
      projectPath,
      { userAccessPolicyRequests: [{ granteeId: aMember.id, read: false, write: true }] },
      'Resources must be Read = true',
    ],
    [accountPath, { userAccessPolicyRequests: [policy(aMember.id)] }, 'Machine account access must be Can read, write'],
    [
      accountPath,
      { groupAccessPolicyRequests: [{ granteeId: groupId, read: false, write: true }] },
      'Machine account access must be Can read, write',
    ],
  ] as const;
  for (const [path, body, message] of rejected) {
    const result = await request(owner.id, path, 'PUT', body);
    assert.equal(result.status, 400);
    assert.equal(((await result.json()) as any).message, message);
  }
  const foreign = await seedSmOrg(env);
  const foreignMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, foreign.owner.id, foreign.orgId))!;
  const foreignGroup = crypto.randomUUID();
  const now = new Date().toISOString();
  await getOrm(env.DB)
    .insert(orgGroups)
    .values({ id: foreignGroup, orgId: foreign.orgId, name: 'Elsewhere', createdAt: now, updatedAt: now });
  for (const path of [projectPath, accountPath]) {
    for (const body of [
      { userAccessPolicyRequests: [policy(foreignMember.id, true)] },
      { groupAccessPolicyRequests: [policy(foreignGroup, true)] },
    ]) {
      assert.equal((await request(owner.id, path, 'PUT', body)).status, 404);
    }
  }
  assert.deepEqual(await (await request(owner.id, projectPath)).json(), original);
});

test('machine-account people policies are RW and potential grantees list only confirmed users plus every group', async () => {
  const { env, orgId, owner, a, ownerMember, aMember, account, project, groupId, request } = await setup();
  const { user: invited } = await seedMember(env, orgId, { status: MembershipStatus.Invited });
  const { user: accepted } = await seedMember(env, orgId, { status: MembershipStatus.Accepted });
  const invitedMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, invited.id, orgId))!;
  const acceptedMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, accepted.id, orgId))!;
  const grantees = await request(owner.id, `/api/organizations/${orgId}/access-policies/people/potential-grantees`);
  assert.equal(grantees.status, 200);
  const list = (await grantees.json()) as any;
  assert.equal(list.object, 'list');
  assert.equal(list.continuationToken, null);
  const users = list.data.filter((item: any) => item.type === 'user');
  assert.ok(users.some((item: any) => item.id === aMember.id && item.email === a.email && !item.currentUser));
  assert.ok(users.some((item: any) => item.id === ownerMember.id && item.currentUser));
  assert.ok(
    users.every(
      (item: any) => ![invitedMember.id, acceptedMember.id].includes(item.id) && item.object === 'potentialGrantee',
    ),
  );
  assert.ok(list.data.some((item: any) => item.id === groupId && item.type === 'group' && item.currentUserInGroup));
  assert.equal(
    (await request(invited.id, `/api/organizations/${orgId}/access-policies/people/potential-grantees`)).status,
    404,
  );
  assert.equal(
    (await request(accepted.id, `/api/organizations/${orgId}/access-policies/people/potential-grantees`)).status,
    404,
  );
  // Existing same-org memberships may receive grants before confirmation, although the picker hides them.
  assert.equal(
    (
      await request(owner.id, `/api/projects/${project.id}/access-policies/people`, 'PUT', {
        userAccessPolicyRequests: [policy(acceptedMember.id)],
      })
    ).status,
    200,
  );

  const path = `/api/service-accounts/${account.id}/access-policies/people`;
  assert.equal((await request(a.id, path)).status, 404);
  const assigned = await request(owner.id, path, 'PUT', {
    userAccessPolicyRequests: [policy(aMember.id, true)],
    groupAccessPolicyRequests: [policy(groupId, true)],
  });
  assert.equal(assigned.status, 200);
  const body = (await assigned.json()) as any;
  assert.equal(body.object, 'serviceAccountAccessPolicies');
  assert.ok([...body.userAccessPolicies, ...body.groupAccessPolicies].every((item: any) => item.read && item.write));
  const ownView = await request(a.id, path);
  assert.equal(ownView.status, 200);
  const ownBody = (await ownView.json()) as any;
  assert.equal(ownBody.userAccessPolicies[0].currentUser, true);
  assert.equal(ownBody.groupAccessPolicies[0].currentUserInGroup, false);
  assert.equal((await request(a.id, `/api/service-accounts/${account.id}`)).status, 200);
  const removed = await request(owner.id, path, 'PUT', {});
  assert.equal(removed.status, 200);
  assert.deepEqual(await removed.json(), {
    userAccessPolicies: [],
    groupAccessPolicies: [],
    object: 'serviceAccountAccessPolicies',
  });
  assert.equal((await request(a.id, `/api/service-accounts/${account.id}`)).status, 404);
});
