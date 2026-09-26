import assert from 'node:assert/strict';
import test from 'node:test';

import { MembershipStatus, MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg, smLogin, TOKEN_FIELDS } from './support/sm';

function disabledLicense() {
  const form = new FormData();
  form.set('license', new Blob([JSON.stringify({ useSecretsManager: false, smSeats: 0, smServiceAccounts: 0 })]), 'license.json');
  return form;
}

test('confirmed User and Custom members have SM in every response while unconfirmed members remain excluded regardless of license', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const cases = [
    [await seedMember(env, orgId, MembershipType.User), true],
    [await seedMember(env, orgId, MembershipType.Custom), true],
    [await seedMember(env, orgId, MembershipType.User, MembershipStatus.Invited), false],
    [await seedMember(env, orgId, MembershipType.Admin, MembershipStatus.Accepted), false],
  ] as const;
  for (const upload of [false, true]) {
    if (upload) assert.equal((await authedFetch(env, { userId: owner.id, path: `/api/organizations/licenses/self-hosted/${orgId}`, method: 'POST', body: disabledLicense() })).status, 200);
    const listed = await authedFetch(env, { userId: owner.id, path: `/api/organizations/${orgId}/users` });
    assert.equal(listed.status, 200);
    const members = (await listed.json() as any).data;
    for (const [user, access] of cases) {
      const synced = await authedFetch(env, { userId: user.id, path: '/api/sync' });
      assert.equal(synced.status, 200);
      const organization = (await synced.json() as any).profile.organizations.find((org: any) => org.id === orgId);
      assert.equal(organization.useSecretsManager, true);
      assert.equal(organization.accessSecretsManager, access);
      const member = members.find((row: any) => row.userId === user.id);
      assert.equal(member.accessSecretsManager, access);
      const detail = await authedFetch(env, { userId: owner.id, path: `/api/organizations/${orgId}/users/${member.id}` });
      assert.equal(detail.status, 200);
      assert.equal((await detail.json() as any).accessSecretsManager, access);
      assert.equal((await authedFetch(env, { userId: user.id, path: `/api/organizations/${orgId}/projects` })).status, access ? 200 : 404);
    }
  }
});

test('enable SM is an authorized no-op, standalone metadata is on, and machine login survives license changes', async () => {
  const env = await createTestEnv();
  const { orgId, owner, admin } = await seedSmOrg(env);
  const a = await seedMember(env, orgId, MembershipType.User);
  const invited = await seedMember(env, orgId, MembershipType.User, MembershipStatus.Invited);
  const before = await orgRepo.getMembershipByUserAndOrg(env.DB, invited.id, orgId);
  const member = (await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId))!;
  const path = `/api/organizations/${orgId}/users/enable-secrets-manager`;
  for (const actor of [owner, admin]) {
    const response = await authedFetch(env, { userId: actor.id, path, method: 'PUT', body: { ids: [member.id, before!.id] } });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '');
  }
  assert.equal((await authedFetch(env, { userId: a.id, path, method: 'PUT', body: { ids: [member.id] } })).status, 403);
  assert.deepEqual(await orgRepo.getMembershipByUserAndOrg(env.DB, invited.id, orgId), before);
  assert.deepEqual(await orgRepo.getMembershipByUserAndOrg(env.DB, a.id, orgId), member);
  const metadata = await authedFetch(env, { userId: owner.id, path: `/api/organizations/${orgId}/billing/vnext/self-host/metadata` });
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json() as any).isOnSecretsManagerStandalone, true);
  const account = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const token = await postJson<{ id: string; clientSecret: string }>(env, a, `/api/service-accounts/${account.id}/access-tokens`, TOKEN_FIELDS);
  assert.equal((await smLogin(env, token.id, token.clientSecret)).status, 200);
  assert.equal((await authedFetch(env, { userId: owner.id, path: `/api/organizations/licenses/self-hosted/${orgId}`, method: 'POST', body: disabledLicense() })).status, 200);
  assert.equal((await smLogin(env, token.id, token.clientSecret)).status, 200);
});

test('a newly enabled member starts empty, sees their created project, and cannot see admin resources or trash', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const a = await seedMember(env, orgId, MembershipType.User);
  const hidden = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const hiddenSecret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD, projectIds: [hidden.id] });
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  for (const sub of ['projects', 'secrets', 'service-accounts']) {
    const response = await authedFetch(env, { userId: a.id, path: `/api/organizations/${orgId}/${sub}` });
    assert.equal(response.status, 200);
    const body = await response.json() as any;
    assert.deepEqual(sub === 'secrets' ? body.secrets : body.data, []);
  }
  const counts = await authedFetch(env, { userId: a.id, path: `/api/organizations/${orgId}/sm-counts` });
  assert.equal(counts.status, 200);
  assert.deepEqual(await counts.json(), { projects: 0, secrets: 0, serviceAccounts: 0, object: 'organizationCounts' });
  const revision = '2020-01-01T00:00:00.000Z';
  await env.DB.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE id = ?').bind(revision, account.id).run();
  for (const [kind, id] of [['projects', hidden.id], ['secrets', hiddenSecret.id]]) {
    const denied = await authedFetch(env, { userId: a.id, path: `/api/${kind}/delete`, method: 'POST', body: [id] });
    assert.equal(denied.status, 200);
    assert.deepEqual((await denied.json() as any).data, [{ id, error: 'access denied', object: 'BulkDeleteResponseModel' }]);
    assert.equal(await env.DB.prepare('SELECT updated_at FROM sm_service_accounts WHERE id = ?').bind(account.id).first('updated_at'), revision);
  }
  const created = await postJson<{ id: string }>(env, a, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  assert.equal((await authedFetch(env, { userId: a.id, path: `/api/projects/${created.id}`.toUpperCase() })).status, 200);
  const listed = await authedFetch(env, { userId: a.id, path: `/api/organizations/${orgId}/projects` });
  assert.deepEqual((await listed.json() as any).data.map((project: any) => [project.id, project.write]), [[created.id, true]]);
  assert.equal((await authedFetch(env, { userId: a.id, path: `/api/projects/${hidden.id}` })).status, 404);
  assert.equal((await authedFetch(env, { userId: a.id, path: `/api/secrets/${orgId}/trash` })).status, 404);
});
