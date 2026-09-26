import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';
import { MembershipType } from '../src/services/org-types';

test('SM event routes return empty lists only to target readers in the named organization', async () => {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const user = await seedMember(env, orgId, MembershipType.User);
  const project = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/projects`, { name: ENCRYPTED_FIELD });
  const secret = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/secrets`, { key: ENCRYPTED_FIELD, value: ENCRYPTED_FIELD, note: ENCRYPTED_FIELD });
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  for (const path of [`/api/organization/${orgId}/projects/${project.id}/events`, `/api/organization/${orgId}/secrets/${secret.id}/events`, `/api/organization/${orgId}/service-account/${account.id}/events`, `/api/sm/events/service-accounts/${account.id}`]) {
    const response = await authedFetch(env, { userId: owner.id, path });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { data: [], object: 'list', continuationToken: null });
    assert.equal((await authedFetch(env, { userId: user.id, path })).status, 404);
  }
  assert.equal((await authedFetch(env, { userId: owner.id, path: `/api/organization/${crypto.randomUUID()}/projects/${project.id}/events` })).status, 404);
});
