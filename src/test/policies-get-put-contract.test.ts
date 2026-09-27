import assert from 'node:assert/strict';
import test from 'node:test';

import { MembershipType, PolicyType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMember } from './support/sm';

const { createOwnedOrganization } = await import('../handlers/organizations');

// Official web's policy drawer loads one policy with GET /policies/{type} (policy-api.service.ts
// getPolicy wraps the body in a single PolicyResponse) and saves the SavePolicyRequest envelope
// {policy:{enabled,data},metadata} (base-policy-edit.component.ts buildRequest). Upstream
// PoliciesController.Get synthesizes a disabled status when no row exists.
const MEMBER_KEY = '4.dGVzdA==';
const MASTER_PASSWORD_DATA = { minComplexity: 3, minLength: 14, requireUpper: true };

interface PolicyBody {
  organizationId: string;
  type: number;
  enabled: boolean;
  data: Record<string, unknown> | null;
  object: string;
}

function policyPath(orgId: string, type: number): string {
  return `/api/organizations/${orgId}/policies/${type}`;
}

test('the SavePolicyRequest envelope round-trips enabled and data through GET /policies/{type} and sync', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const { id: orgId } = await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY });
  const { user: member } = await seedMember(env, orgId);

  const absent = await authedFetch(env, { path: policyPath(orgId, PolicyType.MasterPassword), userId: owner.id });
  assert.equal(absent.status, 200);
  assert.deepEqual(await absent.json(), {
    organizationId: orgId,
    type: PolicyType.MasterPassword,
    enabled: false,
    data: {},
    object: 'policy',
  });

  const saved = await authedFetch(env, {
    method: 'PUT',
    path: policyPath(orgId, PolicyType.MasterPassword),
    body: { policy: { enabled: true, data: MASTER_PASSWORD_DATA }, metadata: null },
    userId: owner.id,
  });
  assert.equal(saved.status, 200);
  const savedPolicy = (await saved.json()) as PolicyBody;
  assert.equal(savedPolicy.enabled, true);
  assert.deepEqual(savedPolicy.data, MASTER_PASSWORD_DATA);

  const loaded = await authedFetch(env, { path: policyPath(orgId, PolicyType.MasterPassword), userId: owner.id });
  assert.equal(loaded.status, 200);
  const loadedPolicy = (await loaded.json()) as PolicyBody;
  assert.equal(loadedPolicy.object, 'policy');
  assert.equal(loadedPolicy.type, PolicyType.MasterPassword);
  assert.equal(loadedPolicy.enabled, true);
  assert.deepEqual(loadedPolicy.data, MASTER_PASSWORD_DATA);

  const synced = await authedFetch(env, { path: '/api/sync', userId: member.id });
  assert.equal(synced.status, 200);
  const { policies } = (await synced.json()) as { policies: PolicyBody[] };
  const syncedPolicy = policies.find((policy) => policy.type === PolicyType.MasterPassword);
  assert.equal(syncedPolicy?.enabled, true);
  assert.deepEqual(syncedPolicy?.data, MASTER_PASSWORD_DATA);
});

test('a Custom policy manager reads a single policy while other members cannot read or save it', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const { id: orgId } = await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY });
  const { user: member } = await seedMember(env, orgId);
  const { user: policyManager } = await seedMember(env, orgId, {
    type: MembershipType.Custom,
    permissions: { managePolicies: true },
  });
  const outsider = await seedUser(env);

  const managerRead = await authedFetch(env, {
    path: policyPath(orgId, PolicyType.TwoFactorAuthentication),
    userId: policyManager.id,
  });
  assert.equal(managerRead.status, 200);
  assert.equal(((await managerRead.json()) as PolicyBody).object, 'policy');
  const memberRead = await authedFetch(env, {
    path: policyPath(orgId, PolicyType.TwoFactorAuthentication),
    userId: member.id,
  });
  assert.equal(memberRead.status, 403);
  const memberSave = await authedFetch(env, {
    method: 'PUT',
    path: policyPath(orgId, PolicyType.TwoFactorAuthentication),
    body: { policy: { enabled: true, data: null }, metadata: null },
    userId: member.id,
  });
  assert.equal(memberSave.status, 403);
  const outsiderRead = await authedFetch(env, {
    path: policyPath(orgId, PolicyType.TwoFactorAuthentication),
    userId: outsider.id,
  });
  assert.equal(outsiderRead.status, 404);
  assert.equal(await orgRepo.getPolicy(env.DB, orgId, PolicyType.TwoFactorAuthentication), null);
});

test('a malformed SavePolicyRequest envelope is rejected and leaves the saved policy enabled', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const { id: orgId } = await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY });
  const path = policyPath(orgId, PolicyType.MasterPassword);
  const enabled = await authedFetch(env, {
    method: 'PUT',
    path,
    body: { policy: { enabled: true, data: MASTER_PASSWORD_DATA }, metadata: null },
    userId: owner.id,
  });
  assert.equal(enabled.status, 200);

  for (const policy of [null, 'enabled', true, [{ enabled: false }]]) {
    const rejected = await authedFetch(env, {
      method: 'PUT',
      path,
      body: { policy, metadata: null },
      userId: owner.id,
    });
    assert.equal(rejected.status, 400, `policy: ${JSON.stringify(policy)}`);
    assert.equal(((await rejected.json()) as { error: string }).error, 'The Policy field is required.');
  }
  const stored = await orgRepo.getPolicy(env.DB, orgId, PolicyType.MasterPassword);
  assert.equal(stored?.enabled, true);
  assert.deepEqual(stored?.data, MASTER_PASSWORD_DATA);
});
