import assert from 'node:assert/strict';
import test from 'node:test';

import * as orgRepo from '../src/services/storage-org-repo';
import { MembershipType, PolicyType } from '../src/services/org-types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMembership } from './support/sm';

const MS_PER_SECOND = 1000;

// Official clients build every stored policy with `new Date(revisionDate)` and later call
// toISOString() on it (clients policy.ts toSdkPolicyView). A policy without RevisionDate becomes
// an Invalid Date and throws RangeError, breaking policiesByType$ for the whole account, and
// the org user notification banner compares revisionDate to decide whether to re-show.
interface PolicyBody {
  type: number;
  enabled: boolean;
  revisionDate?: string;
}

function assertIsoRevisionDate(policy: PolicyBody | undefined, expected: string): void {
  assert.ok(policy, 'policy missing from response');
  assert.equal(policy.revisionDate, expected);
  assert.equal(new Date(policy.revisionDate).toISOString(), expected);
}

test('saved policies carry the same ISO revisionDate in the PUT response, the org list and member sync', async (context) => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const member = await seedUser(env);
  const orgId = crypto.randomUUID();
  const now = new Date().toISOString();
  await orgRepo.insertOrganization(env.DB, {
    id: orgId,
    name: 'Policy Org',
    billingEmail: owner.email,
    identifier: null,
    privateKey: null,
    publicKey: null,
    createdAt: now,
    updatedAt: now,
  });
  await seedMembership(env, orgId, { userId: owner.id, type: MembershipType.Owner });
  await seedMembership(env, orgId, { userId: member.id });

  const saved = await authedFetch(env, {
    method: 'PUT',
    path: `/api/organizations/${orgId}/policies/${PolicyType.MasterPassword}`,
    body: { enabled: true, data: { minLength: 12 } },
    userId: owner.id,
  });
  assert.equal(saved.status, 200);
  const savedPolicy = await saved.json() as PolicyBody;
  assert.ok(savedPolicy.revisionDate, 'PUT response has no revisionDate');
  const { revisionDate } = savedPolicy;
  assertIsoRevisionDate(savedPolicy, revisionDate);

  const listed = await authedFetch(env, { path: `/api/organizations/${orgId}/policies`, userId: owner.id });
  assert.equal(listed.status, 200);
  const { data } = await listed.json() as { data: PolicyBody[] };
  assertIsoRevisionDate(data.find((policy) => policy.type === PolicyType.MasterPassword), revisionDate);

  const synced = await authedFetch(env, { path: '/api/sync', userId: member.id });
  assert.equal(synced.status, 200);
  const { policies, policiesNew } = await synced.json() as { policies: PolicyBody[]; policiesNew: PolicyBody[] };
  assertIsoRevisionDate(policies.find((policy) => policy.type === PolicyType.MasterPassword), revisionDate);
  assertIsoRevisionDate(policiesNew.find((policy) => policy.type === PolicyType.MasterPassword), revisionDate);

  // The banner re-shows and picks the newest policy by revisionDate, so an edit must move it
  // forward. Pin the clock past the first save so the comparison cannot tie within a millisecond.
  context.mock.timers.enable({ apis: ['Date'], now: Date.parse(revisionDate) + MS_PER_SECOND });
  const edited = await authedFetch(env, {
    method: 'PUT',
    path: `/api/organizations/${orgId}/policies/${PolicyType.MasterPassword}`,
    body: { enabled: false, data: { minLength: 12 } },
    userId: owner.id,
  });
  assert.equal(edited.status, 200);
  const editedPolicy = await edited.json() as PolicyBody;
  assert.ok(editedPolicy.revisionDate, 'edited PUT response has no revisionDate');
  assert.ok(Date.parse(editedPolicy.revisionDate) > Date.parse(revisionDate), 'edit did not advance revisionDate');

  const relisted = await authedFetch(env, { path: `/api/organizations/${orgId}/policies`, userId: owner.id });
  assert.equal(relisted.status, 200);
  const { data: relistedData } = await relisted.json() as { data: PolicyBody[] };
  assertIsoRevisionDate(relistedData.find((policy) => policy.type === PolicyType.MasterPassword), editedPolicy.revisionDate);
});
