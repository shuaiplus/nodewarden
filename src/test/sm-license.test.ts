import assert from 'node:assert/strict';
import test from 'node:test';

import { MembershipStatus, MembershipType } from '../services/org-types';
import type { Env, User } from '../types';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, ORG_CREATE_PATHS, seedMember, seedSmOrg, TEST_ORG_KEY } from './support/sm';

// Secrets Manager is on for every organization and never reads a license: no license upload may
// switch it off or cap its seats, projects or machine accounts. Every confirmed member gets it.
const SM_OFF_LICENSE = { useSecretsManager: false, smSeats: 0, smServiceAccounts: 0 };
// More projects and machine accounts than SM_OFF_LICENSE's zero seats and machine accounts allow.
const ITEMS_PAST_LICENSE = 3;

interface ProfileOrganization {
  id: string;
  useSecretsManager: boolean;
  accessSecretsManager: boolean;
}

interface MemberAccess {
  id: string;
  userId: string;
  accessSecretsManager: boolean;
}

// Confirmed members hold the org key; access policies determine which SM objects they can see.
const MEMBER_ACCESS_CASES = [
  { role: 'an accepted Admin', type: MembershipType.Admin, status: MembershipStatus.Accepted, access: false },
  { role: 'a confirmed Admin', type: MembershipType.Admin, status: MembershipStatus.Confirmed, access: true },
  { role: 'a confirmed User', type: MembershipType.User, status: MembershipStatus.Confirmed, access: true },
];

async function assertSecretsManagerOn(env: Env, orgId: string, members: User[]): Promise<void> {
  for (const member of members) {
    const synced = await authedFetch(env, { path: '/api/sync', userId: member.id });
    const { profile } = await synced.json() as { profile: { organizations: ProfileOrganization[] } };
    const { useSecretsManager, accessSecretsManager } = profile.organizations.find((org) => org.id === orgId) ?? {};
    assert.deepEqual({ useSecretsManager, accessSecretsManager }, { useSecretsManager: true, accessSecretsManager: true });
  }
  const organization = await authedFetch(env, { path: `/api/organizations/${orgId}`, userId: members[0].id });
  assert.equal((await organization.json() as { useSecretsManager: boolean }).useSecretsManager, true);
}

async function assertNoSecretsManagerLimits(env: Env, orgId: string, owner: User): Promise<void> {
  for (const collection of ['projects', 'service-accounts']) {
    for (let created = 0; created < ITEMS_PAST_LICENSE; created += 1) {
      const response = await authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/${collection}`, body: { name: ENCRYPTED_FIELD }, userId: owner.id });
      assert.equal(response.status, 200, `${collection} #${created + 1}`);
    }
  }
}

// Where official web reads a member's Secrets Manager access: the member's own sync profile, and
// the member list and edit-member dialog an owner opens.
async function secretsManagerAccess(env: Env, orgId: string, owner: User, member: User) {
  const synced = await authedFetch(env, { path: '/api/sync', userId: member.id });
  const { profile } = await synced.json() as { profile: { organizations: ProfileOrganization[] } };
  const listed = await authedFetch(env, { path: `/api/organizations/${orgId}/users`, userId: owner.id });
  const listEntry = (await listed.json() as { data: MemberAccess[] }).data.find((entry) => entry.userId === member.id);
  const detail = await authedFetch(env, { path: `/api/organizations/${orgId}/users/${listEntry?.id}`, userId: owner.id });
  return {
    profile: profile.organizations.find((org) => org.id === orgId)?.accessSecretsManager,
    list: listEntry?.accessSecretsManager,
    detail: (await detail.json() as MemberAccess).accessSecretsManager,
  };
}

// Official web's license dialogs post the file as the multipart `license` field; the self-hosted
// create uploader adds the org key and encrypted default collection name.
function smOffLicenseForm(fields: Record<string, string> = {}): FormData {
  const form = new FormData();
  form.append('license', new Blob([JSON.stringify(SM_OFF_LICENSE)]), 'bitwarden_organization_license.json');
  Object.entries(fields).forEach(([name, value]) => form.append(name, value));
  return form;
}

for (const createPath of ORG_CREATE_PATHS) {
  test(`owners and admins get Secrets Manager without a license on an org from POST ${createPath}`, async () => {
    const env = await createTestEnv();
    const { orgId, owner, admin } = await seedSmOrg(env, createPath);
    await assertSecretsManagerOn(env, orgId, [owner, admin]);
  });
}

test('creating an org from a license switching Secrets Manager off with zero seats changes nothing', async () => {
  const env = await createTestEnv();
  const createBody = smOffLicenseForm({ key: TEST_ORG_KEY, collectionName: ENCRYPTED_FIELD });
  const { orgId, owner, admin } = await seedSmOrg(env, ORG_CREATE_PATHS[1], createBody);
  await assertSecretsManagerOn(env, orgId, [owner, admin]);
  await assertNoSecretsManagerLimits(env, orgId, owner);
});

test('uploading a license switching Secrets Manager off with zero seats changes nothing', async () => {
  const env = await createTestEnv();
  const { orgId, owner, admin } = await seedSmOrg(env);
  const uploaded = await authedFetch(env, { method: 'POST', path: `/api/organizations/licenses/self-hosted/${orgId}`, body: smOffLicenseForm(), userId: owner.id });
  assert.equal(uploaded.status, 200);
  await assertSecretsManagerOn(env, orgId, [owner, admin]);
  await assertNoSecretsManagerLimits(env, orgId, owner);
});

for (const { role, type, status, access } of MEMBER_ACCESS_CASES) {
  test(`${role} gets accessSecretsManager ${access} in the profile, member list and member detail`, async () => {
    const env = await createTestEnv();
    const { orgId, owner } = await seedSmOrg(env);
    const { user: member } = await seedMember(env, orgId, { type, status });
    assert.deepEqual(await secretsManagerAccess(env, orgId, owner, member), { profile: access, list: access, detail: access });
  });
}
