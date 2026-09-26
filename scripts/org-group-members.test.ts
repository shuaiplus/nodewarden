import assert from 'node:assert/strict';
import test from 'node:test';

import { ensureStorageSchema } from '../src/db/migrate';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const { createOwnedOrganization } = await import('../src/handlers/organizations');
import { TEST_ORG_KEY } from './support/sm';

// Upstream UpdateGroupCommand.ValidateMemberAccessAsync: missing and foreign member ids fail alike,
// so the response cannot probe other organizations.
const RESOURCE_NOT_FOUND = 'Resource not found.';

// An org `owner` creates, with the owner's own membership id in it.
async function ownedOrg(env: Env, owner: User): Promise<{ orgId: string; membershipId: string }> {
  const { id: orgId } = await createOwnedOrganization(env, owner, { name: 'Acme', key: TEST_ORG_KEY });
  const membership = await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId);
  assert.ok(membership);
  return { orgId, membershipId: membership.id };
}

function saveGroup(env: Env, owner: User, orgId: string, users: string[], groupId?: string): Promise<Response> {
  return authedFetch(env, {
    method: groupId ? 'PUT' : 'POST',
    path: `/api/organizations/${orgId}/groups${groupId ? `/${groupId}` : ''}`,
    body: { name: 'Group', accessAll: false, collections: [], users },
    userId: owner.id,
  });
}

test('an owner of X adding their org-Y membership or a missing id to a group in X gets 404 and changes nothing', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgX = await ownedOrg(env, owner);
  const orgY = await ownedOrg(env, owner);

  const created = await saveGroup(env, owner, orgX.orgId, [orgY.membershipId]);
  assert.equal(created.status, 404);
  assert.equal((await created.json() as { message: string }).message, RESOURCE_NOT_FOUND);
  assert.deepEqual(await orgRepo.listGroupsByOrg(env.DB, orgX.orgId), []);
  const missing = await saveGroup(env, owner, orgX.orgId, [crypto.randomUUID()]);
  assert.equal(missing.status, 404);
  assert.equal((await missing.json() as { message: string }).message, RESOURCE_NOT_FOUND);
  assert.deepEqual(await orgRepo.listGroupsByOrg(env.DB, orgX.orgId), []);

  const saved = await saveGroup(env, owner, orgX.orgId, [orgX.membershipId]);
  assert.equal(saved.status, 200);
  const { id: groupId } = await saved.json() as { id: string };
  const updated = await saveGroup(env, owner, orgX.orgId, [orgX.membershipId, orgY.membershipId], groupId);
  assert.equal(updated.status, 404);
  assert.deepEqual(await orgRepo.listGroupMemberIds(env.DB, groupId), [orgX.membershipId]);
});

// Before the handler check, any membership id was stored, so the schema step deletes those rows.
test('the schema step removes cross-org group members, keeps same-org ones, and replays cleanly', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgX = await ownedOrg(env, owner);
  const orgY = await ownedOrg(env, owner);
  const saved = await saveGroup(env, owner, orgX.orgId, [orgX.membershipId]);
  const { id: groupId } = await saved.json() as { id: string };
  await orgRepo.replaceGroupMembers(env.DB, groupId, [orgX.membershipId, orgY.membershipId]);

  await ensureStorageSchema(env.DB);
  assert.deepEqual(await orgRepo.listGroupMemberIds(env.DB, groupId), [orgX.membershipId]);
  await ensureStorageSchema(env.DB);
  assert.deepEqual(await orgRepo.listGroupMemberIds(env.DB, groupId), [orgX.membershipId]);
});
