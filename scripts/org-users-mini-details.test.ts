import assert from 'node:assert/strict';
import test from 'node:test';

import { MembershipStatus, MembershipType, revokeStatus } from '../src/services/org-types';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { seedMember } from './support/sm';

const { createOwnedOrganization } = await import('../src/handlers/organizations');

// Official web's collection dialog and group add/edit dialog wait on
// GET /organizations/{orgId}/users/mini-details (upstream OrganizationUsersController.GetMiniDetails)
// with no error handler, so a 404 leaves them spinning. Upstream opens it to every member and
// returns only OrganizationUserUserMiniDetailsResponseModel: no keys, permissions or 2FA state.
const MEMBER_KEY = '4.dGVzdA==';
const MINI_DETAILS_KEYS = ['email', 'id', 'name', 'object', 'status', 'type', 'userId'];

interface MiniDetails {
  id: string;
  userId: string | null;
  type: number;
  status: number;
  name: string | null;
  email: string;
  object: string;
}

function miniDetails(env: Env, actor: User, orgId: string): Promise<Response> {
  return authedFetch(env, { path: `/api/organizations/${orgId}/users/mini-details`, userId: actor.id });
}

// requireMember's 404 message, which the router's catch-all 404 ('Not found') does not share.
async function assertOrganizationNotFound(response: Response): Promise<void> {
  assert.equal(response.status, 404);
  assert.equal((await response.json() as { error: string }).error, 'Organization not found');
}

test('mini-details lists every member, invited and revoked ones included, with exactly the upstream keys', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY })).id;
  const invitedEmail = 'invitee@example.test';
  const invited = await authedFetch(env, {
    method: 'POST',
    path: `/api/organizations/${orgId}/users/invite`,
    body: { emails: [invitedEmail], type: MembershipType.User },
    userId: owner.id,
  });
  assert.equal(invited.status, 200);
  const { user: revoked } = await seedMember(env, orgId, { status: revokeStatus(MembershipStatus.Confirmed) });

  const response = await miniDetails(env, owner, orgId);
  assert.equal(response.status, 200);
  const body = await response.json() as { object: string; data: MiniDetails[]; continuationToken: null };
  assert.equal(body.object, 'list');
  assert.equal(body.continuationToken, null);
  assert.equal(body.data.length, 3);
  body.data.forEach((entry) => {
    assert.deepEqual(Object.keys(entry).sort(), MINI_DETAILS_KEYS);
    assert.equal(entry.object, 'organizationUserUserMiniDetails');
  });

  const ownerEntry = body.data.find((entry) => entry.userId === owner.id)!;
  assert.deepEqual(
    { type: ownerEntry.type, status: ownerEntry.status, name: ownerEntry.name, email: ownerEntry.email },
    { type: MembershipType.Owner, status: MembershipStatus.Confirmed, name: owner.name, email: owner.email },
  );
  const invitedEntry = body.data.find((entry) => entry.email === invitedEmail)!;
  assert.deepEqual(
    { userId: invitedEntry.userId, status: invitedEntry.status, name: invitedEntry.name },
    { userId: null, status: MembershipStatus.Invited, name: null },
  );
  const revokedEntry = body.data.find((entry) => entry.userId === revoked.id)!;
  assert.deepEqual(
    { status: revokedEntry.status, name: revokedEntry.name, email: revokedEntry.email },
    { status: MembershipStatus.Revoked, name: revoked.name, email: revoked.email },
  );
});

test('mini-details is served to any confirmed member but not to outsiders or unconfirmed members', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: MEMBER_KEY })).id;
  const { user: plainMember } = await seedMember(env, orgId);
  const { user: accepted } = await seedMember(env, orgId, { status: MembershipStatus.Accepted });
  const outsider = await seedUser(env);

  assert.equal((await miniDetails(env, plainMember, orgId)).status, 200);
  await assertOrganizationNotFound(await miniDetails(env, accepted, orgId));
  await assertOrganizationNotFound(await miniDetails(env, outsider, orgId));
});
