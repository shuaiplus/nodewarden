import assert from 'node:assert/strict';
import test from 'node:test';

import { MembershipStatus, revokeStatus } from '../services/org-types';
import * as emergencyRepo from '../services/storage-emergency-repo';
import { EmergencyAccessStatus, EmergencyAccessType } from '../services/storage-emergency-repo';
import type { Env, User } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { byId, seedMember } from './support/sm';

const { createOwnedOrganization } = await import('../handlers/organizations');

// Official web fetches the other account's RSA public key before every confirm: emergency access
// and single member confirm call GET /users/{id}/public-key (ApiService.getUserPublicKey), and the
// bulk confirm dialog calls POST /organizations/{orgId}/users/public-keys. Upstream
// UsersController and OrganizationUsersController.UserPublicKeys at server v2026.9.1.
const PUBLIC_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAdGVzdA==';
const WRAPPED_KEY = '4.dGVzdA==';
const ONE_ID_REQUIRED = "The field Ids must be a string or array type with a minimum length of '1'.";
const IDS_REQUIRED = 'The Ids field is required.';
const NOT_FOUND = 'Resource not found.';
// More ids than one D1 statement can bind, so the lookup must not bind them.
const MANY_IDS = 150;

interface UserKey {
  userId: string;
  publicKey: string;
  object: string;
}

interface MemberPublicKey {
  id: string;
  userId: string;
  key: string | null;
  object: string;
}

// Members hold RSA keys unless seeded without any, like an account that never logged in.
function addMember(env: Env, orgId: string, status: number, publicKey: string | null = PUBLIC_KEY) {
  return seedMember(env, orgId, { status, user: { publicKey } });
}

async function errorOf(response: Response): Promise<{ status: number; error: string }> {
  return { status: response.status, error: ((await response.json()) as { error: string }).error };
}

function publicKeys(env: Env, actor: User, orgId: string, body: unknown): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: `/api/organizations/${orgId}/users/public-keys`, body, userId: actor.id });
}

test('an emergency access grantor reads the grantee public key and confirms with it', async () => {
  const env = await createTestEnv();
  const grantor = await seedUser(env);
  const grantee = await seedUser(env, { publicKey: PUBLIC_KEY });
  const now = new Date().toISOString();
  const recordId = crypto.randomUUID();
  await emergencyRepo.saveEmergencyAccess(env.DB, {
    id: recordId,
    grantorId: grantor.id,
    granteeId: grantee.id,
    email: grantee.email,
    keyEncrypted: null,
    type: EmergencyAccessType.View,
    status: EmergencyAccessStatus.Accepted,
    waitTimeDays: 0,
    recoveryInitiatedAt: null,
    lastNotificationAt: null,
    createdAt: now,
    updatedAt: now,
  });

  const response = await authedFetch(env, { path: `/api/users/${grantee.id}/public-key`, userId: grantor.id });
  assert.equal(response.status, 200);
  const body = await response.json() as UserKey;
  assert.deepEqual(body, { userId: grantee.id, publicKey: PUBLIC_KEY, object: 'userKey' });

  const confirmed = await authedFetch(env, {
    method: 'POST',
    path: `/api/emergency-access/${recordId}/confirm`,
    body: { key: WRAPPED_KEY },
    userId: grantor.id,
  });
  assert.equal(confirmed.status, 200);
});

test('a user public key is 404 for an unknown user or one without keys, and needs a login', async () => {
  const env = await createTestEnv();
  const caller = await seedUser(env);
  const keyless = await seedUser(env);

  // The router's own fall-through is also a 404, so the upstream message proves the route ran.
  const notFound = { status: 404, error: NOT_FOUND };
  assert.deepEqual(await errorOf(await authedFetch(env, { path: `/api/users/${crypto.randomUUID()}/public-key`, userId: caller.id })), notFound);
  assert.deepEqual(await errorOf(await authedFetch(env, { path: `/api/users/${keyless.id}/public-key`, userId: caller.id })), notFound);
  assert.equal((await authedFetch(env, { path: `/api/users/${keyless.id}/public-key` })).status, 401);
});

test('bulk member public keys list only Accepted members of this organization, then confirm works', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: WRAPPED_KEY })).id;
  const otherOrgId = (await createOwnedOrganization(env, owner, { name: 'Other', key: WRAPPED_KEY })).id;
  const accepted = await addMember(env, orgId, MembershipStatus.Accepted);
  const confirmed = await addMember(env, orgId, MembershipStatus.Confirmed);
  const keyless = await addMember(env, orgId, MembershipStatus.Accepted, null);
  const invited = await addMember(env, orgId, MembershipStatus.Invited);
  const revoked = await addMember(env, orgId, revokeStatus(MembershipStatus.Accepted));
  const foreign = await addMember(env, otherOrgId, MembershipStatus.Accepted);

  const unknownIds = Array.from({ length: MANY_IDS }, () => crypto.randomUUID());
  const ids = [...unknownIds, ...[accepted, confirmed, keyless, invited, revoked, foreign].map(({ memberId }) => memberId)];
  const response = await publicKeys(env, owner, orgId, { ids });
  assert.equal(response.status, 200);
  const body = await response.json() as { data: MemberPublicKey[]; object: string };
  assert.equal(body.object, 'list');
  // An Accepted member without keys is still listed, with a null key, as upstream.
  const expected = [[accepted, PUBLIC_KEY], [keyless, null]] as const;
  assert.deepEqual(body.data.toSorted(byId), expected.map(([member, key]) => ({
    id: member.memberId,
    userId: member.user.id,
    key,
    object: 'organizationUserPublicKeyResponseModel',
  })).toSorted(byId));

  const confirm = await authedFetch(env, {
    method: 'POST',
    path: `/api/organizations/${orgId}/users/${accepted.memberId}/confirm`,
    body: { key: WRAPPED_KEY },
    userId: owner.id,
  });
  assert.equal(confirm.status, 200);
});

test('bulk member public keys need manageUsers, an organization membership and at least one id', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: WRAPPED_KEY })).id;
  const accepted = await addMember(env, orgId, MembershipStatus.Accepted);
  const plainMember = await addMember(env, orgId, MembershipStatus.Confirmed);
  const outsider = await seedUser(env);
  const body = { ids: [accepted.memberId] };

  assert.equal((await publicKeys(env, plainMember.user, orgId, body)).status, 403);
  assert.equal((await publicKeys(env, outsider, orgId, body)).status, 404);
  // Ids defaults to an empty list upstream: absent fails MinLength, an explicit null fails Required.
  const tooFew = { status: 400, error: ONE_ID_REQUIRED };
  assert.deepEqual(await errorOf(await publicKeys(env, owner, orgId, { ids: [] })), tooFew);
  assert.deepEqual(await errorOf(await publicKeys(env, owner, orgId, {})), tooFew);
  assert.deepEqual(await errorOf(await publicKeys(env, owner, orgId, { ids: null })), { status: 400, error: IDS_REQUIRED });
});
