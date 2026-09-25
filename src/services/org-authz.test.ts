import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  acceptInviteCheck,
  canCreateCollection,
  canEditCipher,
  canManageMembers,
  confirmMemberCheck,
  hasFullCollectionAccess,
  memberRoleChangeCheck,
  planCollectionAssignment,
  resolveCollectionPermission,
} from './org-authz';
import {
  EMPTY_PERMISSIONS,
  MembershipStatus,
  MembershipType,
  revokeStatus,
  type MembershipRecord,
  type OrgPermissions,
} from './org-types';

function member(overrides: Partial<MembershipRecord> = {}): MembershipRecord {
  return {
    id: 'm1',
    userId: 'u1',
    orgId: 'o1',
    email: 'a@example.com',
    invitedByEmail: null,
    accessAll: false,
    key: '',
    status: MembershipStatus.Confirmed,
    type: MembershipType.User,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: '',
    updatedAt: '',
    ...overrides,
  };
}

test('owners have full collection access and can manage members', () => {
  const owner = member({ type: MembershipType.Owner, accessAll: true });
  assert.equal(hasFullCollectionAccess(owner), true);
  assert.equal(canManageMembers(owner), true);
  assert.equal(canCreateCollection(owner), true);
});

test('users cannot edit read-only collections', () => {
  const user = member({ type: MembershipType.User });
  assert.equal(hasFullCollectionAccess(user), false);
  const assigned = new Map([['c1', { collectionId: 'c1', readOnly: true, hidePasswords: false, manage: false }]]);
  assert.equal(canEditCipher(user, ['c1'], assigned), false);
  const permission = resolveCollectionPermission(user, assigned.get('c1') || null);
  assert.equal(permission.canView, true);
  assert.equal(permission.canEdit, false);
});

test('revoked members lose access', () => {
  const revoked = member({ type: MembershipType.Admin, status: MembershipStatus.Revoked, accessAll: true });
  assert.equal(hasFullCollectionAccess(revoked), false);
  assert.equal(canManageMembers(revoked), false);
});

const ORG_NAME = 'Acme';
const INVITEE_EMAIL = 'a@example.com';
const REVOKED_MESSAGE = `Your access to the ${ORG_NAME} vault has been revoked.`;

test('only an Invited row whose email matches the user can be accepted', () => {
  const invited = member({ status: MembershipStatus.Invited, userId: null });
  assert.deepEqual(acceptInviteCheck(invited, INVITEE_EMAIL.toUpperCase(), null, ORG_NAME), { ok: true, member: invited });
  assert.deepEqual(
    acceptInviteCheck(invited, 'b@example.com', null, ORG_NAME),
    { ok: false, message: 'User email does not match invite.' },
  );
  assert.deepEqual(
    acceptInviteCheck(member({ status: MembershipStatus.Invited, email: null }), INVITEE_EMAIL, null, ORG_NAME),
    { ok: false, message: 'User email does not match invite.' },
  );
  [MembershipStatus.Accepted, MembershipStatus.Confirmed, MembershipStatus.Staged].forEach((status) => {
    assert.deepEqual(acceptInviteCheck(member({ status }), INVITEE_EMAIL, null, ORG_NAME), { ok: false, message: 'Already accepted.' });
  });
});

test('a revoked member cannot un-revoke themselves by accepting again', () => {
  [revokeStatus(MembershipStatus.Confirmed), revokeStatus(MembershipStatus.Invited), MembershipStatus.Revoked].forEach((status) => {
    assert.deepEqual(acceptInviteCheck(member({ status }), INVITEE_EMAIL, null, ORG_NAME), { ok: false, message: REVOKED_MESSAGE });
  });
});

test('a user who already belongs to the org cannot accept a second invite', () => {
  const existing = member({ id: 'm0', status: MembershipStatus.Confirmed });
  assert.deepEqual(
    acceptInviteCheck(member({ status: MembershipStatus.Invited }), INVITEE_EMAIL, existing, ORG_NAME),
    { ok: false, message: 'You are already part of this organization.' },
  );
  assert.deepEqual(
    acceptInviteCheck(member({ status: MembershipStatus.Accepted }), INVITEE_EMAIL, existing, ORG_NAME),
    { ok: false, message: 'Invitation already accepted. You will receive an email when your organization membership is confirmed.' },
  );
});

test('only an Accepted row bound to a user in the same org can be confirmed', () => {
  const notValid = { ok: false, message: 'User not valid.' };
  const accepted = member({ status: MembershipStatus.Accepted });
  assert.deepEqual(confirmMemberCheck(accepted, 'o1'), { ok: true, member: accepted });
  assert.deepEqual(confirmMemberCheck(member({ status: MembershipStatus.Invited }), 'o1'), notValid);
  assert.deepEqual(confirmMemberCheck(member({ status: MembershipStatus.Confirmed }), 'o1'), notValid);
  assert.deepEqual(confirmMemberCheck(member({ status: revokeStatus(MembershipStatus.Accepted) }), 'o1'), notValid);
  assert.deepEqual(confirmMemberCheck(member({ status: MembershipStatus.Accepted, userId: null }), 'o1'), notValid);
  assert.deepEqual(confirmMemberCheck(member({ status: MembershipStatus.Accepted }), 'o2'), notValid);
  assert.deepEqual(confirmMemberCheck(null, 'o1'), notValid);
});

test('only Owners touch Owner roles, and Custom managers stay within Users, Custom and their own permissions', () => {
  const { Owner, Admin, User, Custom } = MembershipType;
  const allowed = { ok: true };
  const onlyOwners = { ok: false, message: "Only an Owner can manage another Owner's account." };
  const notAdmins = { ok: false, message: 'Custom users can not manage Admins or Owners.' };
  const ownPermissions = { ok: false, message: 'Custom users can only grant the same custom permissions that they have.' };
  const owner = member({ type: Owner });
  const admin = member({ type: Admin });
  const manager = member({ type: Custom, permissions: { ...EMPTY_PERMISSIONS, manageUsers: true, accessReports: true } });
  const reports = { ...EMPTY_PERMISSIONS, accessReports: true };
  const policies = { ...EMPTY_PERMISSIONS, managePolicies: true };
  const cases: Array<[MembershipRecord, number, number, OrgPermissions, object]> = [
    [owner, User, Owner, EMPTY_PERMISSIONS, allowed],
    [owner, Owner, User, EMPTY_PERMISSIONS, allowed],
    [admin, User, Owner, EMPTY_PERMISSIONS, onlyOwners],
    [admin, Owner, Admin, EMPTY_PERMISSIONS, onlyOwners],
    [admin, User, Admin, EMPTY_PERMISSIONS, allowed],
    [admin, User, Custom, policies, allowed],
    [manager, User, Owner, EMPTY_PERMISSIONS, onlyOwners],
    [manager, User, Admin, EMPTY_PERMISSIONS, notAdmins],
    [manager, Admin, User, EMPTY_PERMISSIONS, notAdmins],
    [manager, User, Custom, policies, ownPermissions],
    [manager, User, Custom, reports, allowed],
    [manager, Custom, User, EMPTY_PERMISSIONS, allowed],
    [member({ type: Custom, permissions: reports }), User, User, EMPTY_PERMISSIONS, notAdmins],
  ];
  cases.forEach(([actor, currentType, newType, permissions, expected]) => {
    assert.deepEqual(memberRoleChangeCheck(actor, currentType, newType, permissions, 'update'), expected, `${actor.type}: ${currentType} -> ${newType}`);
  });
  assert.deepEqual(memberRoleChangeCheck(admin, Owner, Owner, EMPTY_PERMISSIONS, 'invite'), {
    ok: false,
    message: "Only an Owner can configure another Owner's account.",
  });
});

// Upstream CollectionCipher_UpdateCollections and 1aed7ce03: collections outside `available` survive.
test('planCollectionAssignment adds and drops only the collections the caller may change', () => {
  assert.deepEqual(
    planCollectionAssignment({ current: ['A', 'B'], requested: ['C'], available: ['B', 'C'] }),
    { insert: ['C'], remove: ['B'] }
  );
  assert.deepEqual(
    planCollectionAssignment({ current: ['A'], requested: ['A', 'D'], available: ['B'] }),
    { insert: [], remove: [] }
  );
});
