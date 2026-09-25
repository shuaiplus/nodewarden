import { test } from 'node:test';
import assert from 'node:assert/strict';
import { canCreateCollection, canEditCipher, canManageMembers, hasFullCollectionAccess, resolveCollectionPermission } from './org-authz';
import { MembershipStatus, MembershipType, type MembershipRecord } from './org-types';

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
