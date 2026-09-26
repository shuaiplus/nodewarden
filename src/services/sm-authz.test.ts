import assert from 'node:assert/strict';
import test from 'node:test';
import { grantsFromRows, projectAccess } from './sm-authz';

test('project grants merge direct and group access and admins bypass policy checks', () => {
  const grants = grantsFromRows({ projects: [{ id: 'p', write_access: 0 }, { id: 'p', write_access: 1 }], secrets: [], serviceAccounts: [] });
  assert.equal(projectAccess({ kind: 'user', membershipId: 'u' }, grants, 'p'), 'write');
  assert.equal(projectAccess({ kind: 'user', membershipId: 'u' }, grants, 'other'), 'none');
  assert.equal(projectAccess({ kind: 'admin', membershipId: 'a' }, grants, 'other'), 'write');
  assert.equal(projectAccess({ kind: 'serviceAccount', serviceAccountId: 's' }, grants, 'p'), 'write');
});

test('secret writes require destination write but preserve directly granted projectless edits', async () => {
  const { secretAccess, canCreateSecret, canUpdateSecret } = await import('./sm-authz');
  const user = { kind: 'user', membershipId: 'u' } as const;
  const grants = grantsFromRows({ projects: [{ id: 'read', write_access: 0 }, { id: 'write', write_access: 1 }], secrets: [{ id: 's', write_access: 1 }], serviceAccounts: [] });
  assert.equal(secretAccess(user, grants, { id: 'other', projectIds: ['read'] }), 'read');
  assert.equal(canCreateSecret(user, grants, undefined), false);
  assert.equal(canCreateSecret(user, grants, 'write'), true);
  assert.equal(canUpdateSecret(user, grants, { id: 's', projectIds: [] }, []), true);
  assert.equal(canUpdateSecret(user, grants, { id: 's', projectIds: ['write'] }, []), false);
  assert.equal(canUpdateSecret(user, grants, { id: 's', projectIds: ['write'] }, ['read']), false);
  assert.equal(canUpdateSecret(user, grants, { id: 's', projectIds: ['read'] }, ['write']), true);
});

test('machine-account management is human-only and its people grants always allow writes', async () => {
  const { serviceAccountAccess } = await import('./sm-authz');
  const grants = grantsFromRows({ projects: [], secrets: [], serviceAccounts: [{ id: 'sa' }] });
  assert.equal(serviceAccountAccess({ kind: 'admin', membershipId: 'a' }, grants, 'other'), 'write');
  assert.equal(serviceAccountAccess({ kind: 'user', membershipId: 'u' }, grants, 'sa'), 'write');
  assert.equal(serviceAccountAccess({ kind: 'user', membershipId: 'u' }, grants, 'other'), 'none');
  assert.equal(serviceAccountAccess({ kind: 'serviceAccount', serviceAccountId: 'sa' }, grants, 'sa'), 'none');
});
