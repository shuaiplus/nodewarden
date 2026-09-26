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
