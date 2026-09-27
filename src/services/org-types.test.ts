import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EMPTY_PERMISSIONS, parsePermissions } from './org-types';

test('stored permissions keep only boolean grants of known flags and unparseable JSON holds none', () => {
  assert.deepEqual(
    parsePermissions(JSON.stringify({ manageUsers: true, manageGroups: 1, legacyFlag: true })),
    { ...EMPTY_PERMISSIONS, manageUsers: true },
  );
  assert.deepEqual(parsePermissions('null'), EMPTY_PERMISSIONS);
  assert.equal(parsePermissions('{not json'), null);
  assert.equal(parsePermissions(null), null);
});
