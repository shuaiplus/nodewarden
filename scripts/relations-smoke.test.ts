import assert from 'node:assert/strict';
import { test } from 'node:test';

import { getOrm } from '../src/db/client';
import { createTestEnv } from './support/env';

test('relations v2 through-queries execute against the generated baseline', async () => {
  const db = getOrm((await createTestEnv()).DB);

  const rows = await Promise.all([
    db.query.users.findMany({ with: { collections: true } }),
    db.query.ciphers.findMany({ with: { collections: true } }),
    db.query.organizationMemberships.findMany({ with: { groups: true } }),
    db.query.smProjects.findMany({ with: { secrets: true, serviceAccounts: true } }),
    db.query.collections.findMany({ with: { users: true, groups: true, ciphers: true } }),
    db.query.users.findMany({
      with: {
        personalCiphers: true,
        ciphers: true,
        grantedEmergencyAccess: true,
        receivedEmergencyAccess: true,
        createdInvites: true,
        usedInvites: true,
      },
    }),
  ]);

  for (const result of rows) {
    assert.equal(result.length, 0);
  }
});
