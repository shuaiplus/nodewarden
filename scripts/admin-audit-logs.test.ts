import assert from 'node:assert/strict';
import test from 'node:test';

import { authedFetch, createTestEnv, seedUser } from './support/env';

test('non-numeric audit log paging falls back to the default page instead of NaN', async () => {
  const env = await createTestEnv();
  const admin = await seedUser(env, { role: 'admin' });
  const response = await authedFetch(env, { path: '/api/admin/logs?limit=abc&offset=xyz', userId: admin.id });
  assert.equal(response.status, 200);
  const body = await response.json() as { limit: number; offset: number };
  assert.deepEqual([body.limit, body.offset], [50, 0]);
});
