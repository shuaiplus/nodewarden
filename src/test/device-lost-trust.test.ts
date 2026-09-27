import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { auditLogs } from '../db/schema';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('official clients report lost device trust with no body and a Device-Identifier header', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const reported = await authedFetch(env, { method: 'POST', path: '/api/devices/lost-trust', userId: user.id, headers: { 'Device-Identifier': 'lost-device' } });
  assert.equal(reported.status, 200);
  const audit = await getOrm(env.DB).select({ targetId: auditLogs.targetId }).from(auditLogs).where(eq(auditLogs.action, 'device.lost_trust')).get();
  assert.equal(audit?.targetId, 'lost-device');
  const anonymous = await authedFetch(env, { method: 'POST', path: '/api/devices/lost-trust', userId: user.id });
  assert.equal(anonymous.status, 400);
});
