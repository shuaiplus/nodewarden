import assert from 'node:assert/strict';
import test from 'node:test';

import { authedFetch, createTestEnv, seedUser } from './support/env';

test('official clients report lost device trust with no body and a Device-Identifier header', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const reported = await authedFetch(env, { method: 'POST', path: '/api/devices/lost-trust', userId: user.id, headers: { 'Device-Identifier': 'lost-device' } });
  assert.equal(reported.status, 200);
  const audit = await env.DB.prepare("SELECT target_id FROM audit_logs WHERE action = 'device.lost_trust'").first<{ target_id: string }>();
  assert.equal(audit?.target_id, 'lost-device');
  const anonymous = await authedFetch(env, { method: 'POST', path: '/api/devices/lost-trust', userId: user.id });
  assert.equal(anonymous.status, 400);
});
