import assert from 'node:assert/strict';
import test from 'node:test';

import { createAuditLog, listAuditLogs, type AuditLogListOptions } from '../services/storage-admin-repo';
import { authedFetch, createTestEnv, seedUser } from './support/env';

test('non-numeric audit log paging falls back to the default page instead of NaN', async () => {
  const env = await createTestEnv();
  const admin = await seedUser(env, { role: 'admin' });
  const response = await authedFetch(env, { path: '/api/admin/logs?limit=abc&offset=xyz', userId: admin.id });
  assert.equal(response.status, 200);
  const body = (await response.json()) as { limit: number; offset: number };
  assert.deepEqual([body.limit, body.offset], [50, 0]);
});

test('audit log filters take the action prefix literally, bound the time range and search case-insensitively through both joined emails', async () => {
  const env = await createTestEnv();
  const actor = await seedUser(env, { email: 'Finder@Example.test' });
  const target = await seedUser(env, { email: 'target@example.test' });
  const entry = (
    id: string,
    action: string,
    createdAt: string,
    fields: { actorUserId?: string; targetType?: string; targetId?: string } = {},
  ) =>
    createAuditLog(env.DB, {
      id,
      action,
      createdAt,
      category: 'system',
      level: 'info',
      metadata: null,
      actorUserId: fields.actorUserId ?? null,
      targetType: fields.targetType ?? null,
      targetId: fields.targetId ?? null,
    });
  await entry('underscore', 'user_login', '2024-01-01T00:00:00.000Z', { actorUserId: actor.id });
  await entry('wildcard', 'userXlogin', '2024-06-01T00:00:00.000Z', { targetType: 'user', targetId: target.id });
  await entry('cipher', 'cipher.edit', '2025-01-01T00:00:00.000Z', { targetType: 'cipher', targetId: 'CIPHER-ID' });
  const ids = async (filters: Partial<AuditLogListOptions>) =>
    (await listAuditLogs(env.DB, { limit: 10, offset: 0, ...filters })).logs.map((log) => log.id);

  assert.deepEqual(await ids({ actionPrefix: 'user_' }), ['underscore']);
  assert.deepEqual(await ids({ from: '2024-06-01T00:00:00.000Z', to: '2024-06-01T00:00:00.000Z' }), ['wildcard']);
  assert.deepEqual(await ids({ q: 'FINDER@' }), ['underscore']);
  assert.deepEqual(await ids({ q: 'target@' }), ['wildcard']);
  assert.deepEqual(await ids({ q: 'cipher-id' }), ['cipher']);
});
