import assert from 'node:assert/strict';
import { test } from 'node:test';
import { desc } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { auditLogs } from '../db/schema';
import { createTestEnv } from '../test/support/env';
import { pruneAuditLogsToMax } from './storage-admin-repo';

test('pruneAuditLogsToMax keeps the newest entries, reports how many it removed and always keeps one', async () => {
  const env = await createTestEnv();
  const orm = getOrm(env.DB);
  const remaining = async () =>
    (await orm.select({ id: auditLogs.id }).from(auditLogs).orderBy(desc(auditLogs.createdAt))).map(({ id }) => id);
  assert.deepEqual(await remaining(), []);
  await orm.insert(auditLogs).values(
    Array.from({ length: 5 }, (_, minute) => ({
      id: `log-${minute}`,
      action: 'test.entry',
      createdAt: new Date(Date.UTC(2026, 0, 1, 0, minute)).toISOString(),
    })),
  );
  assert.equal(await pruneAuditLogsToMax(env.DB, 10), 0);
  assert.equal(await pruneAuditLogsToMax(env.DB, 2.9), 3);
  assert.deepEqual(await remaining(), ['log-4', 'log-3']);
  assert.equal(await pruneAuditLogsToMax(env.DB, 0), 1);
  assert.deepEqual(await remaining(), ['log-4']);
});
