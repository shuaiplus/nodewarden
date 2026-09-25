import { lt } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { totpLoginReplays } from '../db/schema';

type ShouldRunPeriodicCleanup = (lastRunAt: number, intervalMs: number) => boolean;

export async function consumeTotpLoginCounter(
  db: D1Database,
  shouldRunPeriodicCleanup: ShouldRunPeriodicCleanup,
  lastCleanupAt: number,
  cleanupIntervalMs: number,
  userId: string,
  timeCounter: number,
  consumedAtMs: number,
  markerTtlMs: number
): Promise<{ consumed: boolean; cleanedUpAt: number | null }> {
  const orm = getOrm(db);
  let cleanedUpAt: number | null = null;

  if (shouldRunPeriodicCleanup(lastCleanupAt, cleanupIntervalMs)) {
    await orm.delete(totpLoginReplays).where(lt(totpLoginReplays.consumedAt, consumedAtMs - markerTtlMs));
    cleanedUpAt = consumedAtMs;
  }

  const result = await orm
    .insert(totpLoginReplays)
    .values({ userId, timeCounter, consumedAt: consumedAtMs })
    .onConflictDoNothing({ target: [totpLoginReplays.userId, totpLoginReplays.timeCounter] })
    .run();

  return {
    consumed: (result.meta.changes ?? 0) > 0,
    cleanedUpAt,
  };
}
