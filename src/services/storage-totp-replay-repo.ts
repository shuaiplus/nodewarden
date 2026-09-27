import { lt } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { totpLoginReplays } from '../db/schema';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

const CLEANUP_INTERVAL_MS = 10 * 60 * 1000;
const MARKER_TTL_MS = 5 * 60 * 1000;
let lastCleanupAt = 0;

// Records a TOTP time step as used for the user; false when that step was already consumed.
export async function consumeTotpLoginCounter(db: D1Database, userId: string, timeCounter: number, consumedAtMs = Date.now()): Promise<boolean> {
  if (!Number.isSafeInteger(timeCounter) || timeCounter < 0) return false;
  const orm = getOrm(db);
  if (shouldRunPeriodicCleanup(lastCleanupAt, CLEANUP_INTERVAL_MS)) {
    await orm.delete(totpLoginReplays).where(lt(totpLoginReplays.consumedAt, consumedAtMs - MARKER_TTL_MS));
    lastCleanupAt = consumedAtMs;
  }
  const result = await orm
    .insert(totpLoginReplays)
    .values({ userId, timeCounter, consumedAt: consumedAtMs })
    .onConflictDoNothing({ target: [totpLoginReplays.userId, totpLoginReplays.timeCounter] })
    .run();
  return (result.meta.changes ?? 0) > 0;
}
