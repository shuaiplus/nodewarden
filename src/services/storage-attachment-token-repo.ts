import { lt } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { usedAttachmentDownloadTokens } from '../db/schema';

type ShouldRunPeriodicCleanup = (lastRunAt: number, intervalMs: number) => boolean;

export async function consumeAttachmentDownloadToken(
  db: D1Database,
  shouldRunPeriodicCleanup: ShouldRunPeriodicCleanup,
  lastCleanupAt: number,
  cleanupIntervalMs: number,
  jti: string,
  expUnixSeconds: number
): Promise<{ consumed: boolean; cleanedUpAt: number | null }> {
  const orm = getOrm(db);
  const nowMs = Date.now();
  let cleanedUpAt: number | null = null;

  if (shouldRunPeriodicCleanup(lastCleanupAt, cleanupIntervalMs)) {
    await orm.delete(usedAttachmentDownloadTokens).where(lt(usedAttachmentDownloadTokens.expiresAt, nowMs));
    cleanedUpAt = nowMs;
  }

  const result = await orm
    .insert(usedAttachmentDownloadTokens)
    .values({ jti, expiresAt: expUnixSeconds * 1000 })
    .onConflictDoNothing({ target: usedAttachmentDownloadTokens.jti })
    .run();

  return {
    consumed: (result.meta.changes ?? 0) > 0,
    cleanedUpAt,
  };
}
