import { lt } from 'drizzle-orm';

import { LIMITS } from '../config/limits';
import { getOrm } from '../db/client';
import { usedAttachmentDownloadTokens } from '../db/schema';
import { shouldRunPeriodicCleanup } from './periodic-cleanup';

let lastCleanupAt = 0;

// Marks a download token JTI as used; true only on first use.
export async function consumeAttachmentDownloadToken(
  db: D1Database,
  jti: string,
  expUnixSeconds: number,
): Promise<boolean> {
  const orm = getOrm(db);
  const nowMs = Date.now();
  if (shouldRunPeriodicCleanup(lastCleanupAt, LIMITS.cleanup.attachmentTokenCleanupIntervalMs)) {
    await orm.delete(usedAttachmentDownloadTokens).where(lt(usedAttachmentDownloadTokens.expiresAt, nowMs));
    lastCleanupAt = nowMs;
  }
  const result = await orm
    .insert(usedAttachmentDownloadTokens)
    .values({ jti, expiresAt: expUnixSeconds * 1000 })
    .onConflictDoNothing({ target: usedAttachmentDownloadTokens.jti })
    .run();
  return (result.meta.changes ?? 0) > 0;
}
