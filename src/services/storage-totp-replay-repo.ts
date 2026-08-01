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
  let cleanedUpAt: number | null = null;

  if (shouldRunPeriodicCleanup(lastCleanupAt, cleanupIntervalMs)) {
    await db
      .prepare('DELETE FROM totp_login_replays WHERE consumed_at < ?')
      .bind(consumedAtMs - markerTtlMs)
      .run();
    cleanedUpAt = consumedAtMs;
  }

  const result = await db
    .prepare(
      'INSERT INTO totp_login_replays(user_id, time_counter, consumed_at) VALUES(?, ?, ?) ' +
        'ON CONFLICT(user_id, time_counter) DO NOTHING'
    )
    .bind(userId, timeCounter, consumedAtMs)
    .run();

  return {
    consumed: (result.meta.changes ?? 0) > 0,
    cleanedUpAt,
  };
}
