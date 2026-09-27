import { LIMITS } from '../config/limits';

// Housekeeping runs at most once per interval, on a sampled fraction of requests, so no single
// request pays for it every time and quiet periods do not pile work up.
export function shouldRunPeriodicCleanup(lastRunAt: number, intervalMs: number): boolean {
  return Date.now() - lastRunAt >= intervalMs && Math.random() < LIMITS.cleanup.cleanupProbability;
}
