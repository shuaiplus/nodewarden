import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { userRevisions } from '../db/schema';

export async function getRevisionDate(db: D1Database, userId: string): Promise<string> {
  const orm = getOrm(db);
  const [row] = await orm
    .select({ revisionDate: userRevisions.revisionDate })
    .from(userRevisions)
    .where(eq(userRevisions.userId, userId))
    .limit(1);
  if (row?.revisionDate) return row.revisionDate;

  const date = new Date().toISOString();
  await orm
    .insert(userRevisions)
    .values({ userId, revisionDate: date })
    .onConflictDoNothing({ target: userRevisions.userId });
  return date;
}

export async function updateRevisionDate(db: D1Database, userId: string): Promise<string> {
  const date = new Date().toISOString();
  await getOrm(db)
    .insert(userRevisions)
    .values({ userId, revisionDate: date })
    .onConflictDoUpdate({
      target: userRevisions.userId,
      set: { revisionDate: date },
    });
  return date;
}
