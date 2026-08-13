import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { config } from '../db/schema';

const REGISTERED_KEY = 'registered';

export async function isRegistered(db: D1Database): Promise<boolean> {
  const [row] = await getOrm(db).select({ value: config.value }).from(config).where(eq(config.key, REGISTERED_KEY)).limit(1);
  return row?.value === 'true';
}

export async function getConfigValue(db: D1Database, key: string): Promise<string | null> {
  const [row] = await getOrm(db).select({ value: config.value }).from(config).where(eq(config.key, key)).limit(1);
  return typeof row?.value === 'string' ? row.value : null;
}

export async function setConfigValue(db: D1Database, key: string, value: string): Promise<void> {
  await getOrm(db)
    .insert(config)
    .values({ key, value })
    .onConflictDoUpdate({ target: config.key, set: { value } });
}

export async function setRegistered(db: D1Database): Promise<void> {
  await setConfigValue(db, REGISTERED_KEY, 'true');
}
