import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { domainSettings } from '../db/schema';
import type { UserDomainSettings } from '../types';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains } from './domain-rules';

function parseJsonArray<T>(raw: string | null | undefined, fallback: T[]): T[] {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? parsed as T[] : fallback;
  } catch {
    return fallback;
  }
}

export async function getUserDomainSettings(db: D1Database, userId: string): Promise<UserDomainSettings> {
  const [row] = await getOrm(db)
    .select()
    .from(domainSettings)
    .where(eq(domainSettings.userId, userId))
    .limit(1);
  const equivalentDomains = normalizeEquivalentDomains(parseJsonArray<string[]>(row?.equivalentDomains, []));
  const storedCustomEquivalentDomains = row?.customEquivalentDomains
    ? normalizeCustomEquivalentDomains(parseJsonArray<unknown>(row.customEquivalentDomains, []))
    : [];
  const customEquivalentDomains = storedCustomEquivalentDomains.length
    ? storedCustomEquivalentDomains
    : normalizeCustomEquivalentDomains(equivalentDomains);

  return {
    userId,
    equivalentDomains,
    customEquivalentDomains,
    excludedGlobalEquivalentDomains: parseJsonArray<number>(row?.excludedGlobalEquivalentDomains, []),
    updatedAt: row?.updatedAt || null,
  };
}

export async function saveUserDomainSettings(
  db: D1Database,
  userId: string,
  equivalentDomains: string[][],
  customEquivalentDomains: UserDomainSettings['customEquivalentDomains'],
  excludedGlobalEquivalentDomains: number[],
  updatedAt: string
): Promise<void> {
  const values = {
    userId,
    equivalentDomains: JSON.stringify(equivalentDomains),
    customEquivalentDomains: JSON.stringify(customEquivalentDomains),
    excludedGlobalEquivalentDomains: JSON.stringify(excludedGlobalEquivalentDomains),
    updatedAt,
  };
  await getOrm(db)
    .insert(domainSettings)
    .values(values)
    .onConflictDoUpdate({
      target: domainSettings.userId,
      set: {
        equivalentDomains: values.equivalentDomains,
        customEquivalentDomains: values.customEquivalentDomains,
        excludedGlobalEquivalentDomains: values.excludedGlobalEquivalentDomains,
        updatedAt: values.updatedAt,
      },
    });
}
