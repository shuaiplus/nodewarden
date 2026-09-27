import { eq } from 'drizzle-orm';
import { z } from 'zod';

import { getOrm } from '../db/client';
import { domainSettings } from '../db/schema';
import type { UserDomainSettings } from '../types';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains } from './domain-rules';
import { updateRevisionDate } from './storage-revision-repo';

// Rules are normalized on write, so a missing or corrupt stored value reads as no rules instead of failing sync.
function parseStored(raw: string | null | undefined): unknown {
  try {
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

const StoredTypes = z.array(z.int()).catch([]);

export async function getUserDomainSettings(db: D1Database, userId: string): Promise<UserDomainSettings> {
  const [row] = await getOrm(db).select().from(domainSettings).where(eq(domainSettings.userId, userId)).limit(1);
  const equivalentDomains = normalizeEquivalentDomains(parseStored(row?.equivalentDomains));
  const storedCustomEquivalentDomains = normalizeCustomEquivalentDomains(parseStored(row?.customEquivalentDomains));
  const customEquivalentDomains = storedCustomEquivalentDomains.length
    ? storedCustomEquivalentDomains
    : normalizeCustomEquivalentDomains(equivalentDomains);

  return {
    userId,
    equivalentDomains,
    customEquivalentDomains,
    excludedGlobalEquivalentDomains: StoredTypes.parse(parseStored(row?.excludedGlobalEquivalentDomains)),
    updatedAt: row?.updatedAt || null,
  };
}

export async function saveUserDomainSettings(
  db: D1Database,
  userId: string,
  equivalentDomains: string[][],
  customEquivalentDomains: UserDomainSettings['customEquivalentDomains'],
  excludedGlobalEquivalentDomains: number[],
): Promise<void> {
  const values = {
    userId,
    equivalentDomains: JSON.stringify(equivalentDomains),
    customEquivalentDomains: JSON.stringify(customEquivalentDomains),
    excludedGlobalEquivalentDomains: JSON.stringify(excludedGlobalEquivalentDomains),
    updatedAt: new Date().toISOString(),
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
  await updateRevisionDate(db, userId);
}
