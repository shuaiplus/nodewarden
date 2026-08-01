import type { UserDomainSettings } from '../types';
import { normalizeCustomEquivalentDomains, normalizeEquivalentDomains } from './domain-rules';

// Storage adapter for the domain_settings table.
//
// CONTRACT:
// equivalent_domains is kept as the active derived groups for compatibility and
// fallback reads. custom_equivalent_domains is the full rule list that preserves
// UI/client state. Save both together through saveUserDomainSettings().
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
  const row = await db
    .prepare('SELECT equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at FROM domain_settings WHERE user_id = ?')
    .bind(userId)
    .first<{
      equivalent_domains: string | null;
      custom_equivalent_domains: string | null;
      excluded_global_equivalent_domains: string | null;
      updated_at: string | null;
    }>();
  const equivalentDomains = normalizeEquivalentDomains(parseJsonArray<string[]>(row?.equivalent_domains, []));
  const storedCustomEquivalentDomains = row?.custom_equivalent_domains
    ? normalizeCustomEquivalentDomains(parseJsonArray<unknown>(row.custom_equivalent_domains, []))
    : [];
  const customEquivalentDomains = storedCustomEquivalentDomains.length
    ? storedCustomEquivalentDomains
    : normalizeCustomEquivalentDomains(equivalentDomains);

  return {
    userId,
    equivalentDomains,
    customEquivalentDomains,
    excludedGlobalEquivalentDomains: parseJsonArray<number>(row?.excluded_global_equivalent_domains, []),
    updatedAt: row?.updated_at || null,
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
  await db
    .prepare(
      'INSERT INTO domain_settings(user_id, equivalent_domains, custom_equivalent_domains, excluded_global_equivalent_domains, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(user_id) DO UPDATE SET ' +
      'equivalent_domains = excluded.equivalent_domains, ' +
      'custom_equivalent_domains = excluded.custom_equivalent_domains, ' +
      'excluded_global_equivalent_domains = excluded.excluded_global_equivalent_domains, ' +
      'updated_at = excluded.updated_at'
    )
    .bind(
      userId,
      JSON.stringify(equivalentDomains),
      JSON.stringify(customEquivalentDomains),
      JSON.stringify(excludedGlobalEquivalentDomains),
      updatedAt
    )
    .run();
}
