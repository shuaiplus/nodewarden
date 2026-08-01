import bitwardenGlobalDomainsRaw from '../static/global_domains.bitwarden.json';
import customGlobalDomainsRaw from '../static/global_domains.custom.json';
import type { CustomEquivalentDomain, DomainRulesResponse, GlobalEquivalentDomain } from '../types';
import { normalizeEquivalentDomain } from '../../shared/domain-normalize';

// CONTRACT:
// Equivalent domains are a Bitwarden compatibility surface. The DB stores both
// the full custom rule list and the derived active equivalent-domain groups:
// - custom_equivalent_domains: UI/client rules with id + excluded state.
// - equivalent_domains: active groups derived from non-excluded custom rules.
// - excluded_global_equivalent_domains: disabled global rule type ids.
// Do not treat equivalent_domains and custom_equivalent_domains as accidental
// duplicates without a migration and compatibility plan.
type RawGlobalDomain = Partial<GlobalEquivalentDomain> & {
  Type?: unknown;
  Domains?: unknown;
  Excluded?: unknown;
};

function normalizeDomain(value: unknown): string {
  return normalizeEquivalentDomain(value);
}

function normalizeGlobalDomain(entry: RawGlobalDomain): GlobalEquivalentDomain | null {
  const type = Number(entry.type ?? entry.Type);
  if (!Number.isInteger(type)) return null;

  const rawDomains = entry.domains ?? entry.Domains;
  if (!Array.isArray(rawDomains)) return null;

  const domains = Array.from(new Set(rawDomains.map(normalizeDomain).filter(Boolean)));
  if (domains.length < 2) return null;

  return {
    type,
    domains,
    excluded: Boolean(entry.excluded ?? entry.Excluded ?? false),
  };
}

function normalizeGlobalDomains(input: unknown): GlobalEquivalentDomain[] {
  if (!Array.isArray(input)) return [];

  const seen = new Set<number>();
  const out: GlobalEquivalentDomain[] = [];
  for (const entry of input) {
    const normalized = normalizeGlobalDomain(entry as RawGlobalDomain);
    if (!normalized || seen.has(normalized.type)) continue;
    seen.add(normalized.type);
    out.push(normalized);
  }
  return out;
}

const bitwardenGlobalDomains = normalizeGlobalDomains(bitwardenGlobalDomainsRaw);
const customGlobalDomains = normalizeGlobalDomains(customGlobalDomainsRaw);

export const globalDomains: readonly GlobalEquivalentDomain[] = [
  ...bitwardenGlobalDomains,
  ...customGlobalDomains,
];

export function normalizeEquivalentDomains(input: unknown): string[][] {
  if (!Array.isArray(input)) return [];

  const groups: string[][] = [];
  const seenGroups = new Set<string>();
  for (const group of input) {
    if (!Array.isArray(group)) continue;
    const domains = Array.from(new Set(group.map(normalizeDomain).filter(Boolean)));
    if (domains.length < 2) continue;
    const key = domains.slice().sort().join('\n');
    if (seenGroups.has(key)) continue;
    seenGroups.add(key);
    groups.push(domains);
  }
  return groups;
}

export function mergeEquivalentDomainGroups(input: string[][]): string[][] {
  const parent = new Map<string, string>();

  function find(domain: string): string {
    const current = parent.get(domain);
    if (!current) {
      parent.set(domain, domain);
      return domain;
    }
    if (current === domain) return domain;
    const root = find(current);
    parent.set(domain, root);
    return root;
  }

  function union(a: string, b: string): void {
    const rootA = find(a);
    const rootB = find(b);
    if (rootA !== rootB) parent.set(rootB, rootA);
  }

  for (const group of normalizeEquivalentDomains(input)) {
    if (group.length < 2) continue;
    const [first, ...rest] = group;
    find(first);
    for (const domain of rest) union(first, domain);
  }

  const components = new Map<string, string[]>();
  for (const domain of parent.keys()) {
    const root = find(domain);
    const group = components.get(root) || [];
    group.push(domain);
    components.set(root, group);
  }

  return Array.from(components.values())
    .map((group) => group.sort())
    .filter((group) => group.length >= 2)
    .sort((a, b) => a[0].localeCompare(b[0]));
}

export function expandCustomEquivalentDomainsWithGlobals(
  customGroups: string[][],
  activeGlobalGroups: string[][]
): string[][] {
  const normalizedCustomGroups = normalizeEquivalentDomains(customGroups);
  if (!normalizedCustomGroups.length) return [];

  const customDomains = new Set(normalizedCustomGroups.flat());
  return mergeEquivalentDomainGroups([
    ...activeGlobalGroups,
    ...normalizedCustomGroups,
  ]).filter((group) => group.some((domain) => customDomains.has(domain)));
}

function createCustomDomainId(domains: string[], index: number): string {
  return `custom:${domains.slice().sort().join('|')}:${index}`;
}

export function normalizeCustomEquivalentDomains(input: unknown): CustomEquivalentDomain[] {
  if (!Array.isArray(input)) return [];

  const rules: CustomEquivalentDomain[] = [];
  const seenGroups = new Set<string>();
  for (const [index, item] of input.entries()) {
    const record = Array.isArray(item)
      ? { domains: item, excluded: false, id: '' }
      : item && typeof item === 'object'
        ? item as Record<string, unknown>
        : null;
    if (!record) continue;

    const domains = normalizeEquivalentDomains([record.domains ?? record.Domains])[0];
    if (!domains) continue;

    const key = domains.slice().sort().join('\n');
    if (seenGroups.has(key)) continue;
    seenGroups.add(key);

    const rawId = String(record.id ?? record.Id ?? '').trim();
    rules.push({
      id: rawId || createCustomDomainId(domains, index),
      domains,
      excluded: Boolean(record.excluded ?? record.Excluded ?? false),
    });
  }
  return rules;
}

export function customRulesToActiveEquivalentDomains(rules: CustomEquivalentDomain[]): string[][] {
  return mergeEquivalentDomainGroups(rules
    .filter((rule) => !rule.excluded)
    .map((rule) => rule.domains));
}

export function normalizeExcludedGlobalTypes(input: unknown): number[] {
  if (!Array.isArray(input)) return [];

  const validTypes = new Set(globalDomains.map((entry) => entry.type));
  const seen = new Set<number>();
  const out: number[] = [];
  for (const item of input) {
    const type = Number(typeof item === 'object' && item !== null ? (item as Record<string, unknown>).type : item);
    const excluded = typeof item === 'object' && item !== null
      ? Boolean((item as Record<string, unknown>).excluded)
      : true;
    if (!excluded || !Number.isInteger(type) || !validTypes.has(type) || seen.has(type)) continue;
    seen.add(type);
    out.push(type);
  }
  return out;
}

export function buildDomainsResponse(
  equivalentDomains: string[][],
  customEquivalentDomains: CustomEquivalentDomain[],
  excludedGlobalEquivalentDomains: number[],
  options: { omitExcludedGlobals?: boolean } = {}
): DomainRulesResponse {
  const excluded = new Set(excludedGlobalEquivalentDomains);
  const activeGlobalDomainGroups = globalDomains
    .filter((entry) => !excluded.has(entry.type))
    .map((entry) => entry.domains);
  const mergedEquivalentDomains = expandCustomEquivalentDomainsWithGlobals(
    equivalentDomains,
    activeGlobalDomainGroups
  );
  const globals = globalDomains
    .map((entry) => ({
      type: entry.type,
      domains: entry.domains,
      excluded: excluded.has(entry.type),
    }))
    .filter((entry) => !options.omitExcludedGlobals || !entry.excluded);

  return {
    equivalentDomains: mergedEquivalentDomains,
    customEquivalentDomains,
    globalEquivalentDomains: globals,
    object: 'domains',
  };
}
