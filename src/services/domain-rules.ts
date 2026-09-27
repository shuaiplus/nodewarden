import { z } from 'zod';
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

// Domain rules are advisory: malformed entries are dropped rather than failing the whole list, so legacy
// rows and older clients still load whatever rules remain valid.
const DomainGroup = z.array(z.unknown())
  .transform((group) => Array.from(new Set(group.map(normalizeEquivalentDomain).filter(Boolean))))
  .refine((domains) => domains.length >= 2);
const excludedFlag = z.unknown().optional().transform(Boolean);
const GlobalDomain = z.object({ type: z.coerce.number().int(), domains: DomainGroup, excluded: excludedFlag });
// A bare domain list is an included rule whose id is derived from its domains.
const CustomDomain = z.union([
  DomainGroup.transform((domains) => ({ id: '', domains, excluded: false })),
  z.object({ id: z.unknown().optional().transform((id) => String(id ?? '').trim()), domains: DomainGroup, excluded: excludedFlag }),
]);
// An object entry names a type and whether it is excluded; any other entry is an excluded type number.
const ExcludedType = z.union([
  z.object({ type: z.coerce.number(), excluded: z.unknown().refine(Boolean) }).transform((entry) => entry.type),
  z.custom((entry) => typeof entry !== 'object' || entry === null).transform(Number),
]);

const groupKey = (domains: string[]) => domains.slice().sort().join('\n');

// The valid entries of a list with their original positions, keeping the first entry per key.
function uniqueEntries<T>(input: unknown, entry: z.ZodType<T>, key: (value: T) => unknown): [T, number][] {
  const seen = new Set<unknown>();
  return (Array.isArray(input) ? input : []).flatMap((item, index) => {
    const parsed = entry.safeParse(item);
    if (!parsed.success || seen.has(key(parsed.data))) return [];
    seen.add(key(parsed.data));
    return [[parsed.data, index] as [T, number]];
  });
}

function normalizeGlobalDomains(input: unknown): GlobalEquivalentDomain[] {
  return uniqueEntries(input, GlobalDomain, (domain) => domain.type).map(([domain]) => domain);
}

const bitwardenGlobalDomains = normalizeGlobalDomains(bitwardenGlobalDomainsRaw);
const customGlobalDomains = normalizeGlobalDomains(customGlobalDomainsRaw);

export const globalDomains: readonly GlobalEquivalentDomain[] = [
  ...bitwardenGlobalDomains,
  ...customGlobalDomains,
];

export function normalizeEquivalentDomains(input: unknown): string[][] {
  return uniqueEntries(input, DomainGroup, groupKey).map(([domains]) => domains);
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
  return uniqueEntries(input, CustomDomain, (rule) => groupKey(rule.domains))
    .map(([rule, index]) => ({ ...rule, id: rule.id || createCustomDomainId(rule.domains, index) }));
}

export function customRulesToActiveEquivalentDomains(rules: CustomEquivalentDomain[]): string[][] {
  return mergeEquivalentDomainGroups(rules
    .filter((rule) => !rule.excluded)
    .map((rule) => rule.domains));
}

export function normalizeExcludedGlobalTypes(input: unknown): number[] {
  const knownTypes = new Set(globalDomains.map((entry) => entry.type));
  return uniqueEntries(input, ExcludedType.refine((type) => knownTypes.has(type)), (type) => type).map(([type]) => type);
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
