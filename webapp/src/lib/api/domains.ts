import { t } from '@/lib/i18n';
import type { DomainRules } from '@/lib/types';
import { parseErrorMessage, parseJson, type AuthedFetch } from './shared';

function normalizeDomainsResponse(body: Partial<DomainRules> & Record<string, unknown>): DomainRules {
  const equivalentDomains = Array.isArray(body.equivalentDomains)
    ? body.equivalentDomains
    : Array.isArray(body.EquivalentDomains)
      ? body.EquivalentDomains as string[][]
      : [];
  const globalEquivalentDomains = Array.isArray(body.globalEquivalentDomains)
    ? body.globalEquivalentDomains
    : Array.isArray(body.GlobalEquivalentDomains)
      ? body.GlobalEquivalentDomains as DomainRules['globalEquivalentDomains']
      : [];
  const customEquivalentDomains = Array.isArray(body.customEquivalentDomains)
    ? body.customEquivalentDomains as DomainRules['customEquivalentDomains']
    : Array.isArray(body.CustomEquivalentDomains)
      ? body.CustomEquivalentDomains as DomainRules['customEquivalentDomains']
      : equivalentDomains.map((domains, index) => ({
          id: `custom:${index}`,
          domains,
          excluded: false,
        }));

  return {
    equivalentDomains,
    customEquivalentDomains,
    globalEquivalentDomains,
    object: 'domains',
  };
}

export async function getDomainRules(authedFetch: AuthedFetch): Promise<DomainRules> {
  const resp = await authedFetch('/api/settings/domains');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_domain_rules_load_failed')));
  const body = await parseJson<Partial<DomainRules> & Record<string, unknown>>(resp);
  if (!body) throw new Error(t('txt_domain_rules_invalid_response'));
  return normalizeDomainsResponse(body);
}

export async function saveDomainRules(
  authedFetch: AuthedFetch,
  payload: {
    customEquivalentDomains: DomainRules['customEquivalentDomains'];
    equivalentDomains: string[][];
    excludedGlobalEquivalentDomains: number[];
  }
): Promise<DomainRules> {
  const resp = await authedFetch('/api/settings/domains', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) {
    throw new Error(await parseErrorMessage(resp, t('txt_domain_rules_save_failed')));
  }
  const body = await parseJson<Partial<DomainRules> & Record<string, unknown>>(resp);
  if (!body) throw new Error(t('txt_domain_rules_invalid_response'));
  return normalizeDomainsResponse(body);
}
