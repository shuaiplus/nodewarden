import type { Env } from '../types';
import {
  buildDomainsResponse,
  customRulesToActiveEquivalentDomains,
  normalizeCustomEquivalentDomains,
  normalizeEquivalentDomains,
  normalizeExcludedGlobalTypes,
} from '../services/domain-rules';
import { errorResponse, jsonResponse } from '../utils/response';
import * as domainRulesRepo from '../services/storage-domain-rules-repo';

// CONTRACT:
// This route accepts both camelCase and PascalCase Bitwarden-compatible payloads.
// It stores custom rules, then derives equivalentDomains from the non-excluded
// custom rules. Keep this behavior aligned with backup import/export and
// src/services/storage-domain-rules-repo.ts.
function firstPresent(payload: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(payload, key)) return payload[key];
  }
  return undefined;
}

async function readPayload(request: Request): Promise<Record<string, unknown>> {
  try {
    const parsed = await request.json();
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

export async function handleGetDomains(env: Env, userId: string): Promise<Response> {
  const settings = await domainRulesRepo.getUserDomainSettings(env.DB, userId);
  return jsonResponse(buildDomainsResponse(
    settings.equivalentDomains,
    settings.customEquivalentDomains,
    settings.excludedGlobalEquivalentDomains
  ));
}

export async function handleUpdateDomains(request: Request, env: Env, userId: string): Promise<Response> {
  const payload = await readPayload(request);
  const current = await domainRulesRepo.getUserDomainSettings(env.DB, userId);
  const equivalentDomainsRaw = firstPresent(payload, [
    'equivalentDomains',
    'EquivalentDomains',
  ]);
  const customEquivalentDomainsRaw = firstPresent(payload, [
    'customEquivalentDomains',
    'CustomEquivalentDomains',
  ]);
  const excludedGlobalEquivalentDomainsRaw = firstPresent(payload, [
    'excludedGlobalEquivalentDomains',
    'ExcludedGlobalEquivalentDomains',
    // Some older compatible clients send the excluded type list under this key.
    'globalEquivalentDomains',
    'GlobalEquivalentDomains',
  ]);
  const customEquivalentDomains = customEquivalentDomainsRaw === undefined
    ? (equivalentDomainsRaw === undefined
        ? current.customEquivalentDomains
        : normalizeCustomEquivalentDomains(normalizeEquivalentDomains(equivalentDomainsRaw)))
    : normalizeCustomEquivalentDomains(customEquivalentDomainsRaw);
  const equivalentDomains = customRulesToActiveEquivalentDomains(customEquivalentDomains);
  const excludedGlobalEquivalentDomains = excludedGlobalEquivalentDomainsRaw === undefined
    ? current.excludedGlobalEquivalentDomains
    : normalizeExcludedGlobalTypes(excludedGlobalEquivalentDomainsRaw);

  await domainRulesRepo.saveUserDomainSettings(env.DB, userId, equivalentDomains, customEquivalentDomains, excludedGlobalEquivalentDomains);

  const settings = await domainRulesRepo.getUserDomainSettings(env.DB, userId);
  if (!settings) {
    return errorResponse('Domain settings unavailable', 500);
  }
  return jsonResponse(buildDomainsResponse(
    settings.equivalentDomains,
    settings.customEquivalentDomains,
    settings.excludedGlobalEquivalentDomains
  ));
}
