import { z } from 'zod';
import { normalizeJsonKeys } from '../utils/response';

export const ENTERPRISE_PLAN_TYPE = 20;
export const ENTERPRISE_PRODUCT_TIER = 3;

// Official license files are PascalCase and dummy ones may be empty or not an object at all, so each
// field falls back on its own rather than rejecting the upload.
const OrganizationLicense = z.preprocess(normalizeJsonKeys, z.object({
  name: z.string().trim().catch(''),
  billingEmail: z.string().trim().toLowerCase().includes('@').nullable().catch(null),
  planType: z.coerce.number().positive().catch(ENTERPRISE_PLAN_TYPE),
}).catch({ name: '', billingEmail: null, planType: ENTERPRISE_PLAN_TYPE }));

export function buildNodeWardenEnterpriseLicense(options?: {
  name?: string;
  billingEmail?: string;
}): Record<string, unknown> {
  const issued = new Date().toISOString();
  return {
    licenseType: 1,
    licenseKey: 'nodewarden-enterprise',
    installationId: '00000000-0000-0000-0000-000000000001',
    name: options?.name || 'NodeWarden Enterprise',
    billingEmail: options?.billingEmail || null,
    businessName: options?.name || 'NodeWarden Enterprise',
    enabled: true,
    plan: 'Enterprise (Annually)',
    planType: ENTERPRISE_PLAN_TYPE,
    seats: null,
    maxCollections: null,
    maxStorageGb: 32767,
    selfHost: true,
    usersGetPremium: true,
    use2fa: true,
    useApi: true,
    useCustomPermissions: true,
    useDirectory: true,
    useEvents: true,
    useGroups: true,
    usePolicies: true,
    useResetPassword: true,
    useScim: true,
    useSso: true,
    useTotp: true,
    usePasswordManager: true,
    useSecretsManager: true,
    useKeyConnector: false,
    useOrganizationDomains: true,
    version: 15,
    issued,
    expires: '2099-12-31T23:59:59.000Z',
    refresh: '2099-12-31T23:59:59.000Z',
    trial: false,
  };
}

export function parseOrganizationLicense(raw: unknown, fallbackName: string) {
  const license = OrganizationLicense.parse(raw);
  return { ...license, name: license.name || fallbackName.trim() || 'Organization' };
}

export function enterprisePlansResponse() {
  const enterprise = {
    type: ENTERPRISE_PLAN_TYPE,
    product: 0,
    productTier: ENTERPRISE_PRODUCT_TIER,
    name: 'Enterprise',
    nameLocalizationKey: 'planNameEnterprise',
    descriptionLocalizationKey: 'planDescEnterprise',
    bitwardenProduct: 0,
    isAnnual: true,
    canBeUsedByBusiness: true,
    hasSelfHost: true,
    hasSso: true,
    hasPolicies: true,
    hasGroups: true,
    hasDirectory: true,
    hasEvents: true,
    hasResetPassword: true,
    hasScim: true,
    usersGetPremium: true,
    maxUsers: null,
    trialPeriodDays: 0,
    PasswordManager: { type: ENTERPRISE_PLAN_TYPE, seats: null },
    object: 'plan',
  };
  return {
    object: 'list',
    data: [
      enterprise,
      { ...enterprise, product: 1, bitwardenProduct: 1, name: 'Secrets Manager' },
    ],
    continuationToken: null,
  };
}
