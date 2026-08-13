import {
  clientMembershipType,
  EMPTY_PERMISSIONS,
  MembershipType,
  publicMembershipStatus,
  type MembershipRecord,
  type OrganizationRecord,
  type PolicyRecord,
} from '../services/org-types';
import { resolvePermissions } from '../services/org-authz';

export function organizationResponse(org: OrganizationRecord, options?: { useSso?: boolean; useScim?: boolean; useSecretsManager?: boolean }) {
  return {
    id: org.id,
    name: org.name,
    seats: null,
    maxCollections: null,
    maxStorageGb: 32767,
    use2fa: true,
    useCustomPermissions: true,
    useDirectory: true,
    useEvents: true,
    useGroups: true,
    useTotp: true,
    usePolicies: true,
    useScim: options?.useScim ?? true,
    useSso: options?.useSso ?? true,
    useKeyConnector: false,
    usePasswordManager: true,
    useSecretsManager: options?.useSecretsManager ?? true,
    selfHost: true,
    useApi: true,
    useDisableSMAdsForUsers: true,
    useInviteLinks: true,
    useMyItems: false,
    useOrganizationDomains: false,
    usePam: false,
    usePhishingBlocker: false,
    hasPublicAndPrivateKeys: !!(org.privateKey && org.publicKey),
    useResetPassword: true,
    allowAdminAccessToAllCollectionItems: true,
    limitCollectionCreation: false,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    businessName: org.name,
    billingEmail: org.billingEmail,
    identifier: org.identifier,
    plan: 'Enterprise (Annually)',
    planType: 20,
    productTierType: 3,
    usersGetPremium: true,
    object: 'organization',
  };
}

export function profileOrganizationResponse(
  org: OrganizationRecord,
  member: MembershipRecord,
  options?: { useSso?: boolean; useScim?: boolean }
) {
  const type = clientMembershipType(member.type);
  const permissions = member.type === MembershipType.Custom
    ? resolvePermissions(member)
    : type === MembershipType.Custom && member.accessAll
      ? { ...EMPTY_PERMISSIONS, createNewCollections: true, editAnyCollection: true, deleteAnyCollection: true }
      : EMPTY_PERMISSIONS;

  return {
    id: org.id,
    identifier: org.identifier,
    name: org.name,
    seats: 20,
    maxCollections: null,
    usersGetPremium: true,
    use2fa: true,
    useDirectory: true,
    useEvents: true,
    useGroups: true,
    useTotp: true,
    useScim: options?.useScim ?? true,
    usePolicies: true,
    useApi: true,
    selfHost: true,
    hasPublicAndPrivateKeys: !!(org.privateKey && org.publicKey),
    resetPasswordEnrolled: !!member.resetPasswordKey,
    useResetPassword: true,
    ssoBound: false,
    useSso: options?.useSso ?? true,
    useKeyConnector: false,
    useSecretsManager: true,
    usePasswordManager: true,
    useCustomPermissions: true,
    useActivateAutofillPolicy: false,
    useAdminSponsoredFamilies: false,
    useRiskInsights: false,
    useDisableSMAdsForUsers: true,
    useInviteLinks: true,
    useMyItems: false,
    useOrganizationDomains: false,
    usePam: false,
    usePhishingBlocker: false,
    organizationUserId: member.id,
    providerId: null,
    providerName: null,
    providerType: null,
    productTierType: 3,
    keyConnectorEnabled: false,
    keyConnectorUrl: null,
    accessSecretsManager: member.type <= MembershipType.Admin,
    limitCollectionCreation: member.type > MembershipType.Manager && !member.accessAll,
    limitCollectionDeletion: true,
    limitItemDeletion: false,
    allowAdminAccessToAllCollectionItems: true,
    userIsManagedByOrganization: false,
    userIsClaimedByOrganization: false,
    permissions,
    maxStorageGb: 32767,
    userId: member.userId,
    key: member.key,
    status: publicMembershipStatus(member.status),
    type,
    enabled: true,
    object: 'profileOrganization',
  };
}

export function policyResponse(policy: PolicyRecord) {
  return {
    id: policy.id,
    organizationId: policy.orgId,
    type: policy.type,
    enabled: policy.enabled,
    data: policy.data,
    object: 'policy',
  };
}
