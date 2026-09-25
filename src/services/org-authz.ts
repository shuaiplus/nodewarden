import {
  EMPTY_PERMISSIONS,
  MembershipStatus,
  MembershipType,
  type CollectionAccess,
  type MembershipRecord,
  type OrgPermissions,
  publicMembershipStatus,
} from './org-types';

export interface CollectionPermission extends CollectionAccess {
  canView: boolean;
  canEdit: boolean;
}

export function isActiveMember(member: MembershipRecord | null | undefined): member is MembershipRecord {
  if (!member) return false;
  return publicMembershipStatus(member.status) === MembershipStatus.Confirmed;
}

export function hasFullCollectionAccess(member: MembershipRecord): boolean {
  if (!isActiveMember(member)) return false;
  if (member.accessAll) return true;
  return member.type === MembershipType.Owner || member.type === MembershipType.Admin;
}

export function resolvePermissions(member: MembershipRecord): OrgPermissions {
  if (member.type === MembershipType.Owner || member.type === MembershipType.Admin) {
    return {
      accessEventLogs: true,
      accessImportExport: true,
      accessReports: true,
      createNewCollections: true,
      editAnyCollection: true,
      deleteAnyCollection: true,
      manageGroups: true,
      managePolicies: true,
      manageSso: true,
      manageUsers: true,
      manageResetPassword: true,
      manageScim: true,
    };
  }
  if (member.type === MembershipType.Custom && member.permissions) {
    return { ...EMPTY_PERMISSIONS, ...member.permissions };
  }
  if (member.type === MembershipType.Manager || member.type === MembershipType.Custom) {
    return {
      ...EMPTY_PERMISSIONS,
      createNewCollections: member.accessAll,
      editAnyCollection: member.accessAll,
      deleteAnyCollection: member.accessAll,
    };
  }
  return EMPTY_PERMISSIONS;
}

export function canManageMembers(member: MembershipRecord): boolean {
  return isActiveMember(member) && (
    member.type === MembershipType.Owner
    || member.type === MembershipType.Admin
    || resolvePermissions(member).manageUsers
  );
}

export function canManageGroups(member: MembershipRecord): boolean {
  return isActiveMember(member) && (
    member.type === MembershipType.Owner
    || member.type === MembershipType.Admin
    || resolvePermissions(member).manageGroups
  );
}

export function canManagePolicies(member: MembershipRecord): boolean {
  return isActiveMember(member) && (
    member.type === MembershipType.Owner
    || member.type === MembershipType.Admin
    || resolvePermissions(member).managePolicies
  );
}

export function canManageSso(member: MembershipRecord): boolean {
  return isActiveMember(member) && (
    member.type === MembershipType.Owner
    || member.type === MembershipType.Admin
    || resolvePermissions(member).manageSso
  );
}

export function canManageScim(member: MembershipRecord): boolean {
  return isActiveMember(member) && (
    member.type === MembershipType.Owner
    || member.type === MembershipType.Admin
    || resolvePermissions(member).manageScim
  );
}

export function canAccessSecretsManager(member: MembershipRecord): boolean {
  return isActiveMember(member) && member.type <= MembershipType.Admin;
}

export function canCreateCollection(member: MembershipRecord): boolean {
  if (!isActiveMember(member)) return false;
  if (hasFullCollectionAccess(member)) return true;
  if (member.type === MembershipType.Manager) return member.accessAll;
  return resolvePermissions(member).createNewCollections;
}

export function canDeleteOrganization(member: MembershipRecord): boolean {
  return isActiveMember(member) && member.type === MembershipType.Owner;
}

export function resolveCollectionPermission(
  member: MembershipRecord,
  assigned: CollectionAccess | null
): CollectionPermission {
  if (hasFullCollectionAccess(member)) {
    return {
      collectionId: assigned?.collectionId || '',
      readOnly: false,
      hidePasswords: false,
      manage: member.type !== MembershipType.User,
      canView: true,
      canEdit: true,
    };
  }
  if (!assigned) {
    return {
      collectionId: '',
      readOnly: true,
      hidePasswords: true,
      manage: false,
      canView: false,
      canEdit: false,
    };
  }
  const managerManage = (member.type === MembershipType.Manager || member.type === MembershipType.Custom)
    && (assigned.manage || (!assigned.readOnly && !assigned.hidePasswords));
  return {
    ...assigned,
    manage: assigned.manage || managerManage,
    canView: true,
    canEdit: !assigned.readOnly,
  };
}

export function canViewCipher(
  member: MembershipRecord,
  collectionIds: string[],
  assignedByCollection: Map<string, CollectionAccess>
): boolean {
  if (hasFullCollectionAccess(member)) return true;
  if (collectionIds.length === 0) return false;
  return collectionIds.some((collectionId) => assignedByCollection.has(collectionId));
}

export function canEditCipher(
  member: MembershipRecord,
  collectionIds: string[],
  assignedByCollection: Map<string, CollectionAccess>
): boolean {
  if (hasFullCollectionAccess(member)) return true;
  if (collectionIds.length === 0) return false;
  return collectionIds.some((collectionId) => {
    const assigned = assignedByCollection.get(collectionId);
    return assigned ? !assigned.readOnly : false;
  });
}
