export const MembershipStatus = {
  Revoked: -1,
  Invited: 0,
  Accepted: 1,
  Confirmed: 2,
  Staged: 3,
} as const;

export const MembershipType = {
  Owner: 0,
  Admin: 1,
  User: 2,
  Manager: 3,
  Custom: 4,
} as const;

export const REVOKE_STATUS_OFFSET = 128;

export const PolicyType = {
  TwoFactorAuthentication: 0,
  MasterPassword: 1,
  PasswordGenerator: 2,
  SingleOrg: 3,
  RequireSso: 4,
  PersonalOwnership: 5,
  DisableSend: 6,
  SendOptions: 7,
  ResetPassword: 8,
} as const;

export interface OrgPermissions {
  accessEventLogs: boolean;
  accessImportExport: boolean;
  accessReports: boolean;
  createNewCollections: boolean;
  editAnyCollection: boolean;
  deleteAnyCollection: boolean;
  manageGroups: boolean;
  managePolicies: boolean;
  manageSso: boolean;
  manageUsers: boolean;
  manageResetPassword: boolean;
  manageScim: boolean;
}

export const EMPTY_PERMISSIONS: OrgPermissions = {
  accessEventLogs: false,
  accessImportExport: false,
  accessReports: false,
  createNewCollections: false,
  editAnyCollection: false,
  deleteAnyCollection: false,
  manageGroups: false,
  managePolicies: false,
  manageSso: false,
  manageUsers: false,
  manageResetPassword: false,
  manageScim: false,
};

export interface OrganizationRecord {
  id: string;
  name: string;
  billingEmail: string;
  identifier: string | null;
  privateKey: string | null;
  publicKey: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface MembershipRecord {
  id: string;
  userId: string | null;
  orgId: string;
  email: string | null;
  invitedByEmail: string | null;
  accessAll: boolean;
  key: string;
  status: number;
  type: number;
  permissions: OrgPermissions | null;
  resetPasswordKey: string | null;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CollectionRecord {
  id: string;
  orgId: string;
  name: string;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CollectionAccess {
  collectionId: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export interface GroupRecord {
  id: string;
  orgId: string;
  name: string;
  accessAll: boolean;
  externalId: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyRecord {
  id: string;
  orgId: string;
  type: number;
  enabled: boolean;
  data: Record<string, unknown>;
  updatedAt: string;
}

export function publicMembershipStatus(status: number): number {
  return status <= MembershipStatus.Revoked ? MembershipStatus.Revoked : status;
}

export function revokeStatus(status: number): number {
  if (status <= MembershipStatus.Revoked) return status;
  return status - REVOKE_STATUS_OFFSET;
}

export function restoreStatus(status: number): number {
  if (status > MembershipStatus.Revoked) return status;
  return status + REVOKE_STATUS_OFFSET;
}

export function clientMembershipType(type: number): number {
  return type === MembershipType.Manager ? MembershipType.Custom : type;
}

export function parsePermissions(raw: string | null | undefined): OrgPermissions | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<OrgPermissions>;
    return { ...EMPTY_PERMISSIONS, ...parsed };
  } catch {
    return null;
  }
}

export function isConfirmedVisible(status: number): boolean {
  return status === MembershipStatus.Confirmed;
}
