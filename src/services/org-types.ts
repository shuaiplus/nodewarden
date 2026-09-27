import { z } from 'zod';
import type { collections, organizations } from '../db/schema';
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

// A flag that is absent or not a boolean reads as not granted, in request bodies and stored rows alike.
const grant = z.boolean().catch(false);
const permissionFlags = z.object({
  accessEventLogs: grant,
  accessImportExport: grant,
  accessReports: grant,
  createNewCollections: grant,
  editAnyCollection: grant,
  deleteAnyCollection: grant,
  manageGroups: grant,
  managePolicies: grant,
  manageSso: grant,
  manageUsers: grant,
  manageResetPassword: grant,
  manageScim: grant,
});

// Custom-role permissions: unknown keys are dropped and anything other than an object grants nothing.
export const OrgPermissions = permissionFlags.catch(() => permissionFlags.parse({}));
export type OrgPermissions = z.output<typeof OrgPermissions>;

export const EMPTY_PERMISSIONS: OrgPermissions = OrgPermissions.parse({});

// JSON text as a schema input, so stored columns and uploaded files parse through .pipe()/.catch()
// instead of a try/catch around JSON.parse. Unparseable text is an issue, never a throw.
export const jsonText = z.string().transform((text, context): unknown => {
  try {
    return JSON.parse(text);
  } catch {
    context.issues.push({ code: 'custom', message: 'Invalid JSON', input: text });
    return z.NEVER;
  }
});

export type OrganizationRecord = typeof organizations.$inferSelect;

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

export type CollectionRecord = typeof collections.$inferSelect;

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

// A stored row whose JSON does not parse holds no permissions.
export function parsePermissions(raw: string | null | undefined): OrgPermissions | null {
  return jsonText.pipe(OrgPermissions).safeParse(raw).data ?? null;
}

export function isConfirmedVisible(status: number): boolean {
  return status === MembershipStatus.Confirmed;
}
