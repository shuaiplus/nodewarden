import {
  EMPTY_PERMISSIONS,
  clientMembershipType,
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

// Upstream OrganizationUserValidationService.IsAuthorizedByRole: Owners manage anyone, Admins anyone
// but Owners, and Custom manageUsers members only Users and other Custom members.
function canManageMemberType(actor: MembershipRecord, type: number): boolean {
  if (actor.type === MembershipType.Owner) return true;
  if (actor.type === MembershipType.Admin) return type !== MembershipType.Owner;
  return actor.type === MembershipType.Custom
    && resolvePermissions(actor).manageUsers
    && (type === MembershipType.User || type === MembershipType.Custom);
}

export type RoleChangeCheck = { ok: true } | { ok: false; message: string };

// Upstream words the Owner rejection per route: the v2 UpdateOrganizationUserValidator says
// "manage", while invite still runs OrganizationService.ValidateOrganizationUserUpdatePermissions.
const ONLY_OWNERS_MESSAGES = {
  update: "Only an Owner can manage another Owner's account.",
  invite: "Only an Owner can configure another Owner's account.",
} as const;

// Upstream OrganizationUserValidationService.CanManageRoleChange (v2 UpdateOrganizationUserValidator):
// the actor must manage both the member's current and requested type, so nobody but an Owner can
// grant, edit or demote an Owner, and a Custom actor may only grant permissions it holds itself.
export function memberRoleChangeCheck(
  actor: MembershipRecord,
  currentType: number,
  newType: number,
  newPermissions: OrgPermissions,
  route: keyof typeof ONLY_OWNERS_MESSAGES
): RoleChangeCheck {
  if (!canManageMemberType(actor, currentType) || !canManageMemberType(actor, newType)) {
    const touchesOwner = currentType === MembershipType.Owner || newType === MembershipType.Owner;
    return {
      ok: false,
      message: touchesOwner ? ONLY_OWNERS_MESSAGES[route] : 'Custom users can not manage Admins or Owners.',
    };
  }
  const actorPermissions = resolvePermissions(actor);
  const grantsUnheld = actor.type === MembershipType.Custom
    && newType === MembershipType.Custom
    && (Object.keys(newPermissions) as Array<keyof OrgPermissions>).some((name) => newPermissions[name] && !actorPermissions[name]);
  return grantsUnheld
    ? { ok: false, message: 'Custom users can only grant the same custom permissions that they have.' }
    : { ok: true };
}

// Upstream RemoveOrganizationUserCommand and the v1 Revoke/RestoreOrganizationUserCommand: the same
// role guard as a role change, applied to the member's current type and worded per action.
export function memberRemovalCheck(actor: MembershipRecord, target: MembershipRecord, action: 'remove' | 'revoke' | 'restore'): RoleChangeCheck {
  if (actor.userId && actor.userId === target.userId) return { ok: false, message: `You cannot ${action} yourself.` };
  const targetType = clientMembershipType(target.type);
  if (!canManageMemberType(actor, targetType)) {
    return {
      ok: false,
      message: targetType === MembershipType.Owner ? `Only owners can ${action} other owners.` : `Custom users can not ${action} admins.`,
    };
  }
  const revoked = publicMembershipStatus(target.status) === MembershipStatus.Revoked;
  if (action === 'revoke' && revoked) return { ok: false, message: 'Already revoked.' };
  if (action === 'restore' && !revoked) return { ok: false, message: 'Already active.' };
  return { ok: true };
}

// Upstream restricts self-edits unless admins may access all collection items. NodeWarden applies
// that per actor: Owners and Admins always have the access, so only the other members are restricted.
export function restrictsEditingSelf(actor: MembershipRecord, target: MembershipRecord): boolean {
  return target.userId === actor.userId && !hasFullCollectionAccess(actor);
}

export type MemberCollectionsCheck =
  | { ok: true; collections: CollectionAccess[] }
  | { ok: false; status: number; message: string };

function sameAccess(left: CollectionAccess, right: CollectionAccess | undefined): boolean {
  return !!right && left.readOnly === right.readOnly && left.hidePasswords === right.hidePasswords && left.manage === right.manage;
}

// Upstream OrganizationUsersController.Invite and GetAuthorizedCollectionsToSaveAsync: granting
// access needs ModifyUserAccess on the collection. Owners, Admins and editAnyCollection members hold
// it everywhere, anyone else only where its stored Manage flag is set, own or via a group (upstream
// CanManageCollectionsAsync; legacy "Can edit" does not count): upstream's rule with
// allowAdminAccessToAllCollectionItems off, so manageUsers alone cannot grant direct access to a
// collection it does not manage. Group membership stays unchecked, as upstream. Official web still
// treats that setting as on and offers every collection it shows, so an unchanged entry the actor
// cannot modify is accepted, and the member keeps that access whether re-posted or omitted.
export function memberCollectionsCheck({ actor, actorAccess, requested, current, restrictSelf }: {
  actor: MembershipRecord;
  actorAccess: CollectionAccess[];
  requested: CollectionAccess[];
  current: CollectionAccess[];
  restrictSelf: boolean;
}): MemberCollectionsCheck {
  const currentById = new Map(current.map((access) => [access.collectionId, access]));
  if (restrictSelf && requested.some(({ collectionId }) => !currentById.has(collectionId))) {
    return { ok: false, status: 400, message: 'You cannot add yourself to a collection.' };
  }
  const modifiesAll = hasFullCollectionAccess(actor) || resolvePermissions(actor).editAnyCollection;
  const managed = new Set(actorAccess.filter((access) => access.manage).map(({ collectionId }) => collectionId));
  const canModify = ({ collectionId }: CollectionAccess) => modifiesAll || managed.has(collectionId);
  if (requested.some((access) => !canModify(access) && !sameAccess(access, currentById.get(access.collectionId)))) {
    return { ok: false, status: 404, message: 'Resource not found.' };
  }
  return { ok: true, collections: [...requested.filter(canModify), ...current.filter((access) => !canModify(access))] };
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

export const canAccessSecretsManager = isActiveMember;

export function canCreateCollection(member: MembershipRecord): boolean {
  if (!isActiveMember(member)) return false;
  if (hasFullCollectionAccess(member)) return true;
  if (member.type === MembershipType.Manager) return member.accessAll;
  return resolvePermissions(member).createNewCollections;
}

// The org-wide permissions that let upstream's collection authorization handlers act on a collection
// without managing it: BulkCollectionAuthorizationHandler.CanReadAsync (Read, ReadAccess),
// CanReadWithAccessAsync (ReadWithAccess) and CanUpdateCollectionAsync (Update), and
// CollectionAuthorizationHandler.CanReadAllWithAccessAsync. Owners and Admins hold every permission.
const COLLECTION_OPERATION_PERMISSIONS = {
  readAccess: ['editAnyCollection', 'deleteAnyCollection'],
  readWithAccess: ['editAnyCollection', 'deleteAnyCollection', 'manageUsers'],
  readAllWithAccess: ['editAnyCollection', 'deleteAnyCollection', 'manageUsers', 'manageGroups'],
  update: ['editAnyCollection'],
} as const satisfies Record<string, ReadonlyArray<keyof OrgPermissions>>;

export type CollectionOperation = keyof typeof COLLECTION_OPERATION_PERMISSIONS;

// Anyone else acts only on the collections it manages, by the stored Manage flag, own or via a group,
// as upstream CanManageCollectionsAsync (and memberCollectionsCheck) counts it; "Can edit" does not count.
export function canActOnCollection(member: MembershipRecord, access: CollectionAccess | null, operation: CollectionOperation): boolean {
  const permissions = resolvePermissions(member);
  return isActiveMember(member) && (COLLECTION_OPERATION_PERMISSIONS[operation].some((name) => permissions[name]) || !!access?.manage);
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
  // As upstream UserCollectionDetails, manage is the stored grant alone, the same flag
  // canActOnCollection authorizes by, so a "Can edit" Custom member is never offered Edit collection.
  return {
    ...assigned,
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

export interface CollectionAssignmentPlan {
  insert: string[];
  remove: string[];
}

// Upstream CollectionCipher_UpdateCollections[Admin] (and 1aed7ce03 for EF): a caller adds and drops
// only collections it may write, so assignments it cannot see or edit survive its request.
export function planCollectionAssignment({ current, requested, available }: {
  current: string[];
  requested: string[];
  available: string[];
}): CollectionAssignmentPlan {
  const availableIds = new Set(available);
  const currentIds = new Set(current);
  const requestedIds = new Set(requested);
  return {
    insert: [...requestedIds].filter((collectionId) => availableIds.has(collectionId) && !currentIds.has(collectionId)),
    remove: current.filter((collectionId) => availableIds.has(collectionId) && !requestedIds.has(collectionId)),
  };
}

// A membership transition guard: the row that may move on, or the upstream 400 message.
export type MemberCheck = { ok: true; member: MembershipRecord } | { ok: false; message: string };

// Upstream AcceptOrgUserCommand.AcceptOrgUserByEmailTokenAsync + AcceptOrgUserAsync, in the same
// order, run after the invite token is verified. Only an Invited row may move to Accepted: any
// other status would let a revoked or staged member reinstate themselves.
export function acceptInviteCheck(
  invite: MembershipRecord,
  userEmail: string,
  existingMembership: MembershipRecord | null,
  orgName: string
): MemberCheck {
  if (existingMembership) {
    const message = invite.status === MembershipStatus.Accepted
      ? 'Invitation already accepted. You will receive an email when your organization membership is confirmed.'
      : 'You are already part of this organization.';
    return { ok: false, message };
  }
  if (!invite.email || invite.email.toLowerCase() !== userEmail.toLowerCase()) {
    return { ok: false, message: 'User email does not match invite.' };
  }
  if (publicMembershipStatus(invite.status) === MembershipStatus.Revoked) {
    return { ok: false, message: `Your access to the ${orgName} vault has been revoked.` };
  }
  if (invite.status !== MembershipStatus.Invited) return { ok: false, message: 'Already accepted.' };
  return { ok: true, member: invite };
}

// Upstream ConfirmOrganizationUserCommand only confirms Accepted rows of this org that are bound
// to a user, since the org key is wrapped for that user's public key.
export function confirmMemberCheck(membership: MembershipRecord | null, orgId: string): MemberCheck {
  return membership?.status === MembershipStatus.Accepted && membership.orgId === orgId && membership.userId
    ? { ok: true, member: membership }
    : { ok: false, message: 'User not valid.' };
}
