import {
  canEditCipher,
  canViewCipher,
  hasFullCollectionAccess,
  isActiveMember,
  planCollectionAssignment,
  resolvePermissions,
  type CollectionAssignmentPlan,
} from '../services/org-authz';
import type { CollectionAccess } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { StorageService } from '../services/storage';
import type { Cipher, Env } from '../types';

export type CipherAccess = 'read' | 'edit';

// Personal rows come from getCipherForUser (organization_id IS NULL). Org
// rows fall through to membership + collection ACL so official clients keep
// using the same /api/ciphers and attachment routes.
export async function loadAccessibleCipher(
  env: Env,
  storage: StorageService,
  userId: string,
  id: string,
  access: CipherAccess
): Promise<Cipher | null> {
  const personal = await storage.getCipherForUser(id, userId);
  if (personal) return personal;

  const candidate = await storage.getCipher(id);
  if (!candidate?.organizationId) return null;

  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, candidate.organizationId);
  if (!isActiveMember(member)) return null;

  const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, candidate.organizationId);
  const collectionIds = await orgRepo.listCipherCollectionIds(env.DB, candidate.id);
  const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
  const allowed = access === 'read'
    ? hasFullCollectionAccess(member) || canViewCipher(member, collectionIds, assignedMap)
    : canEditCipher(member, collectionIds, assignedMap);
  if (!allowed) return null;

  (candidate as { collectionIds?: string[] }).collectionIds = collectionIds;
  return candidate;
}

export type CollectionAssignment = { ok: true } | { ok: false; status: 400 | 404; message: string };

const NO_EDIT_PERMISSION = { ok: false, status: 400, message: 'You do not have permissions to edit this.' } as const;

// Upstream Cipher_UpdateCollections' #AvailableCollections for a member without full collection
// access: its own collections, assigned directly or through a group, minus the readOnly ones.
function writableCollectionIds(accesses: CollectionAccess[]): string[] {
  return accesses.filter((access) => !access.readOnly).map((access) => access.collectionId);
}

// Upstream Cipher_UpdateCollections links only collections of the target org that the member can
// write. Other ids are rejected here instead of dropped, so a create or share never lands a cipher
// in another org's collection or one the caller cannot edit. Only full collection access sees an
// item in no collection, so nobody else may leave one there. The refusal is a 400, not a 403:
// official clients log out on any authenticated 403, and a stale add-item form (a collection just
// made read-only or deleted) must not cost the user the session and the draft.
export async function checkCollectionAssignment(
  env: Env,
  userId: string,
  orgId: string,
  collectionIds: string[]
): Promise<CollectionAssignment> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member)) return { ok: false, status: 404, message: 'Organization not found' };
  const fullAccess = hasFullCollectionAccess(member);
  const writable = new Set(fullAccess
    ? await listOrgCollectionIds(env, orgId)
    : writableCollectionIds(await orgRepo.listUserCollectionAccess(env.DB, userId, orgId)));
  const allowed = collectionIds.length ? collectionIds.every((collectionId) => writable.has(collectionId)) : fullAccess;
  return allowed ? { ok: true } : NO_EDIT_PERMISSION;
}

async function listOrgCollectionIds(env: Env, orgId: string): Promise<string[]> {
  return (await orgRepo.listCollectionsByOrg(env.DB, orgId)).map((collection) => collection.id);
}

// 'member' is PUT /ciphers/{id}/collections_v2, 'admin' is the admin console's /collections-admin.
export type CollectionChangeMode = 'member' | 'admin';

export type CollectionChange =
  | { ok: true; cipher: Cipher; organizationId: string; plan: CollectionAssignmentPlan }
  | { ok: false; status: 400 | 404; message: string };

const CIPHER_NOT_FOUND = { ok: false, status: 404, message: 'Cipher not found' } as const;

// Upstream CiphersController.PutCollections_vNext / PutCollectionsAdmin with CipherService
// .SaveCollectionsAsync. A member needs to see the item's passwords (else 404) and edit it (else
// 400), and changes only its writable collections. An admin (Owner, Admin or editAnyCollection)
// may use any collection of the org, but naming another org's collection is a 404.
export async function planCipherCollectionChange(
  env: Env,
  storage: StorageService,
  userId: string,
  id: string,
  requested: string[],
  mode: CollectionChangeMode
): Promise<CollectionChange> {
  const cipher = await storage.getCipher(id);
  const organizationId = cipher?.organizationId;
  if (!cipher || !organizationId) return CIPHER_NOT_FOUND;
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, organizationId);
  if (!isActiveMember(member)) return CIPHER_NOT_FOUND;
  const current = await orgRepo.listCipherCollectionIds(env.DB, cipher.id);
  const planned = (available: string[]): CollectionChange =>
    ({ ok: true, cipher, organizationId, plan: planCollectionAssignment({ current, requested, available }) });

  if (mode === 'admin') {
    if (!resolvePermissions(member).editAnyCollection) return CIPHER_NOT_FOUND;
    const orgCollectionIds = await listOrgCollectionIds(env, organizationId);
    const orgCollectionIdSet = new Set(orgCollectionIds);
    if (!requested.every((collectionId) => orgCollectionIdSet.has(collectionId))) return CIPHER_NOT_FOUND;
    return planned(orgCollectionIds);
  }
  if (hasFullCollectionAccess(member)) return planned(await listOrgCollectionIds(env, organizationId));

  const accesses = await orgRepo.listUserCollectionAccess(env.DB, userId, organizationId);
  const assigned = new Map(accesses.map((access) => [access.collectionId, access]));
  // Upstream CipherDetails.ViewPassword: some assigned collection holding the item shows passwords.
  if (!current.some((collectionId) => assigned.get(collectionId)?.hidePasswords === false)) return CIPHER_NOT_FOUND;
  if (!canEditCipher(member, current, assigned)) return NO_EDIT_PERMISSION;
  return planned(writableCollectionIds(accesses));
}

export async function deleteAuthorizedCipher(
  storage: StorageService,
  cipher: Cipher,
  userId: string
): Promise<void> {
  if (cipher.organizationId) {
    await storage.deleteCipherById(cipher.id);
    return;
  }
  await storage.deleteCipher(cipher.id, userId);
}

// Upstream separates report/export reads of the whole encrypted vault from single-item admin reads.
export async function canReadOrganizationCiphers(env: Env, userId: string, orgId: string, scope: 'all' | 'admin'): Promise<boolean> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member)) return false;
  const permissions = resolvePermissions(member);
  return scope === 'admin'
    ? permissions.editAnyCollection || permissions.deleteAnyCollection
    : permissions.accessReports || permissions.accessImportExport || permissions.editAnyCollection;
}
