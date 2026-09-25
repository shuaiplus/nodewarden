import { canEditCipher, canViewCipher, hasFullCollectionAccess, isActiveMember } from '../services/org-authz';
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

export type CollectionAssignment = { ok: true } | { ok: false; status: 403 | 404; message: string };

// Upstream Cipher_UpdateCollections links only collections of the target org that the member can
// write. Other ids are rejected here instead of dropped, so a share never lands a cipher in another
// org's collection or one the caller cannot edit.
export async function checkCollectionAssignment(
  env: Env,
  userId: string,
  orgId: string,
  collectionIds: string[]
): Promise<CollectionAssignment> {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member)) return { ok: false, status: 404, message: 'Organization not found' };
  const writable = new Set(hasFullCollectionAccess(member)
    ? (await orgRepo.listCollectionsByOrg(env.DB, orgId)).map((collection) => collection.id)
    : (await orgRepo.listUserCollectionAccess(env.DB, userId, orgId)).filter((access) => !access.readOnly).map((access) => access.collectionId));
  return collectionIds.every((collectionId) => writable.has(collectionId))
    ? { ok: true }
    : { ok: false, status: 403, message: 'Access denied' };
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
