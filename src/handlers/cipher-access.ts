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
