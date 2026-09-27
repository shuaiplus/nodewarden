import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { errorResponse } from '../utils/response';
import { cipherToResponse, isCipherResponseSyncCompatible, shouldPreserveRepairableCipherUris } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import { buildUserDecryptionCompat, buildUserDecryptionOptions } from '../utils/user-decryption';
import { buildDomainsResponse } from '../services/domain-rules';
import { buildWebAuthnPrfOption } from '../utils/account-passkeys';
import { buildProfileResponse } from '../utils/profile-response';
import * as orgRepo from '../services/storage-org-repo';
import { canViewCipher, hasFullCollectionAccess, resolveCollectionPermission } from '../services/org-authz';
import { policyResponse } from '../utils/org-response';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as cipherRepo from '../services/storage-cipher-repo';
import * as domainRulesRepo from '../services/storage-domain-rules-repo';
import * as folderRepo from '../services/storage-folder-repo';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sendRepo from '../services/storage-send-repo';
import * as userRepo from '../services/storage-user-repo';

// CONTRACT:
// /api/sync reuses cipherToResponse() as the single cipher response shaper.
// Filtering invalid cipher responses here protects clients from stored rows that
// would otherwise make official apps fail after an HTTP 200 sync.
// Keep this aligned with src/handlers/ciphers.ts when adding new vault fields.
// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  const excludeSendsParam = url.searchParams.get('excludeSends');
  const excludeSends = excludeSendsParam !== null && /^(1|true|yes)$/i.test(excludeSendsParam);
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);

  // Read the revision before the user row: writers change the row first and bump the
  // revision second, so a body cached under a revision can never predate that revision.
  const [revisionDate, accountPasskeys] = await Promise.all([
    revisionRepo.getRevisionDate(env.DB, userId),
    passkeyRepo.listAccountPasskeyCredentialsByUserId(env.DB, userId),
  ]);
  const accountPasskeyCacheTag = accountPasskeys
    .map((credential) =>
      [
        credential.id,
        credential.updatedAt,
        credential.supportsPrf ? '1' : '0',
        credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey ? '1' : '0',
      ].join(':'),
    )
    .join(',');
  // The cache key carries the revision, the passkey state and every response option.
  const cacheRequest = new Request(
    new URL(
      `/__nodewarden/cache/sync/${encodeURIComponent(userId)}/${encodeURIComponent(revisionDate)}/${encodeURIComponent(accountPasskeyCacheTag)}/${excludeDomains ? '1' : '0'}/${excludeSends ? '1' : '0'}/${preserveRepairableUris ? '1' : '0'}`,
      url.origin,
    ).toString(),
    { method: 'GET' },
  );
  const cachedResponse = await caches.default.match(cacheRequest);
  if (cachedResponse) {
    return new Response(cachedResponse.body, cachedResponse);
  }

  const user = await userRepo.getUserById(env.DB, userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const [ciphers, folders, sends, personalAttachments, domainSettings, orgCiphersForAttachments] = await Promise.all([
    cipherRepo.getAllCiphers(env.DB, userId),
    folderRepo.getAllFolders(env.DB, userId),
    excludeSends ? Promise.resolve([]) : sendRepo.getAllSends(env.DB, userId),
    attachmentRepo.getAttachmentsByUserId(env.DB, userId),
    excludeDomains ? Promise.resolve(null) : domainRulesRepo.getUserDomainSettings(env.DB, userId),
    orgRepo.listAccessibleOrgCiphers(env.DB, userId),
  ]);
  const attachmentsByCipher = new Map(personalAttachments);
  const extraAttachmentMap = await attachmentRepo.getAttachmentsByCipherIds(
    env.DB,
    orgCiphersForAttachments.map((cipher) => cipher.id),
  );
  for (const [cipherId, attachments] of extraAttachmentMap.entries()) {
    attachmentsByCipher.set(cipherId, attachments);
  }
  const webAuthnPrfOptions = accountPasskeys
    .map(buildWebAuthnPrfOption)
    .filter((option): option is NonNullable<typeof option> => !!option);
  const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOptions[0] || null);
  const validFolderIds = new Set(folders.map((folder) => folder.id));

  const profile: ProfileResponse = await buildProfileResponse(user, env);
  const orgCiphers = orgCiphersForAttachments;
  const visibleOrgCiphers = [];
  const collectionDetails = [];
  const policies = await orgRepo.listEnabledPoliciesForUser(env.DB, userId);
  const memberships = await orgRepo.listMembershipsByUser(env.DB, userId);
  for (const member of memberships) {
    if (member.status !== 2) continue;
    const collections = await orgRepo.listCollectionsByOrg(env.DB, member.orgId);
    const assigned = await orgRepo.listUserCollectionAccess(env.DB, userId, member.orgId);
    const assignedMap = new Map(assigned.map((item) => [item.collectionId, item]));
    for (const collection of collections) {
      const permission = resolveCollectionPermission(member, assignedMap.get(collection.id) || null);
      if (!permission.canView && !hasFullCollectionAccess(member)) continue;
      collectionDetails.push({
        id: collection.id,
        organizationId: collection.orgId,
        name: collection.name,
        externalId: collection.externalId,
        type: 0,
        readOnly: permission.readOnly,
        hidePasswords: permission.hidePasswords,
        manage: permission.manage,
        object: 'collectionDetails',
      });
    }
    for (const cipher of orgCiphers.filter((item) => item.organizationId === member.orgId)) {
      // listAccessibleOrgCiphers already scoped these to the member's collections and
      // attached the ids; re-check here so the response layer never widens that scope.
      const collectionIds = (cipher as { collectionIds?: string[] }).collectionIds || [];
      if (!canViewCipher(member, collectionIds, assignedMap)) continue;
      visibleOrgCiphers.push({ ...cipher, collectionIds });
    }
  }

  const cipherResponses: CipherResponse[] = [];
  for (const cipher of [...ciphers, ...visibleOrgCiphers]) {
    const response = cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], {
      preserveRepairableUris,
      validFolderIds,
    });
    if (cipher.organizationId) {
      response.organizationId = cipher.organizationId;
      response.collectionIds = Array.isArray((cipher as { collectionIds?: string[] }).collectionIds)
        ? (cipher as { collectionIds?: string[] }).collectionIds || []
        : [];
      response.userId = null;
    }
    if (isCipherResponseSyncCompatible(response)) {
      cipherResponses.push(response);
    }
  }

  const folderResponses: FolderResponse[] = [];
  for (const folder of folders) {
    folderResponses.push({
      id: folder.id,
      name: folder.name,
      revisionDate: folder.updatedAt,
      creationDate: folder.createdAt,
      object: 'folder',
    });
  }

  const sendResponses = sends.map(sendToResponse);
  const syncResponse: SyncResponse = {
    profile,
    folders: folderResponses,
    collections: collectionDetails,
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : buildDomainsResponse(
          domainSettings?.equivalentDomains || [],
          domainSettings?.customEquivalentDomains || [],
          domainSettings?.excludedGlobalEquivalentDomains || [],
          { omitExcludedGlobals: true },
        ),
    policies: policies.map(policyResponse),
    policiesNew: policies.map(policyResponse),
    sends: sendResponses,
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: webAuthnPrfOptions[0] || null,
      WebAuthnPrfOptions: webAuthnPrfOptions,
      V2UpgradeToken: null,
      UserKeyId: user.userKeyId,
      Object: 'userDecryption',
    },
    UserDecryptionOptions: userDecryptionOptions,
    userDecryption: buildUserDecryptionCompat(user) as SyncResponse['userDecryption'],
    object: 'sync',
  };

  const response = new Response(JSON.stringify(syncResponse), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `private, max-age=${Math.max(1, Math.floor(LIMITS.cache.syncResponseTtlMs / 1000))}`,
    },
  });
  await caches.default.put(cacheRequest, response.clone());
  return response;
}
