import { Env, SyncResponse, CipherResponse, FolderResponse, ProfileResponse } from '../types';
import { StorageService } from '../services/storage';
import { errorResponse } from '../utils/response';
import { cipherToResponse, isCipherResponseSyncCompatible, shouldPreserveRepairableCipherUris } from './ciphers';
import { sendToResponse } from './sends';
import { LIMITS } from '../config/limits';
import {
  buildUserDecryptionCompat,
  buildUserDecryptionOptions,
} from '../utils/user-decryption';
import { buildDomainsResponse } from '../services/domain-rules';
import { buildWebAuthnPrfOption } from '../utils/account-passkeys';
import { buildProfileResponse } from '../utils/profile-response';

// CONTRACT:
// /api/sync reuses cipherToResponse() as the single cipher response shaper.
// Filtering invalid cipher responses here protects clients from stored rows that
// would otherwise make official apps fail after an HTTP 200 sync.
// Keep this aligned with src/handlers/ciphers.ts when adding new vault fields.
function buildSyncCacheRequest(
  request: Request,
  userId: string,
  revisionDate: string,
  accountPasskeyCacheTag: string,
  excludeDomains: boolean,
  excludeSends: boolean,
  preserveRepairableUris: boolean
): Request {
  const url = new URL(request.url);
  const cacheUrl = new URL(
    `/__nodewarden/cache/sync/${encodeURIComponent(userId)}/${encodeURIComponent(revisionDate)}/${encodeURIComponent(accountPasskeyCacheTag)}/${excludeDomains ? '1' : '0'}/${excludeSends ? '1' : '0'}/${preserveRepairableUris ? '1' : '0'}`,
    url.origin
  );
  return new Request(cacheUrl.toString(), { method: 'GET' });
}

async function readSyncCache(cacheRequest: Request): Promise<Response | null> {
  const hit = await caches.default.match(cacheRequest);
  if (!hit) return null;
  return new Response(hit.body, hit);
}

async function writeSyncCache(cacheRequest: Request, response: Response): Promise<void> {
  await caches.default.put(cacheRequest, response.clone());
}

// GET /api/sync
export async function handleSync(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const excludeDomainsParam = url.searchParams.get('excludeDomains');
  const excludeDomains = excludeDomainsParam !== null && /^(1|true|yes)$/i.test(excludeDomainsParam);
  const excludeSendsParam = url.searchParams.get('excludeSends');
  const excludeSends = excludeSendsParam !== null && /^(1|true|yes)$/i.test(excludeSendsParam);
  const preserveRepairableUris = shouldPreserveRepairableCipherUris(request);

  const user = await storage.getUserById(userId);
  if (!user) {
    return errorResponse('User not found', 404);
  }

  const [revisionDate, accountPasskeys] = await Promise.all([
    storage.getRevisionDate(userId),
    storage.getAccountPasskeyCredentialsByUserId(userId),
  ]);
  const accountPasskeyCacheTag = accountPasskeys
    .map((credential) => [
      credential.id,
      credential.updatedAt,
      credential.supportsPrf ? '1' : '0',
      credential.encryptedUserKey && credential.encryptedPublicKey && credential.encryptedPrivateKey ? '1' : '0',
    ].join(':'))
    .join(',');
  const cacheRequest = buildSyncCacheRequest(request, userId, revisionDate, accountPasskeyCacheTag, excludeDomains, excludeSends, preserveRepairableUris);
  const cachedResponse = await readSyncCache(cacheRequest);
  if (cachedResponse) {
    return cachedResponse;
  }

  const [ciphers, folders, sends, attachmentsByCipher, domainSettings] = await Promise.all([
    storage.getAllCiphers(userId),
    storage.getAllFolders(userId),
    excludeSends ? Promise.resolve([]) : storage.getAllSends(userId),
    storage.getAttachmentsByUserId(userId),
    excludeDomains ? Promise.resolve(null) : storage.getUserDomainSettings(userId),
  ]);
  const webAuthnPrfOptions = accountPasskeys
    .map(buildWebAuthnPrfOption)
    .filter((option): option is NonNullable<typeof option> => !!option);
  const userDecryptionOptions = buildUserDecryptionOptions(user, webAuthnPrfOptions[0] || null);
  const validFolderIds = new Set(folders.map((folder) => folder.id));

  const profile: ProfileResponse = buildProfileResponse(user, env);

  const cipherResponses: CipherResponse[] = [];
  for (const cipher of ciphers) {
    const response = cipherToResponse(cipher, attachmentsByCipher.get(cipher.id) || [], { preserveRepairableUris, validFolderIds });
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
    collections: [],
    ciphers: cipherResponses,
    domains: excludeDomains
      ? null
      : buildDomainsResponse(
          domainSettings?.equivalentDomains || [],
          domainSettings?.customEquivalentDomains || [],
          domainSettings?.excludedGlobalEquivalentDomains || [],
          { omitExcludedGlobals: true }
        ),
    policies: [],
    policiesNew: [],
    sends: sendResponses,
    UserDecryption: {
      MasterPasswordUnlock: userDecryptionOptions.MasterPasswordUnlock,
      TrustedDeviceOption: null,
      KeyConnectorOption: null,
      WebAuthnPrfOption: webAuthnPrfOptions[0] || null,
      WebAuthnPrfOptions: webAuthnPrfOptions,
      V2UpgradeToken: null,
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
  await writeSyncCache(cacheRequest, response);
  return response;
}
