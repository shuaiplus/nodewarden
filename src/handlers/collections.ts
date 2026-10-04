import { Env, Collection } from '../types';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { bumpOrganizationMembers } from '../utils/org-notify';
import {
  normalizeOptionalId,
  optionalEncString,
  readJsonBody,
  requireOrganizationOwner,
  writeOrgAudit,
} from './organizations';

// CONTRACT:
// Organization collection management: owner-gated CRUD over the org's
// collections plus the member-facing collection list. Wire shapes mirror the
// Bitwarden CollectionResponse/CollectionDetailsResponse the sync endpoint
// and the NodeWarden webapp consume. Access enforcement (readOnly,
// hidePasswords) lives in src/services/storage-collection-repo.ts.

export function collectionToResponse(
  collection: Collection,
  options: { readOnly?: boolean; hidePasswords?: boolean; object?: string } = {}
): Record<string, unknown> {
  return {
    id: collection.id,
    organizationId: collection.organizationId,
    name: collection.name,
    externalId: collection.externalId ?? null,
    ...(options.readOnly !== undefined ? { readOnly: !!options.readOnly } : {}),
    ...(options.hidePasswords !== undefined ? { hidePasswords: !!options.hidePasswords } : {}),
    object: options.object || 'collection',
  };
}


// --- Organization collections (owner management) ---

// POST /api/organizations/:id/collections (owners)
export async function handleCreateOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);
  const name = optionalEncString(body.name);
  if (!name) return errorResponse('name must be an encrypted string', 400);

  const now = new Date().toISOString();
  const collection: Collection = {
    id: generateUUID(),
    organizationId,
    name,
    externalId: normalizeOptionalId(body.externalId),
    creationDate: now,
    revisionDate: now,
  };
  await storage.saveCollection(collection);

  // v2-style create also carries member assignments.
  if (Array.isArray(body.users)) {
    const assignment = await readOrganizationUserAssignmentInput(storage, organizationId, body.users);
    if (assignment instanceof Response) return assignment;
    await storage.replaceCollectionUsers(collection.id, assignment);
  }

  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeOrgAudit(storage, request, userId, 'organization.collection.create', {
    organizationId,
    collectionId: collection.id,
  });

  return jsonResponse(collectionToResponse(collection), 200);
}

async function readOrganizationUserAssignmentInput(
  storage: StorageService,
  organizationId: string,
  value: unknown
): Promise<Array<{ organizationUserId: string; readOnly: boolean; hidePasswords: boolean }> | Response> {
  if (!Array.isArray(value)) return [];
  const out: Array<{ organizationUserId: string; readOnly: boolean; hidePasswords: boolean }> = [];
  for (const item of value) {
    if (!item || typeof item !== 'object') continue;
    const row = item as Record<string, unknown>;
    const organizationUserId = normalizeOptionalId(row.id);
    if (!organizationUserId) continue;
    const organizationUser = await storage.getOrganizationUser(organizationUserId);
    if (!organizationUser || organizationUser.organizationId !== organizationId) {
      return errorResponse(`Organization user ${organizationUserId} does not belong to this organization`, 400);
    }
    out.push({
      organizationUserId,
      readOnly: !!row.readOnly,
      hidePasswords: !!row.hidePasswords,
    });
  }
  return out;
}

// GET /api/organizations/:id/collections (owners)
export async function handleListOrganizationCollections(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const collections = await storage.listCollectionsForOrganization(organizationId);
  return jsonResponse({
    data: collections.map((collection) => collectionToResponse(collection)),
    object: 'list',
    continuationToken: null,
  });
}

// GET /api/organizations/:id/collections/:collectionId/details (owners)
export async function handleGetOrganizationCollectionDetails(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const collection = await storage.getCollection(collectionId);
  if (!collection || collection.organizationId !== organizationId) {
    return errorResponse('Collection not found', 404);
  }

  const collectionUsers = await storage.listCollectionUsers(collectionId);
  return jsonResponse({
    ...collectionToResponse(collection),
    users: collectionUsers.map((row) => ({
      id: row.organizationUserId,
      readOnly: !!row.readOnly,
      hidePasswords: !!row.hidePasswords,
    })),
    groups: [],
    object: 'collectionDetails',
  });
}

// PUT /api/organizations/:id/collections/:collectionId (owners)
// Body: { name, externalId, users: [{id, readOnly, hidePasswords}], groups: [] }
export async function handleUpdateOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  const collection = await storage.getCollection(collectionId);
  if (!collection || collection.organizationId !== organizationId) {
    return errorResponse('Collection not found', 404);
  }

  const body = await readJsonBody(request);
  if (!body) return errorResponse('Invalid JSON', 400);

  const name = optionalEncString(body.name);
  if (name) collection.name = name;
  if (body.externalId !== undefined) collection.externalId = normalizeOptionalId(body.externalId);
  collection.revisionDate = new Date().toISOString();
  await storage.saveCollection(collection);

  if (Array.isArray(body.users)) {
    const assignment = await readOrganizationUserAssignmentInput(storage, organizationId, body.users);
    if (assignment instanceof Response) return assignment;
    await storage.replaceCollectionUsers(collectionId, assignment);
  }

  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeOrgAudit(storage, request, userId, 'organization.collection.update', {
    organizationId,
    collectionId,
  });

  return jsonResponse(collectionToResponse(collection));
}

// DELETE /api/organizations/:id/collections/:collectionId (owners)
export async function handleDeleteOrganizationCollection(
  request: Request,
  env: Env,
  userId: string,
  organizationId: string,
  collectionId: string
): Promise<Response> {
  const storage = new StorageService(env.DB);
  const owner = await requireOrganizationOwner(storage, organizationId, userId);
  if (owner instanceof Response) return owner;

  // Single-statement org-scoped, owner-preconditioned delete: a concurrent
  // demotion or an id collision cannot authorize the wrong delete.
  const deleted = await storage.deleteCollectionForOwner(collectionId, organizationId, userId);
  if (!deleted) {
    return errorResponse('Collection not found', 404);
  }

  await bumpOrganizationMembers(request, env, storage, organizationId);
  await writeOrgAudit(storage, request, userId, 'organization.collection.delete', {
    organizationId,
    collectionId,
  }, 'security');

  return new Response(null, { status: 204 });
}

// GET /api/collections — collections across all confirmed orgs for the user.
export async function handleListMyCollections(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const collections = await storage.listCollectionsForUser(userId);
  return jsonResponse({
    data: collections.map((collection) =>
      collectionToResponse(collection, {
        readOnly: collection.readOnly,
        hidePasswords: collection.hidePasswords,
        object: 'collectionDetails',
      })
    ),
    object: 'list',
    continuationToken: null,
  });
}
