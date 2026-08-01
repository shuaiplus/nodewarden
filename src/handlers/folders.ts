import { Env, Folder, FolderResponse } from '../types';
import {
  notifyUserFolderCreate,
  notifyUserFolderDelete,
  notifyUserFolderUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { jsonResponse, errorResponse } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { auditRequestMetadata, writeAuditEvent } from '../services/audit-events';

function notifyVaultSyncForRequest(
  request: Request,
  env: Env,
  userId: string,
  revisionDate: string
): void {
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
}

async function writeFolderAudit(
  storage: StorageService,
  request: Request,
  userId: string,
  action: string,
  metadata: Record<string, unknown>
): Promise<void> {
  await writeAuditEvent(storage, {
    actorUserId: userId,
    action,
    category: 'data',
    level: action.includes('delete') ? 'security' : 'info',
    targetType: 'folder',
    targetId: typeof metadata.id === 'string' ? metadata.id : null,
    metadata: {
      ...metadata,
      ...auditRequestMetadata(request),
    },
  });
}

// Convert internal folder to API response format
function folderToResponse(folder: Folder): FolderResponse {
  return {
    id: folder.id,
    name: folder.name,
    revisionDate: folder.updatedAt,
    creationDate: folder.createdAt,
    object: 'folder',
  };
}

// GET /api/folders
export async function handleGetFolders(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let folders: Folder[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await storage.getFoldersPage(userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    folders = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + folders.length) : null;
  } else {
    folders = await storage.getAllFolders(userId);
  }

  return jsonResponse({
    data: folders.map(folderToResponse),
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/folders/:id
export async function handleGetFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  return jsonResponse(folderToResponse(folder));
}

// POST /api/folders
export async function handleCreateFolder(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { name?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (!body.name) {
    return errorResponse('Name is required', 400);
  }

  const now = new Date().toISOString();
  const folder: Folder = {
    id: generateUUID(),
    userId: userId,
    name: body.name,
    createdAt: now,
    updatedAt: now,
  };

  await storage.saveFolder(folder);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyUserFolderCreate(env, {
    userId,
    folderId: folder.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });

  return jsonResponse(folderToResponse(folder), 200);
}

// PUT /api/folders/:id
export async function handleUpdateFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  let body: { name?: string };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  if (body.name) {
    folder.name = body.name;
  }
  folder.updatedAt = new Date().toISOString();

  await storage.saveFolder(folder);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyUserFolderUpdate(env, {
    userId,
    folderId: folder.id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });

  return jsonResponse(folderToResponse(folder));
}

// DELETE /api/folders/:id
export async function handleDeleteFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const folder = await storage.getFolderForUser(id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  await storage.clearFolderFromCiphers(userId, id);
  await storage.deleteFolder(id, userId);
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyVaultSyncForRequest(request, env, userId, revisionDate);
  notifyUserFolderDelete(env, {
    userId,
    folderId: id,
    revisionDate,
    contextId: readActingDeviceIdentifier(request),
  });
  await writeFolderAudit(storage, request, userId, 'folder.delete', {
    id,
  });

  return new Response(null, { status: 204 });
}

// POST /api/folders/delete
export async function handleBulkDeleteFolders(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);

  let body: { ids?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const ids = Array.isArray(body.ids) ? body.ids.map((id) => String(id || '').trim()).filter(Boolean) : [];
  if (!ids.length) {
    return errorResponse('Folder ids are required', 400);
  }

  const folders = (
    await Promise.all(ids.map(async (id) => {
      const folder = await storage.getFolderForUser(id, userId);
      return folder;
    }))
  ).filter((folder): folder is Folder => !!folder);
  const revisionDate = await storage.bulkDeleteFolders(ids, userId);
  if (revisionDate) {
    notifyVaultSyncForRequest(request, env, userId, revisionDate);
    for (const folder of folders) {
      notifyUserFolderDelete(env, {
        userId,
        folderId: folder.id,
        revisionDate,
        contextId: readActingDeviceIdentifier(request),
      });
    }
    await writeFolderAudit(storage, request, userId, 'folder.delete.bulk', {
      count: ids.length,
    });
  }

  return new Response(null, { status: 204 });
}
