import { z } from 'zod';
import { Env, Folder, FolderResponse } from '../types';
import {
  notifyUserFolderCreate,
  notifyUserFolderDelete,
  notifyUserFolderUpdate,
  notifyUserVaultSync,
} from '../durable/notifications-hub';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { readActingDeviceIdentifier } from '../utils/device';
import { generateUUID } from '../utils/uuid';
import { parsePagination, encodeContinuationToken } from '../utils/pagination';
import { writeDataAudit } from '../services/audit-events';
import { nonEmptyIdList } from './ciphers';
import * as folderRepo from '../services/storage-folder-repo';
import * as revisionRepo from '../services/storage-revision-repo';

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
  const url = new URL(request.url);
  const pagination = parsePagination(url);

  let folders: Folder[];
  let continuationToken: string | null = null;
  if (pagination) {
    const pageRows = await folderRepo.getFoldersPage(env.DB, userId, pagination.limit + 1, pagination.offset);
    const hasNext = pageRows.length > pagination.limit;
    folders = hasNext ? pageRows.slice(0, pagination.limit) : pageRows;
    continuationToken = hasNext ? encodeContinuationToken(pagination.offset + folders.length) : null;
  } else {
    folders = await folderRepo.getAllFolders(env.DB, userId);
  }

  return jsonResponse({
    data: folders.map(folderToResponse),
    object: 'list',
    continuationToken: continuationToken,
  });
}

// GET /api/folders/:id
export async function handleGetFolder(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const folder = await folderRepo.getFolderForUser(env.DB, id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  return jsonResponse(folderToResponse(folder));
}

// POST /api/folders
export async function handleCreateFolder(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(
    request,
    z.object({
      name: z.string({ error: 'Name is required' }).min(1, { error: 'Name is required' }),
    }),
  );
  if (body instanceof Response) return body;

  const now = new Date().toISOString();
  const folder: Folder = {
    id: generateUUID(),
    userId: userId,
    name: body.name,
    createdAt: now,
    updatedAt: now,
  };

  await folderRepo.saveFolder(env.DB, folder);
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
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
  const folder = await folderRepo.getFolderForUser(env.DB, id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  const body = await parseBody(request, z.object({ name: z.string().nullish() }));
  if (body instanceof Response) return body;

  if (body.name) {
    folder.name = body.name;
  }
  folder.updatedAt = new Date().toISOString();

  await folderRepo.saveFolder(env.DB, folder);
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
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
  const folder = await folderRepo.getFolderForUser(env.DB, id, userId);

  if (!folder || folder.userId !== userId) {
    return errorResponse('Folder not found', 404);
  }

  await folderRepo.clearFolderFromCiphers(env.DB, userId, id);
  await folderRepo.deleteFolder(env.DB, id, userId);
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
  notifyUserFolderDelete(env, { userId, folderId: id, revisionDate, contextId: readActingDeviceIdentifier(request) });
  await writeDataAudit(env.DB, request, userId, 'folder', 'folder.delete', {
    id,
  });

  return new Response(null, { status: 204 });
}

// POST /api/folders/delete
export async function handleBulkDeleteFolders(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await parseBody(request, z.object({ ids: nonEmptyIdList('Folder ids are required') }));
  if (body instanceof Response) return body;
  const { ids } = body;

  const folders = (
    await Promise.all(
      ids.map(async (id) => {
        const folder = await folderRepo.getFolderForUser(env.DB, id, userId);
        return folder;
      }),
    )
  ).filter((folder): folder is Folder => !!folder);
  const revisionDate = await folderRepo.bulkDeleteFolders(env.DB, ids, userId);
  if (revisionDate) {
    notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));
    for (const folder of folders) {
      notifyUserFolderDelete(env, {
        userId,
        folderId: folder.id,
        revisionDate,
        contextId: readActingDeviceIdentifier(request),
      });
    }
    await writeDataAudit(env.DB, request, userId, 'folder', 'folder.delete.bulk', {
      count: ids.length,
    });
  }

  return new Response(null, { status: 204 });
}
