import { and, desc, eq, inArray, isNull, or } from 'drizzle-orm';

import { getOrm, statementChunks } from '../db/client';
import { ciphers, folders } from '../db/schema';
import { jsonExtract, jsonRemove } from '../db/sql';
import type { Folder } from '../types';
import { updateRevisionDate } from './storage-revision-repo';

function folderClearedData() {
  return jsonRemove(ciphers.data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate');
}

export async function getFolder(db: D1Database, id: string): Promise<Folder | null> {
  const [row] = await getOrm(db).select().from(folders).where(eq(folders.id, id)).limit(1);
  return row ?? null;
}

export async function getFolderForUser(db: D1Database, id: string, userId: string): Promise<Folder | null> {
  const [row] = await getOrm(db)
    .select()
    .from(folders)
    .where(and(eq(folders.id, id), eq(folders.userId, userId)))
    .limit(1);
  return row ?? null;
}

export async function saveFolder(db: D1Database, folder: Folder): Promise<void> {
  await getOrm(db)
    .insert(folders)
    .values({
      id: folder.id,
      userId: folder.userId,
      name: folder.name,
      createdAt: folder.createdAt,
      updatedAt: folder.updatedAt,
    })
    .onConflictDoUpdate({
      target: folders.id,
      set: { name: folder.name, updatedAt: folder.updatedAt },
      where: eq(folders.userId, folder.userId),
    });
}

export async function deleteFolder(db: D1Database, id: string, userId: string): Promise<void> {
  await getOrm(db).delete(folders).where(and(eq(folders.id, id), eq(folders.userId, userId)));
}

export async function clearFolderFromCiphers(
  db: D1Database,
  userId: string,
  folderId: string
): Promise<void> {
  const now = new Date().toISOString();
  await getOrm(db)
    .update(ciphers)
    .set({ folderId: null, updatedAt: now, data: folderClearedData() })
    .where(and(
      eq(ciphers.userId, userId),
      isNull(ciphers.organizationId),
      or(
        eq(ciphers.folderId, folderId),
        eq(jsonExtract(ciphers.data, '$.folderId'), folderId),
        eq(jsonExtract(ciphers.data, '$.folder_id'), folderId),
      ),
    ));
}

export async function bulkDeleteFolders(db: D1Database, ids: string[], userId: string): Promise<string | null> {
  const uniqueIds = Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return null;

  const orm = getOrm(db);
  const now = new Date().toISOString();
  const unfile = (chunk: string[]) => orm
    .update(ciphers)
    .set({ folderId: null, updatedAt: now, data: folderClearedData() })
    .where(and(
      eq(ciphers.userId, userId),
      isNull(ciphers.organizationId),
      or(
        inArray(ciphers.folderId, chunk),
        inArray(jsonExtract(ciphers.data, '$.folderId'), chunk),
        inArray(jsonExtract(ciphers.data, '$.folder_id'), chunk),
      ),
    ));
  // Chunks are sized for the unfile, which binds more than the folder delete.
  const statements = statementChunks(uniqueIds, unfile).flatMap((chunk) => [
    unfile(chunk),
    orm.delete(folders).where(and(eq(folders.userId, userId), inArray(folders.id, chunk))),
  ]);

  await orm.batch(statements as [typeof statements[0], ...typeof statements]);
  return updateRevisionDate(db, userId);
}

export async function getAllFolders(db: D1Database, userId: string): Promise<Folder[]> {
  const rows = await getOrm(db)
    .select()
    .from(folders)
    .where(eq(folders.userId, userId))
    .orderBy(desc(folders.updatedAt));
  return rows;
}

export async function getFoldersPage(db: D1Database, userId: string, limit: number, offset: number): Promise<Folder[]> {
  const rows = await getOrm(db)
    .select()
    .from(folders)
    .where(eq(folders.userId, userId))
    .orderBy(desc(folders.updatedAt))
    .limit(limit)
    .offset(offset);
  return rows;
}
