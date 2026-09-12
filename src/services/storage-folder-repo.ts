import type { Folder } from '../types';

function mapFolderRow(row: any): Folder {
  return {
    id: row.id,
    userId: row.user_id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export async function getFolder(db: D1Database, id: string): Promise<Folder | null> {
  const row = await db
    .prepare('SELECT id, user_id, name, created_at, updated_at FROM folders WHERE id = ?')
    .bind(id)
    .first<any>();
  if (!row) return null;
  return mapFolderRow(row);
}

export async function getFolderForUser(db: D1Database, id: string, userId: string): Promise<Folder | null> {
  const row = await db
    .prepare('SELECT id, user_id, name, created_at, updated_at FROM folders WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .first<any>();
  if (!row) return null;
  return mapFolderRow(row);
}

export async function saveFolder(db: D1Database, folder: Folder): Promise<void> {
  await db
    .prepare(
      'INSERT INTO folders(id, user_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at WHERE user_id=excluded.user_id'
    )
    .bind(folder.id, folder.userId, folder.name, folder.createdAt, folder.updatedAt)
    .run();
}

export async function deleteFolder(db: D1Database, id: string, userId: string): Promise<void> {
  await db.prepare('DELETE FROM folders WHERE id = ? AND user_id = ?').bind(id, userId).run();
}

export async function clearFolderFromCiphers(
  db: D1Database,
  userId: string,
  folderId: string
): Promise<void> {
  const now = new Date().toISOString();
  await db
    .prepare(
      `UPDATE ciphers
       SET folder_id = NULL, updated_at = ?,
           data = json_remove(data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate')
       WHERE user_id = ?
         AND (
           folder_id = ?
           OR json_extract(data, '$.folderId') = ?
           OR json_extract(data, '$.folder_id') = ?
         )`
    )
    .bind(now, userId, folderId, folderId, folderId)
    .run();
}

export async function getAllFolders(db: D1Database, userId: string): Promise<Folder[]> {
  const res = await db
    .prepare('SELECT id, user_id, name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC')
    .bind(userId)
    .all<any>();
  return (res.results || []).map((row) => mapFolderRow(row));
}

export async function getFoldersPage(db: D1Database, userId: string, limit: number, offset: number): Promise<Folder[]> {
  const res = await db
    .prepare(
      'SELECT id, user_id, name, created_at, updated_at FROM folders WHERE user_id = ? ORDER BY updated_at DESC LIMIT ? OFFSET ?'
    )
    .bind(userId, limit, offset)
    .all<any>();
  return (res.results || []).map((row) => mapFolderRow(row));
}
