// Per-user filing of organization ciphers. Shared items are filed into each
// member's own personal folders via this mapping; the cipher row itself never
// carries a personal folder id (personal folders are per-user rows, and folder
// names are user-key encrypted — a filing cannot be shared across members).
//
// FK cascades keep the mapping consistent: deleting a cipher, folder, or user
// removes the affected rows (unfiling).

export interface CipherUserFolder {
  cipherId: string;
  folderId: string;
}

export async function listCipherUserFolders(db: D1Database, userId: string): Promise<CipherUserFolder[]> {
  const result = await db
    .prepare('SELECT cipher_id, folder_id FROM cipher_user_folders WHERE user_id = ?')
    .bind(userId)
    .all<any>();
  return (result.results || []).map((row) => ({
    cipherId: row.cipher_id,
    folderId: row.folder_id,
  }));
}

export async function getCipherUserFolder(db: D1Database, userId: string, cipherId: string): Promise<string | null> {
  const row = await db
    .prepare('SELECT folder_id FROM cipher_user_folders WHERE user_id = ? AND cipher_id = ?')
    .bind(userId, cipherId)
    .first<{ folder_id: string }>();
  return row?.folder_id ?? null;
}

// A null folderId unfiles the cipher for the user.
export async function setCipherUserFolder(
  db: D1Database,
  userId: string,
  cipherId: string,
  folderId: string | null
): Promise<void> {
  if (!folderId) {
    await db
      .prepare('DELETE FROM cipher_user_folders WHERE user_id = ? AND cipher_id = ?')
      .bind(userId, cipherId)
      .run();
    return;
  }
  const now = new Date().toISOString();
  await db
    .prepare(
      'INSERT INTO cipher_user_folders(cipher_id, user_id, folder_id, created_at, updated_at) ' +
      'VALUES(?, ?, ?, ?, ?) ' +
      'ON CONFLICT(cipher_id, user_id) DO UPDATE SET folder_id=excluded.folder_id, updated_at=excluded.updated_at'
    )
    .bind(cipherId, userId, folderId, now, now)
    .run();
}

// Bulk move-to-folder for organization ciphers. The folder must already have
// been verified as owned by the acting user; every cipher in ids must have
// been access-checked by the caller.
export async function bulkSetCipherUserFolders(
  db: D1Database,
  maxChunkSize: number,
  userId: string,
  cipherIds: string[],
  folderId: string | null
): Promise<void> {
  if (!cipherIds.length) return;
  const uniqueIds = Array.from(new Set(cipherIds.map((id) => String(id || '').trim()).filter(Boolean)));
  if (!uniqueIds.length) return;
  const chunkSize = Math.max(1, maxChunkSize);
  for (let i = 0; i < uniqueIds.length; i += chunkSize) {
    const chunk = uniqueIds.slice(i, i + chunkSize);
    if (!folderId) {
      const placeholders = chunk.map(() => '?').join(',');
      await db
        .prepare(`DELETE FROM cipher_user_folders WHERE user_id = ? AND cipher_id IN (${placeholders})`)
        .bind(userId, ...chunk)
        .run();
      continue;
    }
    const now = new Date().toISOString();
    const rows = chunk.flatMap((cipherId) => [cipherId, userId, folderId, now, now]);
    const values = chunk.map(() => '(?, ?, ?, ?, ?)').join(',');
    await db
      .prepare(
        `INSERT INTO cipher_user_folders(cipher_id, user_id, folder_id, created_at, updated_at) VALUES ${values} ` +
        'ON CONFLICT(cipher_id, user_id) DO UPDATE SET folder_id=excluded.folder_id, updated_at=excluded.updated_at'
      )
      .bind(...rows)
      .run();
  }
}
