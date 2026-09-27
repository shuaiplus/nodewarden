import { and, desc, eq, inArray, isNotNull, isNull, or, sql, type SQL } from 'drizzle-orm';

import { chunkRows, getOrm } from '../db/client';
import { ciphers } from '../db/schema';
import type { Cipher } from '../types';
import { updateRevisionDate } from './storage-revision-repo';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}


const CIPHER_SCALAR_DATA_KEYS = new Set([
  'id',
  'userId',
  'user_id',
  'type',
  'folderId',
  'folder_id',
  'name',
  'notes',
  'favorite',
  'reprompt',
  'key',
  'attachments',
  'Attachments',
  'attachments2',
  'Attachments2',
  'createdAt',
  'created_at',
  'creationDate',
  'updatedAt',
  'updated_at',
  'revisionDate',
  'archivedAt',
  'archived_at',
  'archivedDate',
  'deletedAt',
  'deleted_at',
  'deletedDate',
]);

function buildCipherData(cipher: Cipher, folderId: string | null): string {
  const payload: Record<string, unknown> = {
    ...cipher,
    folderId,
  };
  for (const key of CIPHER_SCALAR_DATA_KEYS) {
    delete payload[key];
  }
  return JSON.stringify(payload);
}

function parseCipherRow(row: typeof ciphers.$inferSelect | null | undefined): Cipher | null {
  if (!row?.data) return null;
  try {
    const parsed = JSON.parse(row.data) as Cipher;
    const folderId = normalizeOptionalId(row.folderId ?? parsed.folderId ?? null);
    return {
      ...parsed,
      id: row.id,
      userId: row.userId,
      organizationId: normalizeOptionalId(row.organizationId ?? parsed.organizationId ?? null),
      type: Number(row.type) || Number(parsed.type) || 1,
      folderId,
      name: row.name ?? parsed.name ?? null,
      notes: row.notes ?? parsed.notes ?? null,
      favorite: row.favorite != null ? !!row.favorite : !!parsed.favorite,
      reprompt: row.reprompt ?? parsed.reprompt ?? 0,
      key: row.key ?? parsed.key ?? null,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      archivedAt: row.archivedAt ?? parsed.archivedAt ?? parsed.archivedDate ?? null,
      deletedAt: row.deletedAt ?? parsed.deletedAt ?? parsed.deletedDate ?? null,
    };
  } catch {
    console.error('Corrupted cipher data, id:', row.id);
    return null;
  }
}

function sanitizeIds(ids: string[]): string[] {
  return Array.from(new Set(ids.map((id) => String(id || '').trim()).filter(Boolean)));
}

function personalVault(userId: string) {
  return and(eq(ciphers.userId, userId), isNull(ciphers.organizationId));
}

export async function getCipher(db: D1Database, id: string): Promise<Cipher | null> {
  const [row] = await getOrm(db).select().from(ciphers).where(eq(ciphers.id, id)).limit(1);
  return parseCipherRow(row);
}

export async function getCipherForUser(db: D1Database, id: string, userId: string): Promise<Cipher | null> {
  const [row] = await getOrm(db)
    .select()
    .from(ciphers)
    .where(and(eq(ciphers.id, id), personalVault(userId)))
    .limit(1);
  return parseCipherRow(row);
}

// The upsert as an unexecuted statement, so callers can batch it with related writes.
export function cipherUpsert(db: D1Database, cipher: Cipher) {
  const folderId = normalizeOptionalId(cipher.folderId);
  const data = buildCipherData(cipher, folderId);
  const organizationId = normalizeOptionalId(cipher.organizationId ?? null);
  const values = {
    id: cipher.id,
    userId: cipher.userId,
    organizationId,
    type: Number(cipher.type) || 1,
    folderId,
    name: cipher.name,
    notes: cipher.notes,
    favorite: cipher.favorite ? 1 : 0,
    data,
    reprompt: cipher.reprompt ?? 0,
    key: cipher.key,
    createdAt: cipher.createdAt,
    updatedAt: cipher.updatedAt,
    archivedAt: cipher.archivedAt ?? null,
    deletedAt: cipher.deletedAt,
  };
  return getOrm(db)
    .insert(ciphers)
    .values(values)
    .onConflictDoUpdate({
      target: ciphers.id,
      set: {
        organizationId: values.organizationId,
        type: values.type,
        folderId: values.folderId,
        name: values.name,
        notes: values.notes,
        favorite: values.favorite,
        data: values.data,
        reprompt: values.reprompt,
        key: values.key,
        updatedAt: values.updatedAt,
        archivedAt: values.archivedAt,
        deletedAt: values.deletedAt,
      },
      // An org overwrite is only legitimate when the stored row already belongs
      // to that same org; a NULL organization_id must never match an incoming org cipher.
      where: or(
        eq(ciphers.userId, cipher.userId),
        and(
          isNotNull(ciphers.organizationId),
          sql`${ciphers.organizationId} = ${organizationId}`,
        ),
      ),
    });
}

export async function saveCipher(db: D1Database, cipher: Cipher): Promise<void> {
  await cipherUpsert(db, cipher);
}

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  await getOrm(db).delete(ciphers).where(and(eq(ciphers.id, id), personalVault(userId)));
}

export async function deleteCipherById(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(ciphers).where(eq(ciphers.id, id));
}

export function deleteCiphersByOrganization(db: D1Database, organizationId: string) {
  return getOrm(db).delete(ciphers).where(eq(ciphers.organizationId, organizationId));
}

export function reassignOrganizationCiphers(db: D1Database, userId: string, guard: SQL) {
  return getOrm(db).update(ciphers).set({
    userId: sql`(
      SELECT successor.user_id FROM organization_memberships successor
      WHERE successor.org_id = ${ciphers.organizationId}
        AND successor.user_id <> ${userId} AND successor.status = 2
      ORDER BY (successor.type = 0) DESC, successor.created_at, successor.id LIMIT 1
    )`,
  }).where(and(eq(ciphers.userId, userId), isNotNull(ciphers.organizationId), guard));
}

async function chunkedUpdate(
  db: D1Database,
  ids: string[],
  userId: string,
  fixedBinds: number,
  set: Record<string, unknown>,
  extraWhere: ReturnType<typeof and> | undefined
): Promise<string | null> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  for (const chunk of chunkRows(uniqueIds, 1, fixedBinds)) {
    await orm
      .update(ciphers)
      .set(set)
      .where(and(personalVault(userId), inArray(ciphers.id, chunk), extraWhere));
  }
  return updateRevisionDate(db, userId);
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    3,
    {
      deletedAt: now,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined
  );
}

export async function bulkRestoreCiphers(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    2,
    {
      deletedAt: null,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined
  );
}

export async function bulkDeleteCiphers(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<string | null> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  for (const chunk of chunkRows(uniqueIds, 1, 1)) {
    await orm.delete(ciphers).where(and(personalVault(userId), inArray(ciphers.id, chunk)));
  }
  return updateRevisionDate(db, userId);
}

export async function getAllCiphers(db: D1Database, userId: string): Promise<Cipher[]> {
  const rows = await getOrm(db)
    .select()
    .from(ciphers)
    .where(personalVault(userId))
    .orderBy(desc(ciphers.updatedAt));
  return rows.flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersPage(
  db: D1Database,
  userId: string,
  includeDeleted: boolean,
  limit: number,
  offset: number
): Promise<Cipher[]> {
  const deletedFilter = includeDeleted
    ? undefined
    : and(
      isNull(ciphers.deletedAt),
      sql`json_extract(${ciphers.data}, '$.deletedAt') is null`,
      sql`json_extract(${ciphers.data}, '$.deletedDate') is null`,
    );
  const rows = await getOrm(db)
    .select()
    .from(ciphers)
    .where(and(personalVault(userId), deletedFilter))
    .orderBy(desc(ciphers.updatedAt))
    .limit(limit)
    .offset(offset);
  return rows.flatMap((row) => {
    const cipher = parseCipherRow(row);
    return cipher ? [cipher] : [];
  });
}

export async function getCiphersByIds(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return [];
  const orm = getOrm(db);
  const out: Cipher[] = [];
  for (const chunk of chunkRows(uniqueIds, 1, 1)) {
    const rows = await orm
      .select()
      .from(ciphers)
      .where(and(personalVault(userId), inArray(ciphers.id, chunk)));
    out.push(
      ...rows.flatMap((row) => {
        const cipher = parseCipherRow(row);
        return cipher ? [cipher] : [];
      })
    );
  }
  return out;
}

export async function bulkMoveCiphers(
  db: D1Database,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    3,
    {
      folderId: normalizeOptionalId(folderId),
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate')`,
    },
    undefined
  );
}

export async function bulkArchiveCiphers(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    3,
    {
      archivedAt: now,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')`,
    },
    and(
      isNull(ciphers.deletedAt),
      sql`json_extract(${ciphers.data}, '$.deletedAt') is null`,
      sql`json_extract(${ciphers.data}, '$.deletedDate') is null`,
    )
  );
}

export async function bulkUnarchiveCiphers(
  db: D1Database,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    2,
    {
      archivedAt: null,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined
  );
}

export async function countPersonalCiphers(db: D1Database, userId: string): Promise<number> {
  const row = await db.prepare('SELECT count(*) AS total FROM ciphers WHERE user_id=? AND organization_id IS NULL').bind(userId).first<{ total: number }>();
  return row?.total ?? 0;
}
