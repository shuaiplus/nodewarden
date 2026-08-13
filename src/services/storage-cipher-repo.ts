import { and, desc, eq, inArray, isNotNull, isNull, or, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { ciphers } from '../db/schema';
import type { Cipher } from '../types';

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

type SqlChunkSize = (fixedBindCount: number) => number;
type UpdateRevisionDate = (userId: string) => Promise<string>;

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

export async function saveCipher(db: D1Database, cipher: Cipher): Promise<void> {
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
  await getOrm(db)
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

export async function deleteCipher(db: D1Database, id: string, userId: string): Promise<void> {
  await getOrm(db).delete(ciphers).where(and(eq(ciphers.id, id), personalVault(userId)));
}

export async function deleteCipherById(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(ciphers).where(eq(ciphers.id, id));
}

export async function deleteCiphersByOrganization(db: D1Database, organizationId: string): Promise<void> {
  await getOrm(db).delete(ciphers).where(eq(ciphers.organizationId, organizationId));
}

async function chunkedUpdate(
  db: D1Database,
  ids: string[],
  userId: string,
  sqlChunkSize: SqlChunkSize,
  fixedBinds: number,
  set: Record<string, unknown>,
  extraWhere: ReturnType<typeof and> | undefined,
  updateRevisionDate: UpdateRevisionDate
): Promise<string | null> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(fixedBinds);
  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
    await orm
      .update(ciphers)
      .set(set)
      .where(and(personalVault(userId), inArray(ciphers.id, chunk), extraWhere));
  }
  return updateRevisionDate(userId);
}

export async function bulkSoftDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    sqlChunkSize,
    3,
    {
      deletedAt: now,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined,
    updateRevisionDate
  );
}

export async function bulkRestoreCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    sqlChunkSize,
    2,
    {
      deletedAt: null,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined,
    updateRevisionDate
  );
}

export async function bulkDeleteCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(1);
  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
    await orm.delete(ciphers).where(and(personalVault(userId), inArray(ciphers.id, chunk)));
  }
  return updateRevisionDate(userId);
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
  sqlChunkSize: SqlChunkSize,
  ids: string[],
  userId: string
): Promise<Cipher[]> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return [];
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(1);
  const out: Cipher[] = [];
  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
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
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  folderId: string | null,
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    sqlChunkSize,
    3,
    {
      folderId: normalizeOptionalId(folderId),
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate')`,
    },
    undefined,
    updateRevisionDate
  );
}

export async function bulkArchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    sqlChunkSize,
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
    ),
    updateRevisionDate
  );
}

export async function bulkUnarchiveCiphers(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  updateRevisionDate: UpdateRevisionDate,
  ids: string[],
  userId: string
): Promise<string | null> {
  const now = new Date().toISOString();
  return chunkedUpdate(
    db,
    ids,
    userId,
    sqlChunkSize,
    2,
    {
      archivedAt: null,
      updatedAt: now,
      data: sql`json_remove(${ciphers.data}, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate')`,
    },
    undefined,
    updateRevisionDate
  );
}
