import { and, asc, desc, eq, inArray, isNotNull, isNull, ne, or, type SQL } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { chunkRows, getOrm } from '../db/client';
import { ciphers, organizationMemberships } from '../db/schema';
import { bound, jsonExtract, jsonRemove, scalar } from '../db/sql';
import type { Cipher } from '../types';
import { MembershipStatus, MembershipType } from './org-types';
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

// Older clients stored archivedDate / deletedDate inside the cipher blob; only string values are dates.
const legacyDate = (value: unknown): string | null => (typeof value === 'string' ? value : null);

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
      archivedAt: row.archivedAt ?? parsed.archivedAt ?? legacyDate(parsed.archivedDate),
      deletedAt: row.deletedAt ?? parsed.deletedAt ?? legacyDate(parsed.deletedDate),
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
  const data = JSON.stringify(Object.fromEntries(Object.entries(cipher).filter(([key]) => !CIPHER_SCALAR_DATA_KEYS.has(key))));
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
      // An incoming personal cipher binds NULL, which equals nothing either.
      where: or(
        eq(ciphers.userId, cipher.userId),
        and(
          isNotNull(ciphers.organizationId),
          eq(ciphers.organizationId, bound(organizationId)),
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

// Each org item passes to the oldest other confirmed Owner of its org, else to its oldest other confirmed member.
export function reassignOrganizationCiphers(db: D1Database, userId: string, guard: SQL) {
  const orm = getOrm(db);
  const successor = alias(organizationMemberships, 'successor');
  return orm.update(ciphers).set({
    userId: scalar<string>(orm.select({ userId: successor.userId }).from(successor)
      .where(and(eq(successor.orgId, ciphers.organizationId), ne(successor.userId, userId), eq(successor.status, MembershipStatus.Confirmed)))
      .orderBy(desc(eq(successor.type, MembershipType.Owner)), asc(successor.createdAt), asc(successor.id))
      .limit(1)),
  }).where(and(eq(ciphers.userId, userId), isNotNull(ciphers.organizationId), guard));
}

async function chunkedUpdate(
  db: D1Database,
  ids: string[],
  userId: string,
  set: Record<string, unknown>,
  extraWhere: ReturnType<typeof and> | undefined
): Promise<string | null> {
  const uniqueIds = sanitizeIds(ids);
  if (!uniqueIds.length) return null;
  const orm = getOrm(db);
  const update = (chunk: string[]) => orm
    .update(ciphers)
    .set(set)
    .where(and(personalVault(userId), inArray(ciphers.id, chunk), extraWhere));
  // An empty id list renders as `false`, so an empty chunk binds exactly the parameters every chunk adds to its ids.
  for (const chunk of chunkRows(uniqueIds, 1, update([]).toSQL().params.length)) {
    await update(chunk);
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
    {
      deletedAt: now,
      updatedAt: now,
      data: jsonRemove(ciphers.data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate'),
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
    {
      deletedAt: null,
      updatedAt: now,
      data: jsonRemove(ciphers.data, '$.deletedAt', '$.deletedDate', '$.updatedAt', '$.revisionDate'),
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
      isNull(jsonExtract(ciphers.data, '$.deletedAt')),
      isNull(jsonExtract(ciphers.data, '$.deletedDate')),
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
    {
      folderId: normalizeOptionalId(folderId),
      updatedAt: now,
      data: jsonRemove(ciphers.data, '$.folderId', '$.folder_id', '$.updatedAt', '$.revisionDate'),
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
    {
      archivedAt: now,
      updatedAt: now,
      data: jsonRemove(ciphers.data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate'),
    },
    and(
      isNull(ciphers.deletedAt),
      isNull(jsonExtract(ciphers.data, '$.deletedAt')),
      isNull(jsonExtract(ciphers.data, '$.deletedDate')),
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
    {
      archivedAt: null,
      updatedAt: now,
      data: jsonRemove(ciphers.data, '$.archivedAt', '$.archivedDate', '$.updatedAt', '$.revisionDate'),
    },
    undefined
  );
}

export async function countPersonalCiphers(db: D1Database, userId: string): Promise<number> {
  return getOrm(db).$count(ciphers, and(eq(ciphers.userId, userId), isNull(ciphers.organizationId)));
}
