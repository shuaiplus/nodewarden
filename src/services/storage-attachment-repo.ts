import { and, eq, exists, inArray, isNull, type SQLWrapper } from 'drizzle-orm';
import { alias } from 'drizzle-orm/sqlite-core';

import { getOrm, type Orm, statementChunks } from '../db/client';
import { attachments, ciphers } from '../db/schema';
import { excluded } from '../db/sql';
import type { Attachment } from '../types';
import { getCipher, saveCipher } from './storage-cipher-repo';
import { updateRevisionDate } from './storage-revision-repo';

// EXISTS the user's personal (non-organization) cipher with this id: a bound value or a column of the enclosing statement.
function ownsPersonalCipher(orm: Orm, userId: string, cipherId: SQLWrapper | string) {
  const cipher = alias(ciphers, 'owned_cipher');
  return exists(orm.select({ id: cipher.id }).from(cipher)
    .where(and(eq(cipher.id, cipherId), eq(cipher.userId, userId), isNull(cipher.organizationId))));
}

export async function getAttachment(db: D1Database, id: string): Promise<Attachment | null> {
  const [row] = await getOrm(db).select().from(attachments).where(eq(attachments.id, id)).limit(1);
  return row ?? null;
}

export async function getAttachmentForUser(db: D1Database, id: string, userId: string): Promise<Attachment | null> {
  const [row] = await getOrm(db)
    .select({
      id: attachments.id,
      cipherId: attachments.cipherId,
      fileName: attachments.fileName,
      size: attachments.size,
      sizeName: attachments.sizeName,
      key: attachments.key,
    })
    .from(attachments)
    .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId))
    .where(and(eq(attachments.id, id), eq(ciphers.userId, userId), isNull(ciphers.organizationId)))
    .limit(1);
  return row ?? null;
}

// The upsert as an unexecuted statement, so callers can batch it with related writes.
export function attachmentUpsert(db: D1Database, attachment: Attachment) {
  const orm = getOrm(db);
  const currentCipher = alias(ciphers, 'current_cipher');
  const nextCipher = alias(ciphers, 'next_cipher');
  return orm
    .insert(attachments)
    .values({
      id: attachment.id,
      cipherId: attachment.cipherId,
      fileName: attachment.fileName,
      size: attachment.size,
      sizeName: attachment.sizeName,
      key: attachment.key,
    })
    .onConflictDoUpdate({
      target: attachments.id,
      set: {
        cipherId: attachment.cipherId,
        fileName: attachment.fileName,
        size: attachment.size,
        sizeName: attachment.sizeName,
        key: attachment.key,
      },
      // Re-saving an existing id never moves the attachment onto another owner's cipher.
      where: exists(orm.select({ id: currentCipher.id }).from(currentCipher)
        .innerJoin(nextCipher, eq(nextCipher.id, excluded(attachments.cipherId)))
        .where(and(eq(currentCipher.id, attachments.cipherId), eq(currentCipher.userId, nextCipher.userId)))),
    });
}

export async function saveAttachment(db: D1Database, attachment: Attachment): Promise<void> {
  await attachmentUpsert(db, attachment);
}

export async function deleteAttachment(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(attachments).where(eq(attachments.id, id));
}

export async function deleteAttachmentForUser(db: D1Database, id: string, userId: string): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(attachments).where(and(eq(attachments.id, id), ownsPersonalCipher(orm, userId, attachments.cipherId)));
}

export async function bulkDeleteAttachmentsByIds(db: D1Database, attachmentIds: string[]): Promise<void> {
  const uniqueIds = [...new Set(attachmentIds.map((id) => String(id || '').trim()).filter(Boolean))];
  if (!uniqueIds.length) return;
  const orm = getOrm(db);
  const remove = (chunk: string[]) => orm.delete(attachments).where(inArray(attachments.id, chunk));
  for (const chunk of statementChunks(uniqueIds, remove)) {
    await remove(chunk);
  }
}

export async function getAttachmentsByCipher(db: D1Database, cipherId: string): Promise<Attachment[]> {
  const rows = await getOrm(db).select().from(attachments).where(eq(attachments.cipherId, cipherId));
  return rows;
}

export async function getAttachmentsByCipherIds(db: D1Database, cipherIds: string[]): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  const uniqueCipherIds = [...new Set(cipherIds)];
  if (!uniqueCipherIds.length) return grouped;
  const orm = getOrm(db);
  const read = (chunk: string[]) => orm.select().from(attachments).where(inArray(attachments.cipherId, chunk));
  for (const chunk of statementChunks(uniqueCipherIds, read)) {
    const rows = await read(chunk);
    for (const item of rows) {
      const list = grouped.get(item.cipherId);
      if (list) list.push(item);
      else grouped.set(item.cipherId, [item]);
    }
  }

  return grouped;
}

export async function getAttachmentsByUserId(db: D1Database, userId: string): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  const rows = await getOrm(db)
    .select({
      id: attachments.id,
      cipherId: attachments.cipherId,
      fileName: attachments.fileName,
      size: attachments.size,
      sizeName: attachments.sizeName,
      key: attachments.key,
    })
    .from(attachments)
    .innerJoin(ciphers, eq(ciphers.id, attachments.cipherId))
    .where(and(eq(ciphers.userId, userId), isNull(ciphers.organizationId)));

  for (const item of rows) {
    const list = grouped.get(item.cipherId);
    if (list) list.push(item);
    else grouped.set(item.cipherId, [item]);
  }

  return grouped;
}

export async function addAttachmentToCipher(db: D1Database, cipherId: string, attachmentId: string): Promise<void> {
  await getOrm(db).update(attachments).set({ cipherId }).where(eq(attachments.id, attachmentId));
}

export async function addAttachmentToCipherForUser(
  db: D1Database,
  cipherId: string,
  attachmentId: string,
  userId: string
): Promise<void> {
  const orm = getOrm(db);
  await orm
    .update(attachments)
    .set({ cipherId })
    .where(and(
      eq(attachments.id, attachmentId),
      ownsPersonalCipher(orm, userId, cipherId),
      ownsPersonalCipher(orm, userId, attachments.cipherId),
    ));
}

export async function deleteAllAttachmentsByCipher(db: D1Database, cipherId: string): Promise<void> {
  await getOrm(db).delete(attachments).where(eq(attachments.cipherId, cipherId));
}

export async function updateCipherRevisionDate(db: D1Database, cipherId: string): Promise<{ userId: string; revisionDate: string } | null> {
  const cipher = await getCipher(db, cipherId);
  if (!cipher) return null;
  cipher.updatedAt = new Date().toISOString();
  await saveCipher(db, cipher);
  const revisionDate = await updateRevisionDate(db, cipher.userId);
  return { userId: cipher.userId, revisionDate };
}
