import { and, eq, inArray, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { attachments, ciphers } from '../db/schema';
import type { Attachment, Cipher } from '../types';

type SafeBind = (stmt: D1PreparedStatement, ...values: unknown[]) => D1PreparedStatement;
type SqlChunkSize = (fixedBindCount: number) => number;
type GetCipher = (id: string) => Promise<Cipher | null>;
type SaveCipher = (cipher: Cipher) => Promise<void>;
type UpdateRevisionDate = (userId: string) => Promise<string>;

function mapAttachment(row: typeof attachments.$inferSelect): Attachment {
  return {
    id: row.id,
    cipherId: row.cipherId,
    fileName: row.fileName,
    size: row.size,
    sizeName: row.sizeName,
    key: row.key,
  };
}

export async function getAttachment(db: D1Database, id: string): Promise<Attachment | null> {
  const [row] = await getOrm(db).select().from(attachments).where(eq(attachments.id, id)).limit(1);
  return row ? mapAttachment(row) : null;
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
    .where(and(eq(attachments.id, id), eq(ciphers.userId, userId)))
    .limit(1);
  return row ? mapAttachment(row) : null;
}

export async function saveAttachment(db: D1Database, _safeBind: SafeBind, attachment: Attachment): Promise<void> {
  await getOrm(db)
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
      where: sql`EXISTS (
        SELECT 1 FROM ciphers current_cipher
        INNER JOIN ciphers next_cipher ON next_cipher.id = excluded.cipher_id
        WHERE current_cipher.id = ${attachments.cipherId}
          AND current_cipher.user_id = next_cipher.user_id
      )`,
    });
}

export async function deleteAttachment(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(attachments).where(eq(attachments.id, id));
}

export async function deleteAttachmentForUser(db: D1Database, id: string, userId: string): Promise<void> {
  await getOrm(db)
    .delete(attachments)
    .where(and(
      eq(attachments.id, id),
      sql`EXISTS (
        SELECT 1 FROM ciphers c
        WHERE c.id = ${attachments.cipherId} AND c.user_id = ${userId}
      )`,
    ));
}

export async function bulkDeleteAttachmentsByIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  attachmentIds: string[]
): Promise<void> {
  const uniqueIds = [...new Set(attachmentIds.map((id) => String(id || '').trim()).filter(Boolean))];
  if (!uniqueIds.length) return;
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(0);

  for (let offset = 0; offset < uniqueIds.length; offset += chunkSize) {
    const chunk = uniqueIds.slice(offset, offset + chunkSize);
    await orm.delete(attachments).where(inArray(attachments.id, chunk));
  }
}

export async function getAttachmentsByCipher(db: D1Database, cipherId: string): Promise<Attachment[]> {
  const rows = await getOrm(db).select().from(attachments).where(eq(attachments.cipherId, cipherId));
  return rows.map(mapAttachment);
}

export async function getAttachmentsByCipherIds(
  db: D1Database,
  sqlChunkSize: SqlChunkSize,
  cipherIds: string[]
): Promise<Map<string, Attachment[]>> {
  const grouped = new Map<string, Attachment[]>();
  const uniqueCipherIds = [...new Set(cipherIds)];
  if (!uniqueCipherIds.length) return grouped;
  const orm = getOrm(db);
  const chunkSize = sqlChunkSize(0);

  for (let offset = 0; offset < uniqueCipherIds.length; offset += chunkSize) {
    const chunk = uniqueCipherIds.slice(offset, offset + chunkSize);
    const rows = await orm.select().from(attachments).where(inArray(attachments.cipherId, chunk));
    for (const item of rows.map(mapAttachment)) {
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
    .where(eq(ciphers.userId, userId));

  for (const item of rows.map(mapAttachment)) {
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
  await getOrm(db)
    .update(attachments)
    .set({ cipherId })
    .where(and(
      eq(attachments.id, attachmentId),
      sql`EXISTS (
        SELECT 1 FROM ciphers target_cipher
        WHERE target_cipher.id = ${cipherId} AND target_cipher.user_id = ${userId}
      )`,
      sql`EXISTS (
        SELECT 1 FROM ciphers current_cipher
        WHERE current_cipher.id = ${attachments.cipherId} AND current_cipher.user_id = ${userId}
      )`,
    ));
}

export async function deleteAllAttachmentsByCipher(db: D1Database, cipherId: string): Promise<void> {
  await getOrm(db).delete(attachments).where(eq(attachments.cipherId, cipherId));
}

export async function updateCipherRevisionDate(
  getCipherById: GetCipher,
  saveCipherRecord: SaveCipher,
  updateRevisionDate: UpdateRevisionDate,
  cipherId: string
): Promise<{ userId: string; revisionDate: string } | null> {
  const cipher = await getCipherById(cipherId);
  if (!cipher) return null;
  cipher.updatedAt = new Date().toISOString();
  await saveCipherRecord(cipher);
  const revisionDate = await updateRevisionDate(cipher.userId);
  return { userId: cipher.userId, revisionDate };
}
