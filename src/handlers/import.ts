import { z } from 'zod';
import { LIMITS } from '../config/limits';
import { getOrm, type Orm } from '../db/client';
import { ciphers as cipherTable, folders as folderTable } from '../db/schema';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import type {
  Env,
  Cipher,
  CipherBankAccount,
  CipherDriversLicense,
  CipherPassport,
  Folder,
  PasswordHistory,
} from '../types';
import { readActingDeviceIdentifier } from '../utils/device';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import {
  normalizeCipherLoginForStorage,
  normalizeCipherSshKeyForCompatibility,
  validateCipherEncryptedFieldsForCompatibility,
} from './ciphers';
import * as folderRepo from '../services/storage-folder-repo';
import * as revisionRepo from '../services/storage-revision-repo';

const orNull = <T extends z.ZodType>(schema: T) => schema.nullish().transform((value) => value ?? null);
const list = <T extends z.ZodType>(item: T) =>
  z
    .array(item)
    .nullish()
    .transform((items) => items ?? []);
const encString = orNull(z.string());
const optionalId = z
  .string()
  .nullish()
  .transform((id) => id?.trim() || null);
// Shapes the cipher endpoints own; validateCipherEncryptedFieldsForCompatibility checks their fields.
const clientObject = <T>() => orNull(z.custom<T>((value) => typeof value === 'object'));

// Bitwarden's ImportCiphersRequestModel. parseBody folds PascalCase keys to camelCase; cipher entries
// keep unknown keys so new client fields persist, and absent fields default as the create endpoint's.
const CiphersImportBody = z.object({
  ciphers: list(
    z.looseObject({
      id: optionalId,
      type: z.number(),
      folderId: optionalId,
      name: z
        .string()
        .nullish()
        .transform((name) => name ?? 'Untitled'),
      notes: encString,
      favorite: z
        .boolean()
        .nullish()
        .transform((favorite) => favorite ?? false),
      reprompt: z
        .number()
        .nullish()
        .transform((reprompt) => reprompt ?? 0),
      key: encString,
      login: orNull(
        z.looseObject({
          username: encString,
          password: encString,
          uris: orNull(z.array(z.looseObject({ uri: encString, uriChecksum: encString, match: orNull(z.number()) }))),
          totp: encString,
          autofillOnPageLoad: orNull(z.boolean()),
          uri: encString,
          passwordRevisionDate: encString,
        }),
      ),
      card: orNull(
        z.looseObject({
          cardholderName: encString,
          brand: encString,
          number: encString,
          expMonth: encString,
          expYear: encString,
          code: encString,
        }),
      ),
      identity: orNull(
        z.looseObject({
          title: encString,
          firstName: encString,
          middleName: encString,
          lastName: encString,
          address1: encString,
          address2: encString,
          address3: encString,
          city: encString,
          state: encString,
          postalCode: encString,
          country: encString,
          company: encString,
          email: encString,
          phone: encString,
          ssn: encString,
          username: encString,
          passportNumber: encString,
          licenseNumber: encString,
        }),
      ),
      secureNote: orNull(z.looseObject({ type: z.number() })),
      sshKey: z.unknown().optional(),
      bankAccount: clientObject<CipherBankAccount>(),
      driversLicense: clientObject<CipherDriversLicense>(),
      passport: clientObject<CipherPassport>(),
      fields: orNull(
        z.array(z.looseObject({ name: encString, value: encString, type: z.number(), linkedId: orNull(z.number()) })),
      ),
      passwordHistory: clientObject<PasswordHistory[]>(),
    }),
  ),
  folders: list(z.object({ name: z.string().nullish() })),
  folderRelationships: list(z.object({ key: z.number(), value: z.number() })),
});

async function runOrmBatch(
  orm: Orm,
  statements: Array<{ execute: () => Promise<unknown> }>,
  chunkSize: number,
): Promise<void> {
  for (let offset = 0; offset < statements.length; offset += chunkSize) {
    const chunk = statements.slice(offset, offset + chunkSize);
    if (!chunk.length) continue;
    await orm.batch(chunk as unknown as Parameters<Orm['batch']>[0]);
  }
}

// POST /api/ciphers/import - Bitwarden client import endpoint
export async function handleCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const url = new URL(request.url);
  const returnCipherMap = url.searchParams.get('returnCipherMap') === '1';

  const body = await parseBody(request, CiphersImportBody);
  if (body instanceof Response) return body;
  const { folders, ciphers, folderRelationships } = body;

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];

  for (let i = 0; i < folders.length; i++) {
    const folderId = generateUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: folders[i].name || 'Folder',
      createdAt: now,
      updatedAt: now,
    };

    folderRows.push(folder);
  }

  if (folderRows.length > 0) {
    const orm = getOrm(env.DB);
    await runOrmBatch(
      orm,
      folderRows.map((folder) =>
        orm
          .insert(folderTable)
          .values(folder)
          .onConflictDoUpdate({
            target: folderTable.id,
            set: { userId: folder.userId, name: folder.name, updatedAt: folder.updatedAt },
          }),
      ),
      batchChunkSize,
    );
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }
  const existingFolderIds = new Set((await folderRepo.getAllFolders(env.DB, userId)).map((folder) => folder.id));

  // Create ciphers
  const cipherRows: Cipher[] = [];
  const cipherMapRows: Array<{ index: number; sourceId: string | null; id: string }> = [];
  for (let i = 0; i < ciphers.length; i++) {
    const c = ciphers[i];
    const folderId = cipherFolderMap.get(i) || (c.folderId && existingFolderIds.has(c.folderId) ? c.folderId : null);
    const cipher: Cipher = {
      ...c,
      id: generateUUID(),
      userId: userId,
      folderId: folderId,
      login: normalizeCipherLoginForStorage(c.login),
      sshKey: normalizeCipherSshKeyForCompatibility(c.sshKey ?? null),
      createdAt: now,
      updatedAt: now,
      archivedAt: null,
      deletedAt: null,
    };
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) {
      return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    }

    cipherRows.push(cipher);
    cipherMapRows.push({ index: i, sourceId: c.id, id: cipher.id });
  }

  if (cipherRows.length > 0) {
    const orm = getOrm(env.DB);
    const cipherStatements = cipherRows.map((cipher) => {
      const values = {
        id: cipher.id,
        userId: cipher.userId,
        organizationId: null,
        type: Number(cipher.type) || 1,
        folderId: cipher.folderId,
        name: cipher.name,
        notes: cipher.notes,
        favorite: cipher.favorite ? 1 : 0,
        data: JSON.stringify(cipher),
        reprompt: cipher.reprompt,
        key: cipher.key,
        createdAt: cipher.createdAt,
        updatedAt: cipher.updatedAt,
        archivedAt: cipher.archivedAt,
        deletedAt: cipher.deletedAt,
      };
      return orm
        .insert(cipherTable)
        .values(values)
        .onConflictDoUpdate({
          target: cipherTable.id,
          set: {
            userId: values.userId,
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
        });
    });
    await runOrmBatch(orm, cipherStatements, batchChunkSize);
  }

  // Update revision date
  const revisionDate = await revisionRepo.updateRevisionDate(env.DB, userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));

  if (returnCipherMap) {
    return jsonResponse({
      object: 'import-result',
      cipherMap: cipherMapRows,
    });
  }

  return new Response(null, { status: 200 });
}
