import { LIMITS } from '../config/limits';
import { getOrm, type Orm } from '../db/client';
import { ciphers as cipherTable, folders as folderTable } from '../db/schema';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { StorageService } from '../services/storage';
import { Env, Cipher, Folder, CipherType } from '../types';
import { readActingDeviceIdentifier } from '../utils/device';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { normalizeCipherLoginForStorage, normalizeCipherSshKeyForCompatibility, validateCipherEncryptedFieldsForCompatibility } from './ciphers';

// Bitwarden client import request format
interface CiphersImportRequest {
  ciphers: Array<{
    id?: string | null;
    type: number;
    name?: string | null;
    notes?: string | null;
    favorite?: boolean;
    reprompt?: number;
    sshKey?: any | null;
    bankAccount?: any | null;
    driversLicense?: any | null;
    passport?: any | null;
    key?: string | null;
    login?: {
      uris?: Array<{ uri: string | null; uriChecksum?: string | null; match?: number | null }> | null;
      username?: string | null;
      password?: string | null;
      totp?: string | null;
      autofillOnPageLoad?: boolean | null;
      uri?: string | null;
      passwordRevisionDate?: string | null;
      [key: string]: any;
    } | null;
    card?: {
      cardholderName?: string | null;
      brand?: string | null;
      number?: string | null;
      expMonth?: string | null;
      expYear?: string | null;
      code?: string | null;
    } | null;
    identity?: {
      title?: string | null;
      firstName?: string | null;
      middleName?: string | null;
      lastName?: string | null;
      address1?: string | null;
      address2?: string | null;
      address3?: string | null;
      city?: string | null;
      state?: string | null;
      postalCode?: string | null;
      country?: string | null;
      company?: string | null;
      email?: string | null;
      phone?: string | null;
      ssn?: string | null;
      username?: string | null;
      passportNumber?: string | null;
      licenseNumber?: string | null;
    } | null;
    secureNote?: { type: number } | null;
    fields?: Array<{
      name?: string | null;
      value?: string | null;
      type: number;
      linkedId?: number | null;
    }> | null;
    passwordHistory?: Array<{
      password: string;
      lastUsedDate: string;
    }> | null;
    [key: string]: any;
  }>;
  folders: Array<{
    name: string;
  }>;
  folderRelationships: Array<{
    key: number;   // cipher index
    value: number; // folder index
  }>;
}

function bindNull(v: any): any {
  return v === undefined ? null : v;
}

function readAliasedImportProp<T = unknown>(source: any, aliases: string[]): T | undefined {
  if (!source || typeof source !== 'object') return undefined;
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      return source[key] as T;
    }
  }
  return undefined;
}

function normalizeOptionalId(value: unknown): string | null {
  if (value == null) return null;
  const normalized = String(value).trim();
  return normalized ? normalized : null;
}

async function runOrmBatch(
  orm: Orm,
  statements: Array<{ execute: () => Promise<unknown> }>,
  chunkSize: number
): Promise<void> {
  for (let offset = 0; offset < statements.length; offset += chunkSize) {
    const chunk = statements.slice(offset, offset + chunkSize);
    if (!chunk.length) continue;
    await orm.batch(chunk as unknown as Parameters<Orm['batch']>[0]);
  }
}

// POST /api/ciphers/import - Bitwarden client import endpoint
export async function handleCiphersImport(request: Request, env: Env, userId: string): Promise<Response> {
  const storage = new StorageService(env.DB);
  const url = new URL(request.url);
  const returnCipherMap = url.searchParams.get('returnCipherMap') === '1';

  let importData: CiphersImportRequest;
  try {
    importData = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }

  const folders = Array.isArray(importData.folders) ? importData.folders : [];
  const ciphers = Array.isArray(importData.ciphers) ? importData.ciphers : [];
  const folderRelationships = Array.isArray(importData.folderRelationships) ? importData.folderRelationships : [];

  if (folders.length + ciphers.length > LIMITS.performance.importItemLimit) {
    return errorResponse(`Import exceeds maximum of ${LIMITS.performance.importItemLimit} items`, 400);
  }

  const now = new Date().toISOString();
  const batchChunkSize = LIMITS.performance.bulkMoveChunkSize;

  // Create folders and build index -> id mapping
  const folderIdMap = new Map<number, string>();
  const folderRows: Folder[] = [];
  
  for (let i = 0; i < folders.length; i++) {
    const importedFolder = folders[i] && typeof folders[i] === 'object' ? folders[i] : null;
    const folderId = generateUUID();
    folderIdMap.set(i, folderId);

    const folder: Folder = {
      id: folderId,
      userId: userId,
      name: typeof importedFolder?.name === 'string' && importedFolder.name ? importedFolder.name : 'Folder',
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
        orm.insert(folderTable).values(folder).onConflictDoUpdate({
          target: folderTable.id,
          set: { userId: folder.userId, name: folder.name, updatedAt: folder.updatedAt },
        })
      ),
      batchChunkSize
    );
  }

  // Build cipher index -> folder id mapping from relationships
  const cipherFolderMap = new Map<number, string>();
  for (const rel of folderRelationships) {
    if (!rel || typeof rel !== 'object') continue;
    const folderId = folderIdMap.get(rel.value);
    if (folderId) {
      cipherFolderMap.set(rel.key, folderId);
    }
  }
  const existingFolderIds = new Set((await storage.getAllFolders(userId)).map((folder) => folder.id));

  // Create ciphers
  const cipherRows: Cipher[] = [];
  const cipherMapRows: Array<{ index: number; sourceId: string | null; id: string }> = [];
  for (let i = 0; i < ciphers.length; i++) {
    const c = ciphers[i] && typeof ciphers[i] === 'object' ? ciphers[i] : {} as CiphersImportRequest['ciphers'][number];
    const importedFolderId = normalizeOptionalId(readAliasedImportProp<string | null>(c, ['folderId', 'FolderId']));
    const folderId = cipherFolderMap.get(i) || (importedFolderId && existingFolderIds.has(importedFolderId) ? importedFolderId : null);
    const sourceIdRaw = String(c?.id ?? '').trim();
    const sourceId = sourceIdRaw || null;
    const login = readAliasedImportProp<any | null>(c, ['login', 'Login']);
    const card = readAliasedImportProp<any | null>(c, ['card', 'Card']);
    const identity = readAliasedImportProp<any | null>(c, ['identity', 'Identity']);
    const secureNote = readAliasedImportProp<any | null>(c, ['secureNote', 'SecureNote']);
    const sshKey = readAliasedImportProp<any | null>(c, ['sshKey', 'SshKey']);
    const bankAccount = readAliasedImportProp<any | null>(c, ['bankAccount', 'BankAccount']);
    const driversLicense = readAliasedImportProp<any | null>(c, ['driversLicense', 'DriversLicense']);
    const passport = readAliasedImportProp<any | null>(c, ['passport', 'Passport']);
    const fields = readAliasedImportProp<any[] | null>(c, ['fields', 'Fields']);
    const passwordHistory = readAliasedImportProp<any[] | null>(c, ['passwordHistory', 'PasswordHistory']);
    const key = readAliasedImportProp<string | null>(c, ['key', 'Key']);

    const cipher: Cipher = {
      ...c,
      id: generateUUID(),
      userId: userId,
      type: c.type as CipherType,
      folderId: folderId,
      name: c.name ?? 'Untitled',
      notes: c.notes ?? null,
      favorite: c.favorite ?? false,
      login: login ? {
        ...login,
        username: login.username ?? null,
        password: login.password ?? null,
        uris: login.uris?.map((u: any) => ({
          ...u,
          uri: u.uri ?? null,
          uriChecksum: u.uriChecksum ?? null,
          match: u.match ?? null,
        })) || null,
        totp: login.totp ?? null,
        autofillOnPageLoad: login.autofillOnPageLoad ?? null,
        fido2Credentials: Array.isArray(login.fido2Credentials) ? login.fido2Credentials : null,
        uri: login.uri ?? null,
        passwordRevisionDate: login.passwordRevisionDate ?? null,
      } : null,
      card: card ? {
        ...card,
        cardholderName: card.cardholderName ?? null,
        brand: card.brand ?? null,
        number: card.number ?? null,
        expMonth: card.expMonth ?? null,
        expYear: card.expYear ?? null,
        code: card.code ?? null,
      } : null,
      identity: identity ? {
        ...identity,
        title: identity.title ?? null,
        firstName: identity.firstName ?? null,
        middleName: identity.middleName ?? null,
        lastName: identity.lastName ?? null,
        address1: identity.address1 ?? null,
        address2: identity.address2 ?? null,
        address3: identity.address3 ?? null,
        city: identity.city ?? null,
        state: identity.state ?? null,
        postalCode: identity.postalCode ?? null,
        country: identity.country ?? null,
        company: identity.company ?? null,
        email: identity.email ?? null,
        phone: identity.phone ?? null,
        ssn: identity.ssn ?? null,
        username: identity.username ?? null,
        passportNumber: identity.passportNumber ?? null,
        licenseNumber: identity.licenseNumber ?? null,
      } : null,
      secureNote: secureNote ?? null,
      fields: fields?.map((f: any) => ({
        ...f,
        name: f.name ?? null,
        value: f.value ?? null,
        type: f.type,
        linkedId: f.linkedId ?? null,
      })) || null,
      passwordHistory: passwordHistory ?? null,
      reprompt: c.reprompt ?? 0,
      sshKey: normalizeCipherSshKeyForCompatibility(sshKey ?? null),
      bankAccount: bankAccount ?? null,
      driversLicense: driversLicense ?? null,
      passport: passport ?? null,
      key: key ?? null,
      createdAt: now,
      updatedAt: now,
      archivedAt: null,
      deletedAt: null,
    };
    cipher.login = normalizeCipherLoginForStorage(cipher.login);
    const compatibilityError = validateCipherEncryptedFieldsForCompatibility(cipher);
    if (compatibilityError) {
      return errorResponse(`Cipher ${i + 1}: ${compatibilityError}`, 400);
    }

    cipherRows.push(cipher);
    cipherMapRows.push({ index: i, sourceId, id: cipher.id });
  }

  if (cipherRows.length > 0) {
    const orm = getOrm(env.DB);
    const cipherStatements = cipherRows.map((cipher) => {
      const values = {
        id: cipher.id,
        userId: cipher.userId,
        organizationId: null,
        type: Number(cipher.type) || 1,
        folderId: bindNull(cipher.folderId),
        name: bindNull(cipher.name),
        notes: bindNull(cipher.notes),
        favorite: cipher.favorite ? 1 : 0,
        data: JSON.stringify(cipher),
        reprompt: bindNull(cipher.reprompt ?? 0),
        key: bindNull(cipher.key),
        createdAt: cipher.createdAt,
        updatedAt: cipher.updatedAt,
        archivedAt: bindNull(cipher.archivedAt),
        deletedAt: bindNull(cipher.deletedAt),
      };
      return orm.insert(cipherTable).values(values).onConflictDoUpdate({
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
  const revisionDate = await storage.updateRevisionDate(userId);
  notifyUserVaultSync(env, userId, revisionDate, readActingDeviceIdentifier(request));

  if (returnCipherMap) {
    return jsonResponse({
      object: 'import-result',
      cipherMap: cipherMapRows,
    });
  }

  return new Response(null, { status: 200 });
}
