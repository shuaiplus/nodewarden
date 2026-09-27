import * as z from 'zod/mini';
import type { CiphersImportPayload } from '@/lib/api/vault';
import { txt } from './import-format-shared';

// Exports come from many client versions and hand edits: every field is optional, malformed values degrade to the
// defaults below instead of failing the whole import, and unknown cipher keys pass through untouched.
const loose = <Output>(convert: (value: unknown) => Output) => z.pipe(z.optional(z.unknown()), z.transform(convert));
const text = loose(txt);
const orNull = loose((value) => value ?? null);
const numberOr = (fallback: number) => loose((value) => Number(value ?? fallback) || fallback);
const objectOrEmpty = loose((value) => (value && typeof value === 'object' && !Array.isArray(value) ? value : {}));
const listOrNull = <Item extends z.ZodMiniType>(item: Item) => z.catch(z.nullable(z.array(item)), null);
const listOrEmpty = <Item extends z.ZodMiniType>(item: Item) => z.catch(z.array(item), []);

const Folder = z.pipe(objectOrEmpty, z.object({ id: text, name: text }));

const Login = z.pipe(objectOrEmpty, z.object({
  username: orNull,
  password: orNull,
  totp: orNull,
  fido2Credentials: listOrNull(z.unknown()),
  uris: listOrNull(z.pipe(objectOrEmpty, z.looseObject({ uri: orNull, uriChecksum: orNull, match: orNull }))),
}));

const Item = z.pipe(objectOrEmpty, z.looseObject({
  id: orNull,
  type: numberOr(1),
  name: loose((value) => value ?? 'Untitled'),
  notes: orNull,
  favorite: loose(Boolean),
  reprompt: numberOr(0),
  key: orNull,
  login: z.pipe(loose((value): unknown => value || null), z.nullable(Login)),
  card: orNull,
  identity: orNull,
  secureNote: orNull,
  fields: listOrNull(z.pipe(objectOrEmpty, z.object({ name: orNull, value: orNull, type: numberOr(0), linkedId: orNull }))),
  passwordHistory: z.pipe(
    listOrNull(z.pipe(objectOrEmpty, z.object({ password: orNull, lastUsedDate: orNull }))),
    z.transform((history) => history?.filter((entry) => !!entry.password) ?? null)
  ),
  sshKey: orNull,
  bankAccount: orNull,
  driversLicense: orNull,
  passport: orNull,
}));

const PlainExport = z.object({
  encrypted: z.optional(z.unknown()),
  folders: listOrEmpty(Folder),
  items: listOrEmpty(Item),
});

// Encrypted ciphers are opaque EncStrings, so only their folder link is read.
const EncryptedAccountExport = z.object({
  folders: listOrNull(Folder),
  collections: z.optional(z.unknown()),
  items: listOrEmpty(z.pipe(objectOrEmpty, z.looseObject({}))),
});

function folderRelationshipsOf(items: Array<Record<string, unknown>>, folderIndexById: Map<string, number>) {
  return items.flatMap((item, key) => {
    const value = folderIndexById.get(txt(item.folderId));
    return value === undefined ? [] : [{ key, value }];
  });
}

function folderIndexByIdOf(folders: Array<{ id: string }>): Map<string, number> {
  return new Map(folders.flatMap((folder, index) => (folder.id ? [[folder.id, index] as const] : [])));
}

export function normalizeBitwardenImport(raw: unknown): CiphersImportPayload {
  const parsed = PlainExport.safeParse(raw);
  if (!parsed.success) throw new Error('Invalid Bitwarden JSON');
  if (parsed.data.encrypted === true) throw new Error('Encrypted export requires encrypted import flow.');

  const { items } = parsed.data;
  const folders = parsed.data.folders.filter((folder) => folder.name);
  const folderRelationships = folderRelationshipsOf(items, folderIndexByIdOf(folders));
  return {
    ciphers: items,
    folders: folders.map(({ name }) => ({ name })),
    // Without any explicit link, a single-folder export means every item belongs to that folder.
    folderRelationships: folderRelationships.length || folders.length !== 1
      ? folderRelationships
      : items.map((_, key) => ({ key, value: 0 })),
  };
}

export function normalizeBitwardenEncryptedAccountImport(raw: unknown): CiphersImportPayload {
  const { folders, collections, items } = EncryptedAccountExport.parse(raw);
  if (!folders && Array.isArray(collections)) {
    throw new Error('Encrypted organization export is not supported yet.');
  }
  return {
    ciphers: items,
    folders: (folders ?? []).map(({ name }) => ({ name })),
    folderRelationships: folderRelationshipsOf(items, folderIndexByIdOf(folders ?? [])),
  };
}
