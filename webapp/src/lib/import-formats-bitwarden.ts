import type { CiphersImportPayload } from '@/lib/api/vault';

export interface BitwardenFolderInput {
  id?: string | null;
  name?: string | null;
}

export interface BitwardenUriInput {
  uri?: string | null;
  uriChecksum?: string | null;
  match?: number | null;
}

export interface BitwardenFieldInput {
  name?: string | null;
  value?: string | null;
  type?: number | null;
  linkedId?: number | null;
}

export interface BitwardenCipherInput {
  id?: string | null;
  type?: number | null;
  name?: string | null;
  notes?: string | null;
  favorite?: boolean | null;
  reprompt?: number | null;
  key?: string | null;
  folderId?: string | null;
  login?: {
    uris?: BitwardenUriInput[] | null;
    username?: string | null;
    password?: string | null;
    totp?: string | null;
    fido2Credentials?: Array<Record<string, unknown>> | null;
  } | null;
  card?: Record<string, unknown> | null;
  identity?: Record<string, unknown> | null;
  secureNote?: { type?: number | null } | null;
  fields?: BitwardenFieldInput[] | null;
  passwordHistory?: Array<{ password?: string | null; lastUsedDate?: string | null }> | null;
  sshKey?: Record<string, unknown> | null;
  bankAccount?: Record<string, unknown> | null;
  driversLicense?: Record<string, unknown> | null;
  passport?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface BitwardenJsonInput {
  encrypted?: boolean;
  passwordProtected?: boolean;
  encKeyValidation_DO_NOT_EDIT?: string;
  collections?: Array<{ id?: string | null; name?: string | null }> | null;
  folders?: BitwardenFolderInput[] | null;
  items?: BitwardenCipherInput[] | null;
}

function txt(v: unknown): string {
  if (v === null || v === undefined) return '';
  return String(v).trim();
}

export function normalizeBitwardenImport(raw: unknown): CiphersImportPayload {
  const parsed = raw as BitwardenJsonInput | null;
  if (!parsed || typeof parsed !== 'object') throw new Error('Invalid Bitwarden JSON');
  if (parsed.encrypted === true) throw new Error('Encrypted export requires encrypted import flow.');

  const foldersRaw = Array.isArray(parsed.folders) ? parsed.folders : [];
  const itemsRaw = Array.isArray(parsed.items) ? parsed.items : [];
  const folders: Array<{ name: string }> = [];
  const folderIndexById = new Map<string, number>();
  for (const folder of foldersRaw) {
    const name = txt(folder?.name);
    if (!name) continue;
    const idx = folders.length;
    folders.push({ name });
    const id = txt(folder?.id);
    if (id) folderIndexById.set(id, idx);
  }

  const ciphers: Array<Record<string, unknown>> = [];
  const folderRelationships: Array<{ key: number; value: number }> = [];
  let hasAnyExplicitFolderLink = false;
  for (const item of itemsRaw) {
    ciphers.push({
      ...(item && typeof item === 'object' ? item as Record<string, unknown> : {}),
      id: item?.id ?? null,
      type: Number(item?.type || 1) || 1,
      name: item?.name ?? 'Untitled',
      notes: item?.notes ?? null,
      favorite: !!item?.favorite,
      reprompt: Number(item?.reprompt ?? 0) || 0,
      key: item?.key ?? null,
      login: item?.login
        ? {
            username: item.login.username ?? null,
            password: item.login.password ?? null,
            totp: item.login.totp ?? null,
            fido2Credentials: Array.isArray(item.login.fido2Credentials) ? item.login.fido2Credentials : null,
            uris: Array.isArray(item.login.uris)
              ? item.login.uris.map((u) => ({ ...u, uri: u?.uri ?? null, uriChecksum: u?.uriChecksum ?? null, match: u?.match ?? null }))
              : null,
          }
        : null,
      card: item?.card ?? null,
      identity: item?.identity ?? null,
      secureNote: item?.secureNote ?? null,
      fields: Array.isArray(item?.fields)
        ? item.fields.map((f) => ({
            name: f?.name ?? null,
            value: f?.value ?? null,
            type: Number(f?.type ?? 0) || 0,
            linkedId: f?.linkedId ?? null,
          }))
        : null,
      passwordHistory: Array.isArray(item?.passwordHistory)
        ? item.passwordHistory
            .map((x) => ({ password: x?.password ?? null, lastUsedDate: x?.lastUsedDate ?? null }))
            .filter((x) => !!x.password)
        : null,
      sshKey: item?.sshKey ?? null,
      bankAccount: item?.bankAccount ?? null,
      driversLicense: item?.driversLicense ?? null,
      passport: item?.passport ?? null,
    });
    const folderId = txt(item?.folderId);
    if (!folderId) continue;
    const folderIndex = folderIndexById.get(folderId);
    if (folderIndex !== undefined) {
      hasAnyExplicitFolderLink = true;
      folderRelationships.push({ key: ciphers.length - 1, value: folderIndex });
    }
  }

  if (!hasAnyExplicitFolderLink && folders.length === 1 && ciphers.length > 0) {
    for (let i = 0; i < ciphers.length; i++) {
      folderRelationships.push({ key: i, value: 0 });
    }
  }

  return { ciphers, folders, folderRelationships };
}

export function normalizeBitwardenEncryptedAccountImport(raw: BitwardenJsonInput): CiphersImportPayload {
  const itemsRaw = Array.isArray(raw.items) ? raw.items : [];
  const foldersRaw = Array.isArray(raw.folders) ? raw.folders : [];
  if (!Array.isArray(raw.folders) && Array.isArray(raw.collections)) {
    throw new Error('Encrypted organization export is not supported yet.');
  }

  const folders = foldersRaw.map((f) => ({ name: String(f?.name ?? '') }));
  const folderIndexByLegacyId = new Map<string, number>();
  for (let i = 0; i < foldersRaw.length; i++) {
    const folderId = txt(foldersRaw[i]?.id);
    if (folderId) folderIndexByLegacyId.set(folderId, i);
  }
  const ciphers = itemsRaw.map((x) => ({ ...(x as Record<string, unknown>) }));
  const folderRelationships: Array<{ key: number; value: number }> = [];
  for (let i = 0; i < itemsRaw.length; i++) {
    const folderId = txt(itemsRaw[i]?.folderId);
    if (!folderId) continue;
    const folderIndex = folderIndexByLegacyId.get(folderId);
    if (folderIndex !== undefined) folderRelationships.push({ key: i, value: folderIndex });
  }
  return { ciphers, folders, folderRelationships };
}
