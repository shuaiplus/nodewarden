const IMPORT_CREATION_DATE_ALIASES = [
  'creationDate',
  'CreationDate',
  'createdAt',
  'CreatedAt',
  'created_at',
] as const;

const IMPORT_PASSWORD_REVISION_DATE_ALIASES = [
  'passwordRevisionDate',
  'PasswordRevisionDate',
] as const;

const INVALID_PASSWORD_REVISION_DATE = '1970-01-01T00:00:00.000Z';

function readOwnAliasedValue(source: unknown, aliases: readonly string[]): unknown {
  if (!source || typeof source !== 'object' || Array.isArray(source)) return undefined;
  const record = source as Record<string, unknown>;
  for (const key of aliases) {
    if (Object.prototype.hasOwnProperty.call(record, key)) return record[key];
  }
  return undefined;
}

function normalizeOptionalImportDate(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}

export function readImportedCreationDate(source: unknown): unknown {
  return readOwnAliasedValue(source, IMPORT_CREATION_DATE_ALIASES);
}

export function copyImportedCreationDate(
  source: unknown,
  target: Record<string, unknown>
): void {
  const value = readImportedCreationDate(source);
  if (value !== undefined) target.creationDate = value;
}

export function normalizeImportedCreationDate(source: unknown, fallback: string): string {
  return normalizeOptionalImportDate(readImportedCreationDate(source)) ?? fallback;
}

export function readImportedPasswordRevisionDate(source: unknown): unknown {
  const login = readOwnAliasedValue(source, ['login', 'Login']);
  return readOwnAliasedValue(login, IMPORT_PASSWORD_REVISION_DATE_ALIASES);
}

export function copyImportedPasswordRevisionDate(
  source: unknown,
  target: Record<string, unknown>
): void {
  const login = target.login;
  if (!login || typeof login !== 'object' || Array.isArray(login)) return;
  const value = readImportedPasswordRevisionDate(source);
  (login as Record<string, unknown>).passwordRevisionDate = value ?? null;
}

export function normalizeImportedPasswordRevisionDate(login: unknown): string | null {
  const value = readOwnAliasedValue(login, IMPORT_PASSWORD_REVISION_DATE_ALIASES);
  if (value == null) return null;
  if (typeof value !== 'string') return null;
  return normalizeOptionalImportDate(value) ?? INVALID_PASSWORD_REVISION_DATE;
}
