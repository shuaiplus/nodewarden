import { asc, eq, sql } from 'drizzle-orm';

import { BASELINE_MIGRATION_SQL } from './baseline';
import { getOrm } from './client';
import { users } from './schema';
import { ensurePushInstallationCredentials } from '../services/push-relay';
import { getConfigValue, setConfigValue } from '../services/storage-config-repo';

export function schemaStatements(sql: string = BASELINE_MIGRATION_SQL): string[] {
  return sql
    .split('--> statement-breakpoint')
    .map((statement) => statement.trim())
    .filter(Boolean)
    .map(makeIdempotent);
}

function makeIdempotent(statement: string): string {
  if (/^CREATE TABLE IF NOT EXISTS /i.test(statement)) return statement;
  if (/^CREATE UNIQUE INDEX IF NOT EXISTS /i.test(statement)) return statement;
  if (/^CREATE INDEX IF NOT EXISTS /i.test(statement)) return statement;
  if (/^CREATE TABLE /i.test(statement)) {
    return statement.replace(/^CREATE TABLE /i, 'CREATE TABLE IF NOT EXISTS ');
  }
  if (/^CREATE UNIQUE INDEX /i.test(statement)) {
    return statement.replace(/^CREATE UNIQUE INDEX /i, 'CREATE UNIQUE INDEX IF NOT EXISTS ');
  }
  if (/^CREATE INDEX /i.test(statement)) {
    return statement.replace(/^CREATE INDEX /i, 'CREATE INDEX IF NOT EXISTS ');
  }
  return statement;
}

async function executeSchemaStatement(db: D1Database, statement: string): Promise<void> {
  try {
    await db.prepare(statement).run();
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (message.includes('already exists') || message.includes('duplicate column name')) {
      return;
    }
    throw error;
  }
}

async function ensureAdminUserExists(db: D1Database): Promise<void> {
  const orm = getOrm(db);
  const [admin] = await orm.select({ id: users.id }).from(users).where(eq(users.role, 'admin')).limit(1);
  if (admin) return;

  const [firstUser] = await orm
    .select({ id: users.id })
    .from(users)
    .orderBy(asc(users.createdAt))
    .limit(1);
  if (!firstUser) return;

  await orm
    .update(users)
    .set({ role: 'admin', updatedAt: new Date().toISOString() })
    .where(eq(users.id, firstUser.id));
}

export async function ensureStorageSchema(db: D1Database): Promise<void> {
  await db.prepare('PRAGMA foreign_keys = ON').run();
  await db.prepare('CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
  for (const statement of schemaStatements()) {
    await executeSchemaStatement(db, statement);
  }
  await ensureAdminUserExists(db);
}

const STORAGE_SCHEMA_VERSION_KEY = 'schema.version';
// Bump this whenever src/db/schema.ts changes or a migration is added (data-only --custom ones too).
// Existing D1 installs rerun ensureStorageSchema() only when this differs from config.schema.version.
export const STORAGE_SCHEMA_VERSION = '2026-09-27-drop-two-factor';
const REQUIRED_SCHEMA_TABLES = [
  'events',
  'webauthn_credentials',
  'webauthn_challenges',
  'auth_requests',
  'totp_login_replays',
  'organizations',
  'organization_memberships',
  'collections',
  'sm_secrets',
  'emergency_access',
] as const;
let schemaVerified = false;

async function hasRequiredSchemaTables(db: D1Database): Promise<boolean> {
  const rows = await getOrm(db).all(sql`
    SELECT name FROM sqlite_master
    WHERE type = 'table' AND name IN (${sql.join(REQUIRED_SCHEMA_TABLES.map((name) => sql`${name}`), sql`, `)})
  `) as Array<{ name: string }>;
  const found = new Set(rows.map((row) => row.name));
  return REQUIRED_SCHEMA_TABLES.every((table) => found.has(table));
}

// Runs once per isolate: replays the idempotent schema when the recorded version differs or a
// required table is missing, then makes sure push credentials exist.
export async function initializeDatabase(db: D1Database): Promise<void> {
  if (schemaVerified) return;
  await getOrm(db).run(sql`CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
  const schemaVersion = await getConfigValue(db, STORAGE_SCHEMA_VERSION_KEY);
  if (schemaVersion !== STORAGE_SCHEMA_VERSION || !(await hasRequiredSchemaTables(db))) {
    await ensureStorageSchema(db);
    await setConfigValue(db, STORAGE_SCHEMA_VERSION_KEY, STORAGE_SCHEMA_VERSION);
  }
  await ensurePushInstallationCredentials(db);
  schemaVerified = true;
}
