import { and, asc, eq, inArray } from 'drizzle-orm';
import { sqliteTable, text } from 'drizzle-orm/sqlite-core';

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
    // Idempotent CREATEs let every schema version bump replay the whole baseline.
    .map((statement) => {
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
    });
}

// Every raw statement of the bootstrap runs here: migration DDL and PRAGMAs are SQL text by nature.
async function executeSchemaStatement(db: D1Database, statement: string): Promise<void> {
  try {
    // eslint-disable-next-line nodewarden/no-raw-sql -- migration DDL and PRAGMAs have no query-builder form
    await db.prepare(statement).run();
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (message.includes('already exists') || message.includes('duplicate column name')) {
      return;
    }
    throw error;
  }
}

// The config table records the schema version, so it has to exist before the first version check.
const CONFIG_TABLE_SQL = 'CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)';

export async function ensureStorageSchema(db: D1Database): Promise<void> {
  await executeSchemaStatement(db, 'PRAGMA foreign_keys = ON');
  await executeSchemaStatement(db, CONFIG_TABLE_SQL);
  for (const statement of schemaStatements()) {
    await executeSchemaStatement(db, statement);
  }
  // Bootstrap admin: while no account is an admin, the oldest account becomes one.
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

// SQLite's catalog. Declared outside schema.ts so drizzle-kit never generates DDL for it.
export const sqliteMaster = sqliteTable('sqlite_master', {
  type: text('type').notNull(),
  name: text('name').notNull(),
  sql: text('sql'),
});

// Runs once per isolate: replays the idempotent schema when the recorded version differs or a
// required table is missing, then makes sure push credentials exist.
export async function initializeDatabase(db: D1Database): Promise<void> {
  if (schemaVerified) return;
  await executeSchemaStatement(db, CONFIG_TABLE_SQL);
  const schemaVersion = await getConfigValue(db, STORAGE_SCHEMA_VERSION_KEY);
  // The catalog is only read when the recorded version already matches.
  const schemaCurrent = schemaVersion === STORAGE_SCHEMA_VERSION && (await getOrm(db)
    .select({ name: sqliteMaster.name })
    .from(sqliteMaster)
    .where(and(eq(sqliteMaster.type, 'table'), inArray(sqliteMaster.name, REQUIRED_SCHEMA_TABLES)))
    .then((rows) => {
      const found = new Set(rows.map((row) => row.name));
      return REQUIRED_SCHEMA_TABLES.every((table) => found.has(table));
    }));
  if (!schemaCurrent) {
    await ensureStorageSchema(db);
    await setConfigValue(db, STORAGE_SCHEMA_VERSION_KEY, STORAGE_SCHEMA_VERSION);
  }
  await ensurePushInstallationCredentials(db);
  schemaVerified = true;
}
