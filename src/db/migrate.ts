import { asc, eq } from 'drizzle-orm';

import { BASELINE_MIGRATION_SQL } from './baseline';
import { getOrm } from './client';
import { users } from './schema';

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
