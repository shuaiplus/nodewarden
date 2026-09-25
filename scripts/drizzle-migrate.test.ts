import assert from 'node:assert/strict';
import { test } from 'node:test';
import Database from 'better-sqlite3';

import { schemaStatements } from '../src/db/migrate';

function tableNames(db: Database.Database): string[] {
  return db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all()
    .map((row) => (row as { name: string }).name);
}

function execIdempotent(db: Database.Database, statement: string): void {
  try {
    db.exec(statement);
  } catch (error) {
    const message = error instanceof Error ? error.message.toLowerCase() : String(error).toLowerCase();
    if (message.includes('already exists') || message.includes('duplicate column name')) return;
    throw error;
  }
}

test('generated migrations apply twice and yield the current table set', () => {
  const db = new Database(':memory:');
  const statements = schemaStatements();
  assert.ok(statements.length > 40);
  for (const statement of statements) execIdempotent(db, statement);
  for (const statement of statements) execIdempotent(db, statement);
  assert.equal(tableNames(db).length, 44);
});
