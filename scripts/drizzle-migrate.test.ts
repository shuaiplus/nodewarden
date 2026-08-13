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

test('generated baseline applies twice and yields 40 tables', () => {
  const db = new Database(':memory:');
  const statements = schemaStatements();
  assert.ok(statements.length > 40);
  for (const statement of statements) db.exec(statement);
  for (const statement of statements) db.exec(statement);
  assert.equal(tableNames(db).length, 40);
});
