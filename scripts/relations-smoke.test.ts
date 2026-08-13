import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';

import { relations } from '../src/db/relations';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

function applyGeneratedMigrations(sqlite: Database.Database): void {
  const migrationsDir = join(repoRoot, 'migrations');
  const folders = readdirSync(migrationsDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  for (const folder of folders) {
    const sql = readFileSync(join(migrationsDir, folder, 'migration.sql'), 'utf8');
    for (const statement of sql.split('--> statement-breakpoint')) {
      const trimmed = statement.trim();
      if (trimmed) sqlite.exec(trimmed);
    }
  }
}

test('relations v2 through-queries execute against the generated baseline', async () => {
  const sqlite = new Database(':memory:');
  applyGeneratedMigrations(sqlite);
  const db = drizzle({ client: sqlite, relations });

  const rows = await Promise.all([
    db.query.users.findMany({ with: { collections: true } }),
    db.query.ciphers.findMany({ with: { collections: true } }),
    db.query.organizationMemberships.findMany({ with: { groups: true } }),
    db.query.smProjects.findMany({ with: { secrets: true, serviceAccounts: true } }),
    db.query.collections.findMany({ with: { users: true, groups: true, ciphers: true } }),
    db.query.users.findMany({
      with: {
        personalCiphers: true,
        ciphers: true,
        grantedEmergencyAccess: true,
        receivedEmergencyAccess: true,
        createdInvites: true,
        usedInvites: true,
      },
    }),
  ]);

  for (const result of rows) {
    assert.equal(result.length, 0);
  }
});
