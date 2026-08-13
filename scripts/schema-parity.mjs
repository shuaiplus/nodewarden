// Schema parity harness: builds the legacy hand-written schema (DB A) and the
// drizzle-kit generated baseline (DB B) in memory and diffs them.
//
// Allowed (non-)differences: index names, foreign-key constraint names,
// physical column order, and `CREATE TABLE IF NOT EXISTS` vs `CREATE TABLE`.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runInNewContext } from 'node:vm';
import Database from 'better-sqlite3';

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

// The legacy bootstrap is a TS module whose statement list is a plain array of
// concatenated string literals. Evaluating that literal in an empty VM context
// (the source is this repo's own tracked file) is simpler and less brittle than
// regex-extracting each concatenated fragment.
function legacyStatements() {
  const source = readFileSync(join(repoRoot, 'src/services/storage-schema.ts'), 'utf8');
  const start = source.indexOf('[', source.indexOf('const SCHEMA_STATEMENTS'));
  const end = source.indexOf('\n];', start);
  if (start < 0 || end < 0) throw new Error('could not locate SCHEMA_STATEMENTS array literal');
  return runInNewContext(source.slice(start, end + 2), Object.create(null));
}

// Tables created outside storage-schema.ts, mirrored verbatim from source.
const AD_HOC_STATEMENTS = [
  'CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
  'CREATE TABLE IF NOT EXISTS rate_limit_buckets (' +
    'bucket_key TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)',
  'CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_expires ON rate_limit_buckets(expires_at)',
  'CREATE UNIQUE INDEX IF NOT EXISTS idx_webauthn_credentials_id ON webauthn_credentials(id)',
];

function buildLegacyDatabase() {
  const db = new Database(':memory:');
  for (const statement of [...legacyStatements(), ...AD_HOC_STATEMENTS]) {
    // ALTER TABLE ADD COLUMN replays are idempotent no-ops on a fresh DB, and
    // the data-backfill UPDATEs touch empty tables; both mirror runtime.
    try {
      db.exec(statement);
    } catch (error) {
      if (!/duplicate column name/i.test(error.message)) throw error;
    }
  }
  return db;
}

function generatedMigrationSql() {
  const outDir = join(repoRoot, 'migrations');
  const folders = readdirSync(outDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  if (folders.length === 0) throw new Error('no generated migrations found');
  return folders
    .map((folder) => join(outDir, folder, 'migration.sql'))
    .filter((path) => existsSync(path))
    .map((path) => readFileSync(path, 'utf8'))
    .join('\n');
}

function buildGeneratedDatabase() {
  const db = new Database(':memory:');
  for (const statement of generatedMigrationSql().split('--> statement-breakpoint')) {
    const trimmed = statement.trim();
    if (trimmed) db.exec(trimmed);
  }
  return db;
}

function tableNames(db) {
  return db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all()
    .map((row) => row.name);
}

// Defaults are compared textually after stripping SQLite's optional quoting so
// that 'user' and "user" and ''user'' all normalise to the same token.
function normalizeDefault(value) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  const quoted = /^'(.*)'$/.exec(text) ?? /^"(.*)"$/.exec(text);
  return quoted ? quoted[1] : text;
}

function columnMap(db, table) {
  const columns = new Map();
  for (const row of db.prepare(`PRAGMA table_info(${JSON.stringify(table)})`).all()) {
    columns.set(row.name, {
      type: String(row.type).toUpperCase(),
      notnull: Boolean(row.notnull),
      dflt: normalizeDefault(row.dflt_value),
      pk: row.pk,
    });
  }
  return columns;
}

function indexSignatures(db, table) {
  const master = new Map(
    db
      .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ?")
      .all(table)
      .map((row) => [row.name, row.sql]),
  );
  return db
    .prepare(`PRAGMA index_list(${JSON.stringify(table)})`)
    .all()
    .map((entry) => {
      const columns = db
        .prepare(`PRAGMA index_info(${JSON.stringify(entry.name)})`)
        .all()
        .map((column) => column.name ?? `<expr@${column.seqno}>`);
      const whereMatch = /\sWHERE\s+(.*)$/is.exec(master.get(entry.name) ?? '');
      // Drop identifier quoting first, then table qualifiers, so
      // `"organizations"."identifier"` and bare `identifier` compare equal.
      const predicate = whereMatch
        ? whereMatch[1]
            .replace(/["`[\]]/g, '')
            .replace(new RegExp(`\\b${table}\\.`, 'g'), '')
            .replace(/\s+/g, ' ')
            .trim()
            .toLowerCase()
        : '';
      return `${entry.unique ? 'UNIQUE' : 'INDEX'}(${columns.join(',')})${predicate ? ` WHERE ${predicate}` : ''}`;
    })
    .sort();
}

function foreignKeySignatures(db, table) {
  return db
    .prepare(`PRAGMA foreign_key_list(${JSON.stringify(table)})`)
    .all()
    .map((fk) => `${fk.from}->${fk.table}.${fk.to} ON DELETE ${fk.on_delete}`)
    .sort();
}

function compare() {
  const legacy = buildLegacyDatabase();
  const generated = buildGeneratedDatabase();
  const diffs = [];

  const legacyTables = new Set(tableNames(legacy));
  const generatedTables = new Set(tableNames(generated));
  for (const table of legacyTables) {
    if (!generatedTables.has(table)) diffs.push(`MISSING TABLE in generated: ${table}`);
  }
  for (const table of generatedTables) {
    if (!legacyTables.has(table)) diffs.push(`EXTRA TABLE in generated: ${table}`);
  }

  for (const table of [...legacyTables].filter((name) => generatedTables.has(name)).sort()) {
    const legacyColumns = columnMap(legacy, table);
    const generatedColumns = columnMap(generated, table);
    for (const [name, spec] of legacyColumns) {
      const other = generatedColumns.get(name);
      if (!other) {
        diffs.push(`${table}.${name}: missing in generated`);
        continue;
      }
      for (const field of ['type', 'notnull', 'dflt', 'pk']) {
        if (String(spec[field]) !== String(other[field])) {
          diffs.push(`${table}.${name}.${field}: legacy=${spec[field]} generated=${other[field]}`);
        }
      }
    }
    for (const name of generatedColumns.keys()) {
      if (!legacyColumns.has(name)) diffs.push(`${table}.${name}: extra in generated`);
    }

    const legacyIndexes = indexSignatures(legacy, table);
    const generatedIndexes = indexSignatures(generated, table);
    if (legacyIndexes.join('|') !== generatedIndexes.join('|')) {
      diffs.push(`${table} indexes: legacy=[${legacyIndexes}] generated=[${generatedIndexes}]`);
    }

    const legacyForeignKeys = foreignKeySignatures(legacy, table);
    const generatedForeignKeys = foreignKeySignatures(generated, table);
    if (legacyForeignKeys.join('|') !== generatedForeignKeys.join('|')) {
      diffs.push(`${table} FKs: legacy=[${legacyForeignKeys}] generated=[${generatedForeignKeys}]`);
    }
  }

  return { diffs, tableCount: legacyTables.size };
}

const { diffs, tableCount } = compare();
if (diffs.length === 0) {
  console.log(`PARITY OK — ${tableCount} tables match on columns, indexes and foreign keys.`);
} else {
  console.log(`PARITY FAILED — ${diffs.length} difference(s):`);
  for (const diff of diffs) console.log(`  - ${diff}`);
  process.exitCode = 1;
}
