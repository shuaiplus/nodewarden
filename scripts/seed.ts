// Seed a local SQLite file (wrangler D1 state or any path). Never talk to remote D1.
import { existsSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { seed } from 'drizzle-seed';

import { schemaStatements } from '../src/db/migrate';
import * as schema from '../src/db/schema';

const SEED_GENERATOR_VERSION = '2';
const LOCAL_STATE_ROOT = join(process.cwd(), '.wrangler/state');

function walkSqliteFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...walkSqliteFiles(path));
    else if (entry.name.endsWith('.sqlite')) found.push(path);
  }
  return found;
}

function resolveTarget(args: string[]): string {
  const pathArg = args.find((arg) => !arg.startsWith('--'));
  if (pathArg) {
    return resolve(pathArg);
  }
  const localFiles = walkSqliteFiles(LOCAL_STATE_ROOT);
  if (localFiles.length === 1) return localFiles[0];
  if (localFiles.length === 0) {
    throw new Error('no local D1 sqlite under .wrangler/state; pass a file path');
  }
  throw new Error(`multiple local D1 sqlite files, pass one:\n${localFiles.join('\n')}`);
}

const args = process.argv.slice(2);
if (args.includes('--remote')) {
  throw new Error('refusing to seed remote D1 (drizzle-seed exceeds the 100-param cap)');
}

const target = resolveTarget(args);
const sqlite = new Database(target);
for (const statement of schemaStatements()) {
  sqlite.exec(statement);
}

const db = drizzle({ client: sqlite });
await seed(db, schema, { count: 1, seed: 1, version: SEED_GENERATOR_VERSION }).refine(() => ({
  users: { count: 2 },
  ciphers: { count: 2 },
  usedAttachmentDownloadTokens: { count: 0 },
  loginAttemptsIp: { count: 0 },
  rateLimitBuckets: { count: 0 },
  ssoAuth: { count: 0 },
  webauthnChallenges: { count: 0 },
  totpLoginReplays: { count: 0 },
}));

console.log(`seeded ${target}`);
