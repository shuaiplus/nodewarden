import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Miniflare } from 'miniflare';
import { sqliteTable, text } from 'drizzle-orm/sqlite-core';

const repo = process.env.SM_E2E_REPO_ROOT || fileURLToPath(new URL('../..', import.meta.url));
const { updateSecret } = await import(pathToFileURL(resolve(repo, 'src/services/storage-secret-repo.ts')).href);
const { getOrm } = await import(pathToFileURL(resolve(repo, 'src/db/client.ts')).href);
const policyProbe = sqliteTable('policy_probe', { value: text('value') });
// This platform check complements SQLite route tests: it needs workerd's actual D1 batch.
const mf = new Miniflare({ modules: true, script: 'export default { fetch() { return new Response("local"); } };', compatibilityDate: '2024-09-23', d1Databases: { DB: 'sm-batch-check' } });
try {
  const db = await mf.getD1Database('DB');
  await db.batch([
    db.prepare('CREATE TABLE sm_secrets (id TEXT PRIMARY KEY, org_id TEXT, key TEXT, value TEXT, note TEXT, updated_at TEXT, deleted_at TEXT)'),
    db.prepare('CREATE TABLE sm_projects (id TEXT PRIMARY KEY, org_id TEXT)'),
    db.prepare('CREATE TABLE sm_secret_projects (secret_id TEXT, project_id TEXT)'),
    db.prepare('CREATE TABLE sm_service_accounts (id TEXT PRIMARY KEY, org_id TEXT, updated_at TEXT)'),
    db.prepare('CREATE TABLE policy_probe (value TEXT)'),
    db.prepare("INSERT INTO sm_secrets VALUES ('secret', 'org', 'key', 'current-value', 'note', 'r2', NULL)"),
    db.prepare("INSERT INTO sm_projects VALUES ('p', 'org'), ('q', 'org')"),
    db.prepare("INSERT INTO sm_secret_projects VALUES ('secret', 'q')"),
    db.prepare("INSERT INTO sm_service_accounts VALUES ('machine', 'org', 'old-machine-revision')"),
  ]);
  const next = { id: 'secret', orgId: 'org', key: 'key', value: 'stale-value', note: 'note', updatedAt: 'r3', createdAt: 'r0', deletedAt: null, projectIds: ['p'] };
  const policy = () => getOrm(db).insert(policyProbe).values({ value: 'changed' });
  assert.equal(await updateSecret(db, next, ['p'], 'r2', [policy()]), false, 'moved project rejected despite same revision');
  assert.equal(await updateSecret(db, next, ['q'], 'r1', [policy()]), false, 'stale revision rejected');
  assert.deepEqual(await db.prepare('SELECT value, updated_at FROM sm_secrets').all().then(r => r.results), [{ value: 'current-value', updated_at: 'r2' }]);
  assert.deepEqual(await db.prepare('SELECT project_id FROM sm_secret_projects').all().then(r => r.results), [{ project_id: 'q' }]);
  assert.equal(await db.prepare('SELECT COUNT(*) AS count FROM policy_probe').first('count'), 0);
  assert.equal(await db.prepare('SELECT updated_at FROM sm_service_accounts').first('updated_at'), 'old-machine-revision');
  assert.equal(await updateSecret(db, next, ['q'], 'r2', [policy()]), true, 'current snapshot commits');
  assert.equal(await db.prepare('SELECT value FROM sm_secrets').first('value'), 'stale-value');
  assert.equal(await db.prepare('SELECT project_id FROM sm_secret_projects').first('project_id'), 'p');
  assert.equal(await db.prepare('SELECT COUNT(*) AS count FROM policy_probe').first('count'), 1);
  assert.equal(await db.prepare('SELECT updated_at FROM sm_service_accounts').first('updated_at'), 'r3');
  await assert.rejects(db.batch([
    db.prepare("INSERT INTO policy_probe VALUES ('must roll back')"),
    db.prepare("UPDATE sm_secrets SET value = 'must not survive' WHERE id = 'absent'"),
    db.prepare("SELECT CASE WHEN changes() = 0 THEN json('stale secret update') END"),
    db.prepare("DELETE FROM policy_probe"),
  ]), /malformed JSON/);
  assert.equal(await db.prepare('SELECT COUNT(*) AS count FROM policy_probe').first('count'), 1, 'workerd D1 rolls back a write before the sentinel');
  console.log('PASS workerd D1: changed project rejected; stale revision rejected; links/policy/revision unchanged; current snapshot commits; malformed-JSON sentinel rolls entire batch back.');
} finally { await mf.dispose(); }
