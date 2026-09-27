import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { eq } from 'drizzle-orm';
import { Miniflare } from 'miniflare';

const repo = process.env.SM_E2E_REPO_ROOT || fileURLToPath(new URL('../..', import.meta.url));
const load = (path: string) => import(pathToFileURL(resolve(repo, path)).href);
const { updateSecret } = await load('src/services/storage-secret-repo.ts');
const { abortUnlessChanged, getOrm } = await load('src/db/client.ts');
const { ensureStorageSchema } = await load('src/db/migrate.ts');
const { organizations, smProjects, smSecretProjects, smSecretServiceAccounts, smSecrets, smServiceAccounts } = await load('src/db/schema.ts');
// This platform check complements SQLite route tests: it needs workerd's actual D1 batch.
const mf = new Miniflare({ modules: true, script: 'export default { fetch() { return new Response("local"); } };', compatibilityDate: '2024-09-23', d1Databases: { DB: 'sm-batch-check' } });
try {
  const db = await mf.getD1Database('DB');
  await ensureStorageSchema(db);
  const orm = getOrm(db);
  await orm.batch([
    orm.insert(organizations).values({ id: 'org', name: 'org', billingEmail: 'billing@example.test', createdAt: 'r0', updatedAt: 'r0' }),
    orm.insert(smSecrets).values({ id: 'secret', orgId: 'org', key: 'key', value: 'current-value', note: 'note', createdAt: 'r0', updatedAt: 'r2' }),
    orm.insert(smProjects).values(['p', 'q'].map((id) => ({ id, orgId: 'org', name: id, createdAt: 'r0', updatedAt: 'r0' }))),
    orm.insert(smSecretProjects).values({ secretId: 'secret', projectId: 'q' }),
    orm.insert(smServiceAccounts).values({ id: 'machine', orgId: 'org', name: 'machine', createdAt: 'r0', updatedAt: 'old-machine-revision' }),
  ]);
  const next = { id: 'secret', orgId: 'org', key: 'key', value: 'stale-value', note: 'note', updatedAt: 'r3', createdAt: 'r0', deletedAt: null, projectIds: ['p'] };
  // An access policy granting the machine account the secret, batched with the update as policy changes are.
  const policy = () => orm.insert(smSecretServiceAccounts).values({ secretId: 'secret', serviceAccountId: 'machine', writeAccess: 1 });
  // Everything updateSecret writes: the secret, its project links, the batched policy and the machine account revision.
  const snapshot = async () => ({
    secret: await orm.select({ value: smSecrets.value, updatedAt: smSecrets.updatedAt }).from(smSecrets),
    links: await orm.select({ projectId: smSecretProjects.projectId }).from(smSecretProjects),
    policies: await orm.select({ writeAccess: smSecretServiceAccounts.writeAccess }).from(smSecretServiceAccounts),
    machines: await orm.select({ updatedAt: smServiceAccounts.updatedAt }).from(smServiceAccounts),
  });
  assert.equal(await updateSecret(db, next, ['p'], 'r2', [policy()]), false, 'moved project rejected despite same revision');
  assert.equal(await updateSecret(db, next, ['q'], 'r1', [policy()]), false, 'stale revision rejected');
  assert.deepEqual(await snapshot(), { secret: [{ value: 'current-value', updatedAt: 'r2' }], links: [{ projectId: 'q' }], policies: [], machines: [{ updatedAt: 'old-machine-revision' }] });
  assert.equal(await updateSecret(db, next, ['q'], 'r2', [policy()]), true, 'current snapshot commits');
  const committed = { secret: [{ value: 'stale-value', updatedAt: 'r3' }], links: [{ projectId: 'p' }], policies: [{ writeAccess: 1 }], machines: [{ updatedAt: 'r3' }] };
  assert.deepEqual(await snapshot(), committed);
  await assert.rejects(orm.batch([
    orm.update(smSecretServiceAccounts).set({ writeAccess: 0 }),
    orm.update(smSecrets).set({ value: 'must not survive' }).where(eq(smSecrets.id, 'absent')),
    abortUnlessChanged(orm, 'stale secret update'),
    orm.delete(smSecretServiceAccounts),
  ]), /malformed JSON/);
  assert.deepEqual(await snapshot(), committed, 'workerd D1 rolls back a write before the sentinel');
  console.log('PASS workerd D1: changed project rejected; stale revision rejected; links/policy/revision unchanged; current snapshot commits; malformed-JSON sentinel rolls entire batch back.');
} finally { await mf.dispose(); }
