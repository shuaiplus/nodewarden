import { diffPolicies, grantsFromRows, type GrantRows, type SmActor, type SmGrants, type SmAccess } from './sm-authz';
import { and, asc, desc, eq, inArray, isNull, type SQL } from 'drizzle-orm';

import { chunkRows, columnCount, getOrm } from '../db/client';
import {
  smAccessTokens,
  smProjects,
  smProjectMembers,
  smSecretProjects,
  smSecrets,
  smServiceAccountProjects,
  smServiceAccounts,
  smServiceAccountMembers,
} from '../db/schema';

export interface SmProject {
  id: string;
  orgId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface SmSecret {
  id: string;
  orgId: string;
  key: string;
  value: string;
  note: string | null;
  projectIds: string[];
  createdAt: string;
  updatedAt: string;
  deletedAt: string | null;
}

export interface SmServiceAccount {
  id: string;
  orgId: string;
  name: string;
  createdAt: string;
  updatedAt: string;
}

export interface SmAccessToken {
  id: string;
  serviceAccountId: string;
  name: string;
  clientSecretHash: string;
  encryptedPayload?: string | null;
  key?: string | null;
  expireAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

function mapProject(row: typeof smProjects.$inferSelect): SmProject {
  return {
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapSecret(row: typeof smSecrets.$inferSelect, projectIds: string[]): SmSecret {
  return {
    id: row.id,
    orgId: row.orgId,
    key: row.key,
    value: row.value,
    note: row.note,
    projectIds,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
  };
}

function mapServiceAccount(row: typeof smServiceAccounts.$inferSelect): SmServiceAccount {
  return {
    id: row.id,
    orgId: row.orgId,
    name: row.name,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapAccessToken(row: typeof smAccessTokens.$inferSelect): SmAccessToken {
  return {
    id: row.id,
    serviceAccountId: row.serviceAccountId,
    name: row.name,
    clientSecretHash: row.clientSecretHash,
    encryptedPayload: row.encryptedPayload,
    key: row.key,
    expireAt: row.expireAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
}

// A link counts only when its project is in the secret's org, so a link stored across
// organizations never shows. `secretScope` filters sm_secrets by org or by one id, never by an id
// list, which broke past D1's bound-parameter cap.
async function projectIdsBySecret(db: D1Database, secretScope: SQL): Promise<Map<string, string[]>> {
  const grouped = new Map<string, string[]>();
  const rows = await getOrm(db)
    .select({ secretId: smSecretProjects.secretId, projectId: smSecretProjects.projectId })
    .from(smSecretProjects)
    .innerJoin(smSecrets, eq(smSecrets.id, smSecretProjects.secretId))
    .innerJoin(smProjects, and(eq(smProjects.id, smSecretProjects.projectId), eq(smProjects.orgId, smSecrets.orgId)))
    .where(secretScope);
  for (const row of rows) {
    const list = grouped.get(row.secretId);
    if (list) list.push(row.projectId);
    else grouped.set(row.secretId, [row.projectId]);
  }
  return grouped;
}

export async function saveProject(db: D1Database, project: SmProject): Promise<void> {
  const orm = getOrm(db);
  await orm.batch([orm
    .insert(smProjects)
    .values(project)
    .onConflictDoUpdate({
      target: smProjects.id,
      set: { name: project.name, updatedAt: project.updatedAt },
    })]);
}

export async function listProjects(db: D1Database, orgId: string): Promise<SmProject[]> {
  const rows = await getOrm(db)
    .select()
    .from(smProjects)
    .where(eq(smProjects.orgId, orgId))
    .orderBy(asc(smProjects.name));
  return rows.map(mapProject);
}

export async function getProject(db: D1Database, id: string): Promise<SmProject | null> {
  const [row] = await getOrm(db).select().from(smProjects).where(eq(smProjects.id, id)).limit(1);
  return row ? mapProject(row) : null;
}

// The subset of `ids` that are projects of `orgId`. Each chunk also binds the org id.
export async function projectsInOrg(db: D1Database, orgId: string, ids: string[]): Promise<Set<string>> {
  const orm = getOrm(db);
  const chunks = await Promise.all(chunkRows(ids, 1, 1)
    .map((chunk) => orm.select({ id: smProjects.id }).from(smProjects).where(and(eq(smProjects.orgId, orgId), inArray(smProjects.id, chunk)))));
  return new Set(chunks.flat().map(({ id }) => id));
}

export async function deleteProject(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(smProjects).where(eq(smProjects.id, id));
}

// Saves the secret and replaces its links in one batch with chunked inserts, so a link that fails
// cannot leave the secret saved with its previous links gone.
export async function saveSecret(db: D1Database, secret: SmSecret): Promise<void> {
  const orm = getOrm(db);
  const upsert = orm
    .insert(smSecrets)
    .values({
      id: secret.id,
      orgId: secret.orgId,
      key: secret.key,
      value: secret.value,
      note: secret.note,
      createdAt: secret.createdAt,
      updatedAt: secret.updatedAt,
      deletedAt: secret.deletedAt,
    })
    .onConflictDoUpdate({
      target: smSecrets.id,
      set: {
        key: secret.key,
        value: secret.value,
        note: secret.note,
        updatedAt: secret.updatedAt,
        deletedAt: secret.deletedAt,
      },
    });
  const links = secret.projectIds.map((projectId) => ({ secretId: secret.id, projectId }));
  await orm.batch([
    upsert,
    orm.delete(smSecretProjects).where(eq(smSecretProjects.secretId, secret.id)),
    ...chunkRows(links, columnCount(smSecretProjects)).map((chunk) => orm.insert(smSecretProjects).values(chunk).onConflictDoNothing()),
  ]);
}

export async function getSecret(db: D1Database, id: string): Promise<SmSecret | null> {
  const [row] = await getOrm(db).select().from(smSecrets).where(eq(smSecrets.id, id)).limit(1);
  if (!row) return null;
  const projects = await projectIdsBySecret(db, eq(smSecrets.id, id));
  return mapSecret(row, projects.get(id) ?? []);
}

export async function listSecrets(db: D1Database, orgId: string, includeDeleted = false): Promise<SmSecret[]> {
  const rows = await getOrm(db)
    .select()
    .from(smSecrets)
    .where(includeDeleted ? eq(smSecrets.orgId, orgId) : and(eq(smSecrets.orgId, orgId), isNull(smSecrets.deletedAt)))
    .orderBy(desc(smSecrets.updatedAt));
  const projects = await projectIdsBySecret(db, eq(smSecrets.orgId, orgId));
  return rows.map((row) => mapSecret(row, projects.get(row.id) ?? []));
}

export async function saveServiceAccount(db: D1Database, account: SmServiceAccount): Promise<void> {
  await getOrm(db)
    .insert(smServiceAccounts)
    .values(account)
    .onConflictDoUpdate({
      target: smServiceAccounts.id,
      set: { name: account.name, updatedAt: account.updatedAt },
    });
}

export async function listServiceAccounts(db: D1Database, orgId: string): Promise<SmServiceAccount[]> {
  const rows = await getOrm(db)
    .select()
    .from(smServiceAccounts)
    .where(eq(smServiceAccounts.orgId, orgId))
    .orderBy(asc(smServiceAccounts.name));
  return rows.map(mapServiceAccount);
}

export async function getServiceAccount(db: D1Database, id: string): Promise<SmServiceAccount | null> {
  const [row] = await getOrm(db).select().from(smServiceAccounts).where(eq(smServiceAccounts.id, id)).limit(1);
  return row ? mapServiceAccount(row) : null;
}

// One batch with chunked inserts, so a grant that fails leaves the previous grants in place.
export async function replaceServiceAccountProjects(
  db: D1Database,
  serviceAccountId: string,
  projectIds: string[]
): Promise<void> {
  const orm = getOrm(db);
  const grants = projectIds.map((projectId) => ({ serviceAccountId, projectId, readAccess: 1, writeAccess: 0 }));
  await orm.batch([
    orm.delete(smServiceAccountProjects).where(eq(smServiceAccountProjects.serviceAccountId, serviceAccountId)),
    ...chunkRows(grants, columnCount(smServiceAccountProjects)).map((chunk) => orm.insert(smServiceAccountProjects).values(chunk)),
  ]);
}

// Upstream ignores a machine-account project policy without Read, so only read grants count.
export async function listReadableServiceAccountProjectIds(db: D1Database, serviceAccountId: string): Promise<string[]> {
  const rows = await getOrm(db)
    .select({ projectId: smServiceAccountProjects.projectId })
    .from(smServiceAccountProjects)
    .where(and(eq(smServiceAccountProjects.serviceAccountId, serviceAccountId), eq(smServiceAccountProjects.readAccess, 1)));
  return rows.map((row) => row.projectId);
}

export async function saveAccessToken(db: D1Database, token: SmAccessToken): Promise<void> {
  const orm = getOrm(db);
  await orm.batch([orm.insert(smAccessTokens).values(token)]);
}

export async function listAccessTokens(db: D1Database, serviceAccountId: string): Promise<SmAccessToken[]> {
  const rows = await getOrm(db)
    .select()
    .from(smAccessTokens)
    .where(eq(smAccessTokens.serviceAccountId, serviceAccountId));
  return rows.map(mapAccessToken);
}

export async function getAccessToken(db: D1Database, id: string): Promise<SmAccessToken | null> {
  const [row] = await getOrm(db).select().from(smAccessTokens).where(eq(smAccessTokens.id, id)).limit(1);
  return row ? mapAccessToken(row) : null;
}

export async function revokeAccessToken(db: D1Database, id: string, _revokedAt?: string): Promise<void> {
  const orm = getOrm(db);
  await orm.batch([orm.delete(smAccessTokens).where(eq(smAccessTokens.id, id))]);
}

export async function loadSmGrants(db: D1Database, actor: SmActor, orgId: string): Promise<SmGrants> {
  if (actor.kind === 'admin') return grantsFromRows({ projects: [], secrets: [], serviceAccounts: [] });
  if (actor.kind === 'serviceAccount') return grantsFromRows({ projects: [], secrets: [], serviceAccounts: [] });
  const statements = [
    ['sm_project_members', 'sm_project_groups', 'sm_projects', 'project_id'],
    ['sm_secret_members', 'sm_secret_groups', 'sm_secrets', 'secret_id'],
    ['sm_service_account_members', 'sm_service_account_groups', 'sm_service_accounts', 'service_account_id'],
  ].map(([members, groups, targets, target]) => {
    const permission = target === 'service_account_id' ? '' : ', x.write_access';
    return db.prepare(`SELECT x.${target} AS id${permission} FROM ${members} x
      JOIN ${targets} t ON t.id = x.${target} AND t.org_id = ? WHERE x.membership_id = ?
      UNION ALL SELECT x.${target} AS id${permission} FROM ${groups} x
      JOIN ${targets} t ON t.id = x.${target} AND t.org_id = ?
      JOIN org_groups g ON g.id = x.group_id AND g.org_id = t.org_id
      JOIN org_group_members gm ON gm.group_id = g.id WHERE gm.membership_id = ?`).bind(orgId, actor.membershipId, orgId, actor.membershipId);
  });
  const rows = await db.batch(statements);
  return grantsFromRows({ projects: rows[0].results as GrantRows['projects'], secrets: rows[1].results as GrantRows['secrets'], serviceAccounts: rows[2].results as GrantRows['serviceAccounts'] });
}

export function bumpServiceAccounts(db: D1Database, orgId: string, now = new Date().toISOString()) {
  // ponytail: org-wide bump causes extra resyncs and moves every SA's Last edited; narrow to affected SAs if either matters.
  return getOrm(db).update(smServiceAccounts).set({ updatedAt: now }).where(eq(smServiceAccounts.orgId, orgId));
}

export async function createProject(db: D1Database, project: SmProject, actor: SmActor): Promise<void> {
  const orm = getOrm(db);
  const grant = actor.kind === 'serviceAccount'
    ? orm.insert(smServiceAccountProjects).values({ projectId: project.id, serviceAccountId: actor.serviceAccountId, readAccess: 1, writeAccess: 1 })
    : orm.insert(smProjectMembers).values({ projectId: project.id, membershipId: actor.membershipId, writeAccess: 1 });
  await orm.batch([orm.insert(smProjects).values(project), grant]);
}

export async function deleteProjects(db: D1Database, orgId: string, ids: string[]): Promise<void> {
  const orm = getOrm(db);
  await orm.batch([bumpServiceAccounts(db, orgId), ...chunkRows(ids, 1, 1).map(chunk => orm.delete(smProjects).where(and(eq(smProjects.orgId, orgId), inArray(smProjects.id, chunk))))]);
}

export async function projectCounts(db: D1Database, project: SmProject, access: SmAccess) {
  const counts = { secrets: 0, people: 0, serviceAccounts: 0, object: 'projectCounts' };
  if (access === 'none') return counts;
  counts.secrets = Number((await db.prepare('SELECT COUNT(*) AS n FROM sm_secret_projects sp JOIN sm_secrets s ON s.id = sp.secret_id AND s.org_id = ? AND s.deleted_at IS NULL WHERE sp.project_id = ?').bind(project.orgId, project.id).first<{ n: number }>())?.n ?? 0);
  if (access === 'write') {
    const [people, accounts] = await db.batch<{ n: number }>([
      db.prepare('SELECT (SELECT COUNT(*) FROM sm_project_members WHERE project_id = ?) + (SELECT COUNT(*) FROM sm_project_groups WHERE project_id = ?) AS n').bind(project.id, project.id),
      db.prepare('SELECT COUNT(*) AS n FROM sm_service_account_projects WHERE project_id = ? AND read_access = 1').bind(project.id),
    ]);
    counts.people = Number(people.results[0].n); counts.serviceAccounts = Number(accounts.results[0].n);
  }
  return counts;
}

export async function getProjectsByIds(db: D1Database, ids: string[]): Promise<SmProject[]> {
  const orm = getOrm(db);
  return (await Promise.all(chunkRows(ids, 1).map(chunk => orm.select().from(smProjects).where(inArray(smProjects.id, chunk))))).flat().map(mapProject);
}

export async function updateProject(db: D1Database, project: SmProject): Promise<boolean> {
  const orm = getOrm(db);
  const [rows] = await orm.batch([orm.update(smProjects).set({ name: project.name, updatedAt: project.updatedAt }).where(eq(smProjects.id, project.id)).returning({ id: smProjects.id })]);
  return rows.length > 0;
}

export function revisionStatement(db: D1Database, orgId: string, now = new Date().toISOString()): D1PreparedStatement {
  // ponytail: org-wide revision bump trades a smaller write path for extra machine resyncs.
  return db.prepare('UPDATE sm_service_accounts SET updated_at = ? WHERE org_id = ?').bind(now, orgId);
}

export async function createSecret(db: D1Database, secret: SmSecret, policies: D1PreparedStatement[] = []): Promise<void> {
  await db.batch([
    db.prepare('INSERT INTO sm_secrets (id, org_id, key, value, note, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)').bind(secret.id, secret.orgId, secret.key, secret.value, secret.note, secret.createdAt, secret.updatedAt),
    ...secret.projectIds.map(projectId => db.prepare('INSERT INTO sm_secret_projects (secret_id, project_id) VALUES (?, ?)').bind(secret.id, projectId)),
    ...policies,
    revisionStatement(db, secret.orgId, secret.updatedAt),
  ]);
}

export async function updateSecret(db: D1Database, secret: SmSecret, previousProjectIds: string[], previousRevision: string, policies: D1PreparedStatement[] = []): Promise<boolean> {
  const statements = [db.prepare(`UPDATE sm_secrets SET key = ?, value = ?, note = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL AND updated_at = ?
    AND (SELECT COUNT(*) FROM sm_secret_projects sp JOIN sm_projects p ON p.id = sp.project_id AND p.org_id = sm_secrets.org_id WHERE sp.secret_id = sm_secrets.id) = ?
    AND NOT EXISTS (SELECT 1 FROM sm_secret_projects sp JOIN sm_projects p ON p.id = sp.project_id AND p.org_id = sm_secrets.org_id WHERE sp.secret_id = sm_secrets.id AND sp.project_id NOT IN (SELECT value FROM json_each(?)))`).bind(secret.key, secret.value, secret.note, secret.updatedAt, secret.id, previousRevision, previousProjectIds.length, JSON.stringify(previousProjectIds)),
    // Abort the atomic batch before links or policies if the authorized snapshot changed.
    db.prepare("SELECT CASE WHEN changes() = 0 THEN json('stale secret update') END"),
  ];
  if (previousProjectIds[0] !== secret.projectIds[0]) {
    statements.push(db.prepare('DELETE FROM sm_secret_projects WHERE secret_id = ? AND EXISTS (SELECT 1 FROM sm_secrets WHERE id = ? AND deleted_at IS NULL)').bind(secret.id, secret.id));
    for (const projectId of secret.projectIds) statements.push(db.prepare('INSERT INTO sm_secret_projects (secret_id, project_id) SELECT id, ? FROM sm_secrets WHERE id = ? AND deleted_at IS NULL').bind(projectId, secret.id));
  }
  try {
    await db.batch([...statements, ...policies, revisionStatement(db, secret.orgId, secret.updatedAt)]);
    return true;
  } catch (error) {
    if (error instanceof Error && error.message.includes('malformed JSON')) return false;
    throw error;
  }
}

export async function getSecretsByIds(db: D1Database, ids: string[]): Promise<SmSecret[]> {
  const orm = getOrm(db);
  const results = await Promise.all(chunkRows(ids, 1).map(async chunk => {
    const rows = await orm.select().from(smSecrets).where(inArray(smSecrets.id, chunk));
    const projects = await projectIdsBySecret(db, inArray(smSecrets.id, chunk));
    return rows.map(row => mapSecret(row, projects.get(row.id) ?? []));
  }));
  return results.flat();
}

export async function deleteSecrets(db: D1Database, orgId: string, ids: string[]): Promise<void> {
  const orm = getOrm(db);
  const now = new Date().toISOString();
  await orm.batch([bumpServiceAccounts(db, orgId, now), ...chunkRows(ids, 1, 3).map(chunk => orm.update(smSecrets).set({ deletedAt: now, updatedAt: now }).where(and(eq(smSecrets.orgId, orgId), inArray(smSecrets.id, chunk), isNull(smSecrets.deletedAt))))]);
}

export async function createServiceAccount(db: D1Database, account: SmServiceAccount, membershipId: string): Promise<void> {
  const orm = getOrm(db);
  await orm.batch([
    orm.insert(smServiceAccounts).values(account),
    orm.insert(smServiceAccountMembers).values({ serviceAccountId: account.id, membershipId }),
  ]);
}

export async function updateServiceAccount(db: D1Database, account: SmServiceAccount): Promise<boolean> {
  const orm = getOrm(db);
  const [rows] = await orm.batch([orm.update(smServiceAccounts).set({ name: account.name, updatedAt: account.updatedAt }).where(eq(smServiceAccounts.id, account.id)).returning({ id: smServiceAccounts.id })]);
  return rows.length > 0;
}

export async function getServiceAccountsByIds(db: D1Database, ids: string[]): Promise<SmServiceAccount[]> {
  const orm = getOrm(db);
  return (await Promise.all(chunkRows(ids, 1).map(chunk => orm.select().from(smServiceAccounts).where(inArray(smServiceAccounts.id, chunk))))).flat().map(mapServiceAccount);
}

export async function deleteServiceAccounts(db: D1Database, orgId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const orm = getOrm(db);
  const statements = chunkRows(ids, 1, 1).map(chunk => orm.delete(smServiceAccounts).where(and(eq(smServiceAccounts.orgId, orgId), inArray(smServiceAccounts.id, chunk))));
  await orm.batch([statements[0], ...statements.slice(1)]);
}

export async function revokeAccessTokens(db: D1Database, serviceAccountId: string, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const orm = getOrm(db);
  const statements = chunkRows(ids, 1, 1).map(chunk => orm.delete(smAccessTokens).where(and(eq(smAccessTokens.serviceAccountId, serviceAccountId), inArray(smAccessTokens.id, chunk))));
  await orm.batch([statements[0], ...statements.slice(1)]);
}

export async function serviceAccountSecretCounts(db: D1Database, orgId: string): Promise<Map<string, number>> {
  const rows = await db.prepare(`SELECT sa.id, COUNT(s.id) AS n FROM sm_service_accounts sa
    LEFT JOIN sm_secrets s ON s.org_id = sa.org_id AND s.deleted_at IS NULL AND (
      EXISTS (SELECT 1 FROM sm_secret_service_accounts sp WHERE sp.secret_id = s.id AND sp.service_account_id = sa.id)
      OR EXISTS (SELECT 1 FROM sm_secret_projects sp JOIN sm_service_account_projects ap ON ap.project_id = sp.project_id AND ap.service_account_id = sa.id AND ap.read_access = 1
        JOIN sm_projects p ON p.id = sp.project_id AND p.org_id = sa.org_id WHERE sp.secret_id = s.id))
    WHERE sa.org_id = ? GROUP BY sa.id`).bind(orgId).all<{ id: string; n: number }>();
  return new Map(rows.results.map(row => [row.id, row.n]));
}

export async function serviceAccountCounts(db: D1Database, account: SmServiceAccount, access: SmAccess) {
  const counts = { projects: 0, people: 0, accessTokens: 0, object: 'serviceAccountCounts' };
  if (access === 'none') return counts;
  const [row] = await db.batch<{ projects: number; people: number; accessTokens: number }>([db.prepare(`SELECT
    (SELECT COUNT(*) FROM sm_service_account_projects sp JOIN sm_projects p ON p.id = sp.project_id AND p.org_id = ? WHERE sp.service_account_id = ? AND sp.read_access = 1) AS projects,
    ((SELECT COUNT(*) FROM sm_service_account_members WHERE service_account_id = ?) + (SELECT COUNT(*) FROM sm_service_account_groups WHERE service_account_id = ?)) AS people,
    (SELECT COUNT(*) FROM sm_access_tokens WHERE service_account_id = ?) AS accessTokens`).bind(account.orgId, account.id, account.id, account.id, account.id)]);
  return { ...counts, ...row.results[0] };
}

export const peoplePolicyTables = {
  secret: { member: 'sm_secret_members', group: 'sm_secret_groups', target: 'secret_id' },
  project: { member: 'sm_project_members', group: 'sm_project_groups', target: 'project_id' },
  serviceAccount: { member: 'sm_service_account_members', group: 'sm_service_account_groups', target: 'service_account_id' },
} as const;
export type SmPeopleTarget = keyof typeof peoplePolicyTables;

export async function readPeoplePolicies(db: D1Database, kind: SmPeopleTarget, id: string) {
  const tables = peoplePolicyTables[kind];
  const permission = kind === 'serviceAccount' ? '1 AS write_access' : 'write_access';
  const rows = await db.batch<{ id: string; write_access: number }>([
    db.prepare(`SELECT membership_id AS id, ${permission} FROM ${tables.member} WHERE ${tables.target} = ?`).bind(id),
    db.prepare(`SELECT group_id AS id, ${permission} FROM ${tables.group} WHERE ${tables.target} = ?`).bind(id),
  ]);
  return { users: new Map(rows[0].results.map(row => [row.id, row.write_access ? 'write' as const : 'read' as const])), groups: new Map(rows[1].results.map(row => [row.id, row.write_access ? 'write' as const : 'read' as const])) };
}

export async function replacePeoplePolicies(db: D1Database, kind: SmPeopleTarget, id: string, users: Map<string, SmAccess>, groups: Map<string, SmAccess>): Promise<void> {
  const tables = peoplePolicyTables[kind];
  const statements = [db.prepare(`DELETE FROM ${tables.member} WHERE ${tables.target} = ?`).bind(id), db.prepare(`DELETE FROM ${tables.group} WHERE ${tables.target} = ?`).bind(id)];
  for (const [table, column, policies] of [[tables.member, 'membership_id', users], [tables.group, 'group_id', groups]] as const) {
    const columns = kind === 'serviceAccount' ? 2 : 3;
    for (const rows of chunkRows([...policies], columns)) {
      statements.push(db.prepare(`INSERT INTO ${table} (${tables.target}, ${column}${columns === 3 ? ', write_access' : ''}) VALUES ${rows.map(() => `(${Array(columns).fill('?').join(',')})`).join(',')}`).bind(...rows.flatMap(([granteeId, access]) => columns === 3 ? [id, granteeId, access === 'write' ? 1 : 0] : [id, granteeId])));
    }
  }
  await db.batch(statements);
}

export const machinePolicyTables = {
  secretMembers: { table: 'sm_secret_members', target: 'secret_id', grantee: 'membership_id', read: false },
  secretGroups: { table: 'sm_secret_groups', target: 'secret_id', grantee: 'group_id', read: false },
  secretServiceAccounts: { table: 'sm_secret_service_accounts', target: 'secret_id', grantee: 'service_account_id', read: false },
  projectServiceAccounts: { table: 'sm_service_account_projects', target: 'project_id', grantee: 'service_account_id', read: true },
  serviceAccountProjects: { table: 'sm_service_account_projects', target: 'service_account_id', grantee: 'project_id', read: true },
} as const;
export type SmMachinePolicy = keyof typeof machinePolicyTables;

export function policyDiffStatements(db: D1Database, kind: SmMachinePolicy, id: string, current: ReadonlyMap<string, SmAccess>, requested: ReadonlyMap<string, SmAccess>): D1PreparedStatement[] {
  const { table, target, grantee, read } = machinePolicyTables[kind];
  const { created, updated, deleted } = diffPolicies(current, requested);
  const statements = deleted.map(granteeId => db.prepare(`DELETE FROM ${table} WHERE ${target} = ? AND ${grantee} = ?`).bind(id, granteeId));
  statements.push(...updated.map(granteeId => db.prepare(`UPDATE ${table} SET write_access = ?${read ? ', read_access = 1' : ''} WHERE ${target} = ? AND ${grantee} = ?`).bind(requested.get(granteeId) === 'write' ? 1 : 0, id, granteeId)));
  const columns = read ? 4 : 3;
  for (const chunk of chunkRows(created, columns)) statements.push(db.prepare(`INSERT INTO ${table} (${target}, ${grantee}, write_access${read ? ', read_access' : ''}) VALUES ${chunk.map(() => `(${Array(columns).fill('?').join(',')})`).join(',')}`).bind(...chunk.flatMap(granteeId => [id, granteeId, requested.get(granteeId) === 'write' ? 1 : 0, ...(read ? [1] : [])])));
  return statements;
}

export async function readProjectMachinePolicies(db: D1Database, orgId: string, id: string) {
  const rows = await db.prepare('SELECT sa.id, sa.name, sp.write_access FROM sm_service_account_projects sp JOIN sm_service_accounts sa ON sa.id = sp.service_account_id AND sa.org_id = ? WHERE sp.project_id = ? AND sp.read_access = 1').bind(orgId, id).all<{ id: string; name: string; write_access: number }>();
  return rows.results;
}

export async function readGrantedProjects(db: D1Database, orgId: string, id: string) {
  const rows = await db.prepare('SELECT p.id, p.name, sp.write_access FROM sm_service_account_projects sp JOIN sm_projects p ON p.id = sp.project_id AND p.org_id = ? WHERE sp.service_account_id = ? AND sp.read_access = 1').bind(orgId, id).all<{ id: string; name: string; write_access: number }>();
  return rows.results;
}

export async function readSecretMachinePolicies(db: D1Database, orgId: string, id: string) {
  const rows = await db.prepare('SELECT sa.id, sa.name, sp.write_access FROM sm_secret_service_accounts sp JOIN sm_service_accounts sa ON sa.id = sp.service_account_id AND sa.org_id = ? WHERE sp.secret_id = ?').bind(orgId, id).all<{ id: string; name: string; write_access: number }>();
  return rows.results;
}

export async function getAccessTokenWithAccount(db: D1Database, id: string): Promise<(SmAccessToken & { orgId: string }) | null> {
  const [row] = await getOrm(db).select({ token: smAccessTokens, orgId: smServiceAccounts.orgId }).from(smAccessTokens)
    .innerJoin(smServiceAccounts, eq(smServiceAccounts.id, smAccessTokens.serviceAccountId)).where(eq(smAccessTokens.id, id)).limit(1);
  return row ? { ...mapAccessToken(row.token), orgId: row.orgId } : null;
}
