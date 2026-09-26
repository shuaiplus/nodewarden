import { and, asc, desc, eq, inArray, isNull, type SQL } from 'drizzle-orm';

import { chunkRows, columnCount, getOrm } from '../db/client';
import {
  smAccessTokens,
  smProjects,
  smSecretProjects,
  smSecrets,
  smServiceAccountProjects,
  smServiceAccounts,
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
  await getOrm(db)
    .insert(smProjects)
    .values(project)
    .onConflictDoUpdate({
      target: smProjects.id,
      set: { name: project.name, updatedAt: project.updatedAt },
    });
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
  await getOrm(db).insert(smAccessTokens).values(token);
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

export async function revokeAccessToken(db: D1Database, id: string, revokedAt: string): Promise<void> {
  await getOrm(db).update(smAccessTokens).set({ revokedAt }).where(eq(smAccessTokens.id, id));
}
