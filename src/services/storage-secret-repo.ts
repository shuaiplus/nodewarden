import { and, asc, desc, eq, inArray, isNull } from 'drizzle-orm';

import { getOrm } from '../db/client';
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
  wrappedOrgKey: string | null;
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
    wrappedOrgKey: row.wrappedOrgKey,
    expireAt: row.expireAt,
    revokedAt: row.revokedAt,
    createdAt: row.createdAt,
  };
}

async function projectIdsBySecret(db: D1Database, secretIds: string[]): Promise<Map<string, string[]>> {
  const grouped = new Map<string, string[]>();
  if (!secretIds.length) return grouped;
  const rows = await getOrm(db)
    .select({ secretId: smSecretProjects.secretId, projectId: smSecretProjects.projectId })
    .from(smSecretProjects)
    .where(inArray(smSecretProjects.secretId, secretIds));
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

export async function deleteProject(db: D1Database, id: string): Promise<void> {
  await getOrm(db).delete(smProjects).where(eq(smProjects.id, id));
}

export async function saveSecret(db: D1Database, secret: SmSecret): Promise<void> {
  const orm = getOrm(db);
  await orm
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
  await orm.delete(smSecretProjects).where(eq(smSecretProjects.secretId, secret.id));
  if (secret.projectIds.length) {
    await orm.insert(smSecretProjects).values(
      secret.projectIds.map((projectId) => ({ secretId: secret.id, projectId }))
    ).onConflictDoNothing();
  }
}

export async function getSecret(db: D1Database, id: string): Promise<SmSecret | null> {
  const [row] = await getOrm(db).select().from(smSecrets).where(eq(smSecrets.id, id)).limit(1);
  if (!row) return null;
  const projects = await projectIdsBySecret(db, [id]);
  return mapSecret(row, projects.get(id) ?? []);
}

export async function listSecrets(db: D1Database, orgId: string, includeDeleted = false): Promise<SmSecret[]> {
  const rows = await getOrm(db)
    .select()
    .from(smSecrets)
    .where(includeDeleted ? eq(smSecrets.orgId, orgId) : and(eq(smSecrets.orgId, orgId), isNull(smSecrets.deletedAt)))
    .orderBy(desc(smSecrets.updatedAt));
  const projects = await projectIdsBySecret(db, rows.map((row) => row.id));
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

export async function replaceServiceAccountProjects(
  db: D1Database,
  serviceAccountId: string,
  projectIds: string[]
): Promise<void> {
  const orm = getOrm(db);
  await orm.delete(smServiceAccountProjects).where(eq(smServiceAccountProjects.serviceAccountId, serviceAccountId));
  if (projectIds.length) {
    await orm.insert(smServiceAccountProjects).values(
      projectIds.map((projectId) => ({
        serviceAccountId,
        projectId,
        readAccess: 1,
        writeAccess: 0,
      }))
    );
  }
}

export async function listServiceAccountProjectIds(db: D1Database, serviceAccountId: string): Promise<string[]> {
  const rows = await getOrm(db)
    .select({ projectId: smServiceAccountProjects.projectId })
    .from(smServiceAccountProjects)
    .where(eq(smServiceAccountProjects.serviceAccountId, serviceAccountId));
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
