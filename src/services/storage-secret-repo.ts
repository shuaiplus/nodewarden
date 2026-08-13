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

export async function saveProject(db: D1Database, project: SmProject): Promise<void> {
  await db.prepare(
    'INSERT INTO sm_projects(id, org_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at'
  ).bind(project.id, project.orgId, project.name, project.createdAt, project.updatedAt).run();
}

export async function listProjects(db: D1Database, orgId: string): Promise<SmProject[]> {
  const result = await db.prepare('SELECT * FROM sm_projects WHERE org_id = ? ORDER BY name').bind(orgId).all<any>();
  return (result.results || []).map((row) => ({
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export async function getProject(db: D1Database, id: string): Promise<SmProject | null> {
  const row = await db.prepare('SELECT * FROM sm_projects WHERE id = ?').bind(id).first<any>();
  if (!row) return null;
  return { id: row.id, orgId: row.org_id, name: row.name, createdAt: row.created_at, updatedAt: row.updated_at };
}

export async function deleteProject(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM sm_projects WHERE id = ?').bind(id).run();
}

export async function saveSecret(db: D1Database, secret: SmSecret): Promise<void> {
  await db.prepare(
    'INSERT INTO sm_secrets(id, org_id, key, value, note, created_at, updated_at, deleted_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET key=excluded.key, value=excluded.value, note=excluded.note, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at'
  ).bind(secret.id, secret.orgId, secret.key, secret.value, secret.note, secret.createdAt, secret.updatedAt, secret.deletedAt).run();
  await db.prepare('DELETE FROM sm_secret_projects WHERE secret_id = ?').bind(secret.id).run();
  for (const projectId of secret.projectIds) {
    await db.prepare('INSERT OR IGNORE INTO sm_secret_projects(secret_id, project_id) VALUES(?, ?)').bind(secret.id, projectId).run();
  }
}

export async function getSecret(db: D1Database, id: string): Promise<SmSecret | null> {
  const row = await db.prepare('SELECT * FROM sm_secrets WHERE id = ?').bind(id).first<any>();
  if (!row) return null;
  const projects = await db.prepare('SELECT project_id FROM sm_secret_projects WHERE secret_id = ?').bind(id).all<{ project_id: string }>();
  return {
    id: row.id,
    orgId: row.org_id,
    key: row.key,
    value: row.value,
    note: row.note,
    projectIds: (projects.results || []).map((item) => item.project_id),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at,
  };
}

export async function listSecrets(db: D1Database, orgId: string, includeDeleted = false): Promise<SmSecret[]> {
  const sql = includeDeleted
    ? 'SELECT * FROM sm_secrets WHERE org_id = ? ORDER BY updated_at DESC'
    : 'SELECT * FROM sm_secrets WHERE org_id = ? AND deleted_at IS NULL ORDER BY updated_at DESC';
  const result = await db.prepare(sql).bind(orgId).all<any>();
  const secrets: SmSecret[] = [];
  for (const row of result.results || []) {
    const projects = await db.prepare('SELECT project_id FROM sm_secret_projects WHERE secret_id = ?').bind(row.id).all<{ project_id: string }>();
    secrets.push({
      id: row.id,
      orgId: row.org_id,
      key: row.key,
      value: row.value,
      note: row.note,
      projectIds: (projects.results || []).map((item) => item.project_id),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      deletedAt: row.deleted_at,
    });
  }
  return secrets;
}

export async function saveServiceAccount(db: D1Database, account: SmServiceAccount): Promise<void> {
  await db.prepare(
    'INSERT INTO sm_service_accounts(id, org_id, name, created_at, updated_at) VALUES(?, ?, ?, ?, ?) ' +
    'ON CONFLICT(id) DO UPDATE SET name=excluded.name, updated_at=excluded.updated_at'
  ).bind(account.id, account.orgId, account.name, account.createdAt, account.updatedAt).run();
}

export async function listServiceAccounts(db: D1Database, orgId: string): Promise<SmServiceAccount[]> {
  const result = await db.prepare('SELECT * FROM sm_service_accounts WHERE org_id = ? ORDER BY name').bind(orgId).all<any>();
  return (result.results || []).map((row) => ({
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  }));
}

export async function getServiceAccount(db: D1Database, id: string): Promise<SmServiceAccount | null> {
  const row = await db.prepare('SELECT * FROM sm_service_accounts WHERE id = ?').bind(id).first<any>();
  if (!row) return null;
  return { id: row.id, orgId: row.org_id, name: row.name, createdAt: row.created_at, updatedAt: row.updated_at };
}

export async function replaceServiceAccountProjects(
  db: D1Database,
  serviceAccountId: string,
  projectIds: string[]
): Promise<void> {
  await db.prepare('DELETE FROM sm_service_account_projects WHERE service_account_id = ?').bind(serviceAccountId).run();
  for (const projectId of projectIds) {
    await db.prepare(
      'INSERT INTO sm_service_account_projects(service_account_id, project_id, read_access, write_access) VALUES(?, ?, 1, 0)'
    ).bind(serviceAccountId, projectId).run();
  }
}

export async function listServiceAccountProjectIds(db: D1Database, serviceAccountId: string): Promise<string[]> {
  const result = await db
    .prepare('SELECT project_id FROM sm_service_account_projects WHERE service_account_id = ?')
    .bind(serviceAccountId)
    .all<{ project_id: string }>();
  return (result.results || []).map((row) => row.project_id);
}

export async function saveAccessToken(db: D1Database, token: SmAccessToken): Promise<void> {
  await db.prepare(
    'INSERT INTO sm_access_tokens(id, service_account_id, name, client_secret_hash, wrapped_org_key, expire_at, revoked_at, created_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    token.id,
    token.serviceAccountId,
    token.name,
    token.clientSecretHash,
    token.wrappedOrgKey,
    token.expireAt,
    token.revokedAt,
    token.createdAt
  ).run();
}

export async function listAccessTokens(db: D1Database, serviceAccountId: string): Promise<SmAccessToken[]> {
  const result = await db.prepare('SELECT * FROM sm_access_tokens WHERE service_account_id = ?').bind(serviceAccountId).all<any>();
  return (result.results || []).map((row) => ({
    id: row.id,
    serviceAccountId: row.service_account_id,
    name: row.name,
    clientSecretHash: row.client_secret_hash,
    wrappedOrgKey: row.wrapped_org_key,
    expireAt: row.expire_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  }));
}

export async function getAccessToken(db: D1Database, id: string): Promise<SmAccessToken | null> {
  const row = await db.prepare('SELECT * FROM sm_access_tokens WHERE id = ?').bind(id).first<any>();
  if (!row) return null;
  return {
    id: row.id,
    serviceAccountId: row.service_account_id,
    name: row.name,
    clientSecretHash: row.client_secret_hash,
    wrappedOrgKey: row.wrapped_org_key,
    expireAt: row.expire_at,
    revokedAt: row.revoked_at,
    createdAt: row.created_at,
  };
}

export async function revokeAccessToken(db: D1Database, id: string, revokedAt: string): Promise<void> {
  await db.prepare('UPDATE sm_access_tokens SET revoked_at = ? WHERE id = ?').bind(revokedAt, id).run();
}
