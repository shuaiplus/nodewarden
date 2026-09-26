import { isSerializedEncString } from '../utils/account-passkeys';
import { projectAccess, resolveSmActor, type SmAccess } from '../services/sm-authz';
import type { Env } from '../types';
import * as orgRepo from '../services/storage-org-repo';
import * as smRepo from '../services/storage-secret-repo';
import { canAccessSecretsManager, isActiveMember } from '../services/org-authz';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID, isUUID } from '../utils/uuid';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { publishSecretChanged } from '../services/queue-publisher';

async function requireSmMember(env: Env, userId: string, orgId: string) {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member) || !canAccessSecretsManager(member)) return null;
  return member;
}

// Upstream ProjectsAreInOrganization: a missing or foreign project is 404 before any write, so a
// secret or machine account in one org can never link to another org's project. Like upstream's
// count comparison, a repeated id fails too instead of hitting the link table's primary key.
async function allProjectsInOrg(env: Env, orgId: string, projectIds: string[]): Promise<boolean> {
  const orgProjectIds = await smRepo.projectsInOrg(env.DB, orgId, projectIds);
  return new Set(projectIds).size === projectIds.length && projectIds.every((id) => orgProjectIds.has(id));
}

function secretResponse(secret: smRepo.SmSecret) {
  return {
    id: secret.id,
    organizationId: secret.orgId,
    key: secret.key,
    value: secret.value,
    note: secret.note,
    creationDate: secret.createdAt,
    revisionDate: secret.updatedAt,
    projects: secret.projectIds.map((id) => ({ id, object: 'project' })),
    read: true,
    write: true,
    object: 'secret',
  };
}

export async function handleListSecrets(env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const secrets = await smRepo.listSecrets(env.DB, orgId);
  return jsonResponse({
    secrets: secrets.map((secret) => ({
      id: secret.id,
      organizationId: secret.orgId,
      key: secret.key,
      creationDate: secret.createdAt,
      revisionDate: secret.updatedAt,
      projects: secret.projectIds.map((id) => ({ id })),
    })),
    projects: [],
    object: 'secretWithProjectsList',
  });
}

export async function handleCreateSecret(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const body = await request.json() as Record<string, unknown>;
  const now = new Date().toISOString();
  const secret: smRepo.SmSecret = {
    id: generateUUID(),
    orgId,
    key: String(body.key || ''),
    value: String(body.value || ''),
    note: body.note == null ? null : String(body.note),
    projectIds: Array.isArray(body.projectIds) ? body.projectIds.map(String) : [],
    createdAt: now,
    updatedAt: now,
    deletedAt: null,
  };
  if (!secret.key || !secret.value) return errorResponse('key and value are required', 400);
  if (!(await allProjectsInOrg(env, orgId, secret.projectIds))) return errorResponse('Resource not found.', 404);
  await smRepo.saveSecret(env.DB, secret);
  await publishSecretChanged(env, orgId, secret.id);
  return jsonResponse(secretResponse(secret));
}

export async function handleGetSecret(env: Env, userId: string, secretId: string): Promise<Response> {
  const secret = await smRepo.getSecret(env.DB, secretId);
  if (!secret) return errorResponse('Not found', 404);
  if (!(await requireSmMember(env, userId, secret.orgId))) return errorResponse('Not found', 404);
  return jsonResponse(secretResponse(secret));
}

export async function handleUpdateSecret(request: Request, env: Env, userId: string, secretId: string): Promise<Response> {
  const secret = await smRepo.getSecret(env.DB, secretId);
  if (!secret) return errorResponse('Not found', 404);
  if (!(await requireSmMember(env, userId, secret.orgId))) return errorResponse('Not found', 404);
  const body = await request.json() as Record<string, unknown>;
  if (body.key) secret.key = String(body.key);
  if (body.value) secret.value = String(body.value);
  if (body.note !== undefined) secret.note = body.note == null ? null : String(body.note);
  if (Array.isArray(body.projectIds)) secret.projectIds = body.projectIds.map(String);
  if (!(await allProjectsInOrg(env, secret.orgId, secret.projectIds))) return errorResponse('Resource not found.', 404);
  secret.updatedAt = new Date().toISOString();
  await smRepo.saveSecret(env.DB, secret);
  await publishSecretChanged(env, secret.orgId, secret.id);
  return jsonResponse(secretResponse(secret));
}

// Official web and the SDK send a bare array of ids. Upstream binds `[FromBody] List<Guid> ids`, so any
// other body, or an id that is not a GUID, is a 400 there.
export async function handleDeleteSecrets(request: Request, env: Env, userId: string): Promise<Response> {
  let ids: unknown;
  try {
    ids = await request.json();
  } catch {
    return errorResponse('Invalid JSON', 400);
  }
  if (!Array.isArray(ids) || !ids.every(isUUID)) {
    return errorResponse('Request body must be an array of secret GUIDs', 400);
  }
  const data = [];
  for (const id of ids) {
    const secret = await smRepo.getSecret(env.DB, id);
    if (!secret || !(await requireSmMember(env, userId, secret.orgId))) {
      data.push({ id, error: 'not found', object: 'BulkDeleteResponseModel' });
      continue;
    }
    secret.deletedAt = new Date().toISOString();
    secret.updatedAt = secret.deletedAt;
    await smRepo.saveSecret(env.DB, secret);
    await publishSecretChanged(env, secret.orgId, secret.id);
    data.push({ id, error: null, object: 'BulkDeleteResponseModel' });
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

export async function smContext(env: Env, userId: string, orgId: string) {
  const actor = await resolveSmActor(env, userId, orgId);
  return actor ? { actor, grants: await smRepo.loadSmGrants(env.DB, actor, orgId) } : null;
}

export function encryptedField(value: unknown, max = Infinity): value is string {
  return typeof value === 'string' && value.length <= max && isSerializedEncString(value);
}

export function listResponse<T>(data: T[]) { return { data, object: 'list', continuationToken: null }; }

function projectResponse(project: smRepo.SmProject, level: SmAccess) {
  return { id: project.id, organizationId: project.orgId, name: project.name, creationDate: project.createdAt, revisionDate: project.updatedAt, read: level !== 'none', write: level === 'write', object: 'project' };
}

export async function readIds(request: Request): Promise<string[] | null> {
  const ids: unknown = await request.json().catch(() => null);
  return Array.isArray(ids) && ids.every(isUUID) ? ids.map(id => id.toLowerCase()) : null;
}

export async function handleListProjects(env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  // ponytail: in-memory filter loads every org row; push grants into SQL if an org passes ~10k secrets.
  const projects = (await smRepo.listProjects(env.DB, orgId)).map(project => projectResponse(project, projectAccess(context.actor, context.grants, project.id))).filter(project => project.read);
  return jsonResponse(listResponse(projects));
}

export async function handleCreateProject(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  const body = await request.json().catch(() => null) as { name?: unknown } | null;
  if (!encryptedField(body?.name, 1000)) return errorResponse('Name must be an encrypted string of at most 1000 characters.', 400);
  const now = new Date().toISOString();
  const project = { id: generateUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo.createProject(env.DB, project, context.actor);
  return jsonResponse(projectResponse(project, 'write'));
}

export async function handleProject(request: Request, env: Env, userId: string, id: string, counts = false): Promise<Response> {
  const project = await smRepo.getProject(env.DB, id);
  const context = project && await smContext(env, userId, project.orgId);
  if (!project || !context) return errorResponse('Not found', 404);
  const access = projectAccess(context.actor, context.grants, id);
  if (counts) return context.actor.kind === 'serviceAccount' ? errorResponse('Not found', 404) : jsonResponse(await smRepo.projectCounts(env.DB, project, access));
  if (access === 'none' || (request.method === 'PUT' && access !== 'write')) return errorResponse('Not found', 404);
  if (request.method === 'PUT') {
    const body = await request.json().catch(() => null) as { name?: unknown } | null;
    if (!encryptedField(body?.name, 1000)) return errorResponse('Name must be an encrypted string of at most 1000 characters.', 400);
    project.name = body.name; project.updatedAt = new Date().toISOString();
    if (!await smRepo.updateProject(env.DB, project)) return errorResponse('Not found', 404);
  }
  return jsonResponse(projectResponse(project, access));
}

export async function handleDeleteProjects(request: Request, env: Env, userId: string): Promise<Response> {
  const ids = await readIds(request);
  if (!ids) return errorResponse('Request body must be an array of GUIDs', 400);
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const projects = await smRepo.getProjectsByIds(env.DB, ids);
  const orgId = projects[0]?.orgId;
  if (!orgId || projects.length !== ids.length || projects.some(project => project.orgId !== orgId)) return errorResponse('Not found', 404);
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  const data = ids.map(id => ({ id, error: projectAccess(context.actor, context.grants, id) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  await smRepo.deleteProjects(env.DB, orgId, data.filter(item => !item.error).map(item => item.id));
  return jsonResponse(listResponse(data));
}

export async function handleListServiceAccounts(env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const accounts = await smRepo.listServiceAccounts(env.DB, orgId);
  return jsonResponse({
    data: accounts.map((account) => ({
      id: account.id,
      organizationId: account.orgId,
      name: account.name,
      creationDate: account.createdAt,
      revisionDate: account.updatedAt,
      object: 'serviceAccount',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleCreateServiceAccount(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const body = await request.json() as { name?: string; projectIds?: string[] };
  const projectIds = Array.isArray(body.projectIds) ? body.projectIds.map(String) : [];
  if (!(await allProjectsInOrg(env, orgId, projectIds))) return errorResponse('Resource not found.', 404);
  const now = new Date().toISOString();
  const account = { id: generateUUID(), orgId, name: String(body.name || 'Machine account'), createdAt: now, updatedAt: now };
  await smRepo.saveServiceAccount(env.DB, account);
  await smRepo.replaceServiceAccountProjects(env.DB, account.id, projectIds);
  return jsonResponse({
    id: account.id,
    organizationId: account.orgId,
    name: account.name,
    creationDate: account.createdAt,
    revisionDate: account.updatedAt,
    object: 'serviceAccount',
  });
}

export async function handleCreateAccessToken(request: Request, env: Env, userId: string, serviceAccountId: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, serviceAccountId);
  if (!account) return errorResponse('Not found', 404);
  if (!(await requireSmMember(env, userId, account.orgId))) return errorResponse('Not found', 404);
  const body = await request.json() as { name?: string; expireAt?: string | null };
  const clientSecret = `nws_${generateUUID().replace(/-/g, '')}`;
  const token = {
    id: generateUUID(),
    serviceAccountId,
    name: String(body.name || 'Access token'),
    clientSecretHash: await hashApiKey(clientSecret),
    expireAt: body.expireAt || null,
    revokedAt: null,
    createdAt: new Date().toISOString(),
  };
  await smRepo.saveAccessToken(env.DB, token);
  return jsonResponse({
    id: token.id,
    name: token.name,
    clientSecret,
    clientId: `organization.${account.orgId}.sa.${account.id}.${token.id}`,
    expireAt: token.expireAt,
    creationDate: token.createdAt,
    object: 'accessTokenCreation',
  });
}

export async function handleListAccessTokens(env: Env, userId: string, serviceAccountId: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, serviceAccountId);
  if (!account) return errorResponse('Not found', 404);
  if (!(await requireSmMember(env, userId, account.orgId))) return errorResponse('Not found', 404);
  const tokens = await smRepo.listAccessTokens(env.DB, serviceAccountId);
  return jsonResponse({
    data: tokens.map((token) => ({
      id: token.id,
      name: token.name,
      expireAt: token.expireAt,
      revokedDate: token.revokedAt,
      creationDate: token.createdAt,
      object: 'accessToken',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export async function authenticateServiceAccount(
  env: Env,
  clientId: string,
  clientSecret: string
): Promise<{ orgId: string; serviceAccountId: string; tokenId: string } | null> {
  const match = clientId.match(/^organization\.([a-f0-9-]+)\.sa\.([a-f0-9-]+)\.([a-f0-9-]+)$/i);
  if (!match) return null;
  const token = await smRepo.getAccessToken(env.DB, match[3]);
  if (!token || token.revokedAt) return null;
  if (token.expireAt && Date.parse(token.expireAt) < Date.now()) return null;
  if (!(await verifyApiKey(clientSecret, token.clientSecretHash))) return null;
  const account = await smRepo.getServiceAccount(env.DB, token.serviceAccountId);
  if (!account || account.orgId !== match[1]) return null;
  return { orgId: account.orgId, serviceAccountId: account.id, tokenId: token.id };
}

export async function handlePublicSecretsSync(request: Request, env: Env, orgId: string): Promise<Response> {
  const authorization = String(request.headers.get('Authorization') || '');
  const bearer = authorization.replace(/^Bearer\s+/i, '').trim();
  const [clientId, clientSecret] = bearer.includes('\n') ? bearer.split('\n') : bearer.split(':');
  const machine = await authenticateServiceAccount(env, String(clientId || '').trim(), String(clientSecret || '').trim());
  if (!machine || machine.orgId !== orgId) return errorResponse('Unauthorized', 401);
  return handleSecretsSync(request, env, orgId, machine.serviceAccountId);
}

export async function handleSecretsSync(
  request: Request,
  env: Env,
  orgId: string,
  serviceAccountId: string
): Promise<Response> {
  const url = new URL(request.url);
  const lastSynced = url.searchParams.get('lastSyncedDate');
  const lastMs = lastSynced ? Date.parse(lastSynced) : 0;
  // A machine account reads a secret only through a read grant on one of its projects, so an
  // account with no readable project syncs nothing instead of the whole org.
  const readableProjectIds = new Set(await smRepo.listReadableServiceAccountProjectIds(env.DB, serviceAccountId));
  const secrets = (await smRepo.listSecrets(env.DB, orgId))
    .filter((secret) => secret.projectIds.some((projectId) => readableProjectIds.has(projectId)));
  const changed = !lastMs || secrets.some((secret) => Date.parse(secret.updatedAt) > lastMs);
  return jsonResponse({
    hasChanges: changed,
    secrets: changed ? secrets.map((secret) => ({
      id: secret.id,
      organizationId: secret.orgId,
      key: secret.key,
      value: secret.value,
      note: secret.note,
      projectIds: secret.projectIds,
      revisionDate: secret.updatedAt,
    })) : [],
    object: 'secretsSync',
  });
}
