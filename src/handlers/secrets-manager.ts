import { isSerializedEncString } from '../utils/account-passkeys';
import { projectAccess, serviceAccountAccess, secretAccess, canCreateSecret, canUpdateSecret, resolveSmActor, type SmAccess } from '../services/sm-authz';
import type { Env } from '../types';
import * as smRepo from '../services/storage-secret-repo';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID, isUUID } from '../utils/uuid';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { publishSecretChanged } from '../services/queue-publisher';

// Upstream ProjectsAreInOrganization: a missing or foreign project is 404 before any write, so a
// secret or machine account in one org can never link to another org's project. Like upstream's
// count comparison, a repeated id fails too instead of hitting the link table's primary key.
async function allProjectsInOrg(env: Env, orgId: string, projectIds: string[]): Promise<boolean> {
  const orgProjectIds = await smRepo.projectsInOrg(env.DB, orgId, projectIds);
  return new Set(projectIds).size === projectIds.length && projectIds.every((id) => orgProjectIds.has(id));
}

export function secretResponse(secret: smRepo.SmSecret, projects: Map<string, string>, access: SmAccess = 'write', base = false) {
  return {
    id: secret.id, organizationId: secret.orgId, key: secret.key, value: secret.value, note: secret.note,
    creationDate: secret.createdAt, revisionDate: secret.updatedAt,
    projects: secret.projectIds.map(id => ({ id, name: projects.get(id) })),
    ...(base ? {} : { read: access !== 'none', write: access === 'write' }), object: base ? 'baseSecret' : 'secret',
  };
}

export async function projectNames(env: Env, orgId: string): Promise<Map<string, string>> {
  return new Map((await smRepo.listProjects(env.DB, orgId)).map(project => [project.id, project.name]));
}

export async function secretsListResponse(env: Env, orgId: string, secrets: smRepo.SmSecret[], context: NonNullable<Awaited<ReturnType<typeof smContext>>>) {
  const names = await projectNames(env, orgId);
  const visible = secrets.filter(secret => secretAccess(context.actor, context.grants, secret) !== 'none');
  return {
    secrets: visible.map(secret => {
      const { value, note, object, ...response } = secretResponse(secret, names, secretAccess(context.actor, context.grants, secret));
      return response;
    }),
    projects: [...new Set(visible.flatMap(secret => secret.projectIds))].map(id => ({ id, name: names.get(id) })),
    object: 'SecretsWithProjectsList',
  };
}

export async function handleListSecrets(env: Env, userId: string, orgId: string, projectId?: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  const secrets = (await smRepo.listSecrets(env.DB, orgId)).filter(secret => !projectId || secret.projectIds.includes(projectId));
  return jsonResponse(await secretsListResponse(env, orgId, secrets, context));
}

export async function handleProjectSecrets(env: Env, userId: string, id: string): Promise<Response> {
  const project = await smRepo.getProject(env.DB, id);
  return project ? handleListSecrets(env, userId, project.orgId, id) : errorResponse('Not found', 404);
}

async function secretInput(request: Request) {
  const body = await request.json().catch(() => null) as Record<string, unknown> | null;
  if (!body || !encryptedField(body.key, 1000) || !encryptedField(body.value, 35000) || !encryptedField(body.note, 10000)) return errorResponse('Key, value and note must be encrypted strings within their size limits.', 400);
  if (body.projectIds != null && (!Array.isArray(body.projectIds) || !body.projectIds.every(isUUID))) return errorResponse('ProjectIds must be an array of GUIDs.', 400);
  const projectIds = (body.projectIds as string[] | null | undefined)?.map(id => id.toLowerCase()) ?? [];
  if (projectIds.length > 1) return errorResponse('Only one project assignment is supported.', 400, {}, { ProjectIds: ['Only one project assignment is supported.'] });
  if (body.accessPoliciesRequests != null) {
    const policy = body.accessPoliciesRequests;
    if (typeof policy !== 'object' || Array.isArray(policy) || Object.values(policy).some(items => !Array.isArray(items) || items.length)) return errorResponse('Secret access policies are not supported yet', 400);
  }
  return { key: body.key, value: body.value, note: body.note, projectIds };
}

export async function handleCreateSecret(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  const input = await secretInput(request);
  if (input instanceof Response) return input;
  if (!(await allProjectsInOrg(env, orgId, input.projectIds))) return errorResponse('Resource not found.', 404);
  if (!canCreateSecret(context.actor, context.grants, input.projectIds[0])) return errorResponse('Not found', 404);
  const now = new Date().toISOString();
  const secret = { ...input, id: generateUUID(), orgId, createdAt: now, updatedAt: now, deletedAt: null };
  await smRepo.createSecret(env.DB, secret);
  await publishSecretChanged(env, orgId, secret.id);
  return jsonResponse(secretResponse(secret, await projectNames(env, orgId)));
}

export async function handleGetSecret(env: Env, userId: string, secretId: string): Promise<Response> {
  const secret = await smRepo.getSecret(env.DB, secretId);
  const context = secret && !secret.deletedAt && await smContext(env, userId, secret.orgId);
  if (!secret || !context) return errorResponse('Not found', 404);
  const access = secretAccess(context.actor, context.grants, secret);
  if (access === 'none') return errorResponse('Not found', 404);
  return jsonResponse(secretResponse(secret, await projectNames(env, secret.orgId), access));
}

export async function handleUpdateSecret(request: Request, env: Env, userId: string, secretId: string): Promise<Response> {
  const existing = await smRepo.getSecret(env.DB, secretId);
  const context = existing && !existing.deletedAt && await smContext(env, userId, existing.orgId);
  if (!existing || !context) return errorResponse('Not found', 404);
  const input = await secretInput(request);
  if (input instanceof Response) return input;
  if (!(await allProjectsInOrg(env, existing.orgId, input.projectIds))) return errorResponse('Resource not found.', 404);
  if (!canUpdateSecret(context.actor, context.grants, existing, input.projectIds)) return errorResponse('Not found', 404);
  const secret = { ...existing, ...input, updatedAt: new Date().toISOString() };
  if (!await smRepo.updateSecret(env.DB, secret, existing.projectIds)) return errorResponse('Not found', 404);
  await publishSecretChanged(env, secret.orgId, secret.id);
  return jsonResponse(secretResponse(secret, await projectNames(env, secret.orgId)));
}

export async function handleDeleteSecrets(request: Request, env: Env, userId: string): Promise<Response> {
  const ids = await readIds(request);
  if (!ids) return errorResponse('Request body must be an array of secret GUIDs', 400);
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const secrets = await smRepo.getSecretsByIds(env.DB, ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some(secret => secret.orgId !== orgId || secret.deletedAt)) return errorResponse('Not found', 404);
  const context = await smContext(env, userId, orgId);
  if (!context) return errorResponse('Not found', 404);
  const data = secrets.map(secret => ({ id: secret.id, error: secretAccess(context.actor, context.grants, secret) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  const allowed = data.filter(item => !item.error).map(item => item.id);
  await smRepo.deleteSecrets(env.DB, orgId, allowed);
  await Promise.all(allowed.map(id => publishSecretChanged(env, orgId, id)));
  return jsonResponse(listResponse(data));
}

export async function handleSecretsByIds(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await request.json().catch(() => null) as { ids?: unknown } | null;
  if (!Array.isArray(body?.ids) || !body.ids.every(isUUID)) return errorResponse('Ids must be an array of GUIDs.', 400);
  const ids = body.ids.map(id => id.toLowerCase());
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const secrets = await smRepo.getSecretsByIds(env.DB, ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some(secret => secret.orgId !== orgId || secret.deletedAt)) return errorResponse('Not found', 404);
  const context = await smContext(env, userId, orgId);
  if (!context || secrets.some(secret => secretAccess(context.actor, context.grants, secret) === 'none')) return errorResponse('Not found', 404);
  const names = await projectNames(env, orgId);
  return jsonResponse(listResponse(secrets.map(secret => secretResponse(secret, names, 'read', true))));
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

function serviceAccountResponse(account: smRepo.SmServiceAccount) {
  return { id: account.id, organizationId: account.orgId, name: account.name, creationDate: account.createdAt, revisionDate: account.updatedAt, object: 'serviceAccount' };
}

export async function handleListServiceAccounts(env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const counts = await smRepo.serviceAccountSecretCounts(env.DB, orgId);
  const accounts = (await smRepo.listServiceAccounts(env.DB, orgId)).filter(account => serviceAccountAccess(context.actor, context.grants, account.id) !== 'none');
  return jsonResponse(listResponse(accounts.map(account => ({ ...serviceAccountResponse(account), accessToSecrets: counts.get(account.id) ?? 0 }))));
}

export async function handleCreateServiceAccount(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const body = await request.json().catch(() => null) as { name?: unknown; projectIds?: unknown } | null;
  if (!encryptedField(body?.name, 1000)) return errorResponse('Name must be an encrypted string of at most 1000 characters.', 400);
  if (body.projectIds != null && (!Array.isArray(body.projectIds) || !body.projectIds.every(isUUID))) return errorResponse('ProjectIds must be an array of GUIDs.', 400);
  const projectIds = (body.projectIds as string[] | null | undefined)?.map(id => id.toLowerCase()) ?? [];
  if (!(await allProjectsInOrg(env, orgId, projectIds))) return errorResponse('Resource not found.', 404);
  if (projectIds.some(id => projectAccess(context.actor, context.grants, id) !== 'write')) return errorResponse('Not found', 404);
  const now = new Date().toISOString();
  const account = { id: generateUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo.createServiceAccount(env.DB, account, context.actor.membershipId, projectIds);
  return jsonResponse(serviceAccountResponse(account));
}

export async function handleServiceAccount(request: Request, env: Env, userId: string, id: string, counts = false): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, id);
  const context = account && await smContext(env, userId, account.orgId);
  if (!account || !context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const access = serviceAccountAccess(context.actor, context.grants, id);
  if (counts) return jsonResponse(await smRepo.serviceAccountCounts(env.DB, account, access));
  if (access === 'none') return errorResponse('Not found', 404);
  if (request.method === 'PUT') {
    const body = await request.json().catch(() => null) as { name?: unknown } | null;
    if (!encryptedField(body?.name, 1000)) return errorResponse('Name must be an encrypted string of at most 1000 characters.', 400);
    account.name = body.name; account.updatedAt = new Date().toISOString();
    if (!await smRepo.updateServiceAccount(env.DB, account)) return errorResponse('Not found', 404);
  }
  return jsonResponse(serviceAccountResponse(account));
}

export async function handleDeleteServiceAccounts(request: Request, env: Env, userId: string): Promise<Response> {
  const ids = await readIds(request);
  if (!ids) return errorResponse('Request body must be an array of GUIDs', 400);
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const accounts = await smRepo.getServiceAccountsByIds(env.DB, ids);
  const orgId = accounts[0]?.orgId;
  if (!orgId || accounts.length !== ids.length || accounts.some(account => account.orgId !== orgId)) return errorResponse('Not found', 404);
  const context = await smContext(env, userId, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const data = accounts.map(account => ({ id: account.id, error: serviceAccountAccess(context.actor, context.grants, account.id) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  await smRepo.deleteServiceAccounts(env.DB, orgId, data.filter(item => !item.error).map(item => item.id));
  return jsonResponse(listResponse(data));
}

export async function handleRevokeAccessTokens(request: Request, env: Env, userId: string, id: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, id);
  const context = account && await smContext(env, userId, account.orgId);
  if (!context || serviceAccountAccess(context.actor, context.grants, id) !== 'write') return errorResponse('Not found', 404);
  const body = await request.json().catch(() => null) as { ids?: unknown } | null;
  if (!Array.isArray(body?.ids) || !body.ids.every(isUUID)) return errorResponse('Ids must be an array of GUIDs.', 400);
  await smRepo.revokeAccessTokens(env.DB, id, body.ids.map(id => id.toLowerCase()));
  return new Response(null, { status: 200 });
}

export async function handleSmCounts(env: Env, userId: string, orgId: string): Promise<Response> {
  const context = await smContext(env, userId, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const [projects, secrets, accounts] = await Promise.all([smRepo.listProjects(env.DB, orgId), smRepo.listSecrets(env.DB, orgId), smRepo.listServiceAccounts(env.DB, orgId)]);
  return jsonResponse({ projects: projects.filter(row => projectAccess(context.actor, context.grants, row.id) !== 'none').length, secrets: secrets.filter(row => secretAccess(context.actor, context.grants, row) !== 'none').length, serviceAccounts: accounts.filter(row => serviceAccountAccess(context.actor, context.grants, row.id) !== 'none').length, object: 'organizationCounts' });
}

export async function handleCreateAccessToken(request: Request, env: Env, userId: string, serviceAccountId: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, serviceAccountId);
  if (!account) return errorResponse('Not found', 404);
  const context = await smContext(env, userId, account.orgId);
  if (!context || serviceAccountAccess(context.actor, context.grants, account.id) !== 'write') return errorResponse('Not found', 404);
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
  const context = await smContext(env, userId, account.orgId);
  if (!context || serviceAccountAccess(context.actor, context.grants, account.id) !== 'write') return errorResponse('Not found', 404);
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
