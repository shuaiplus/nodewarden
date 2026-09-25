import type { Env } from '../types';
import * as orgRepo from '../services/storage-org-repo';
import * as smRepo from '../services/storage-secret-repo';
import { canAccessSecretsManager, isActiveMember } from '../services/org-authz';
import { errorResponse, jsonResponse } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { hashApiKey, verifyApiKey } from '../utils/api-key';
import { publishSecretChanged } from '../services/queue-publisher';

async function requireSmMember(env: Env, userId: string, orgId: string) {
  const member = await orgRepo.getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member) || !canAccessSecretsManager(member)) return null;
  return member;
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
  secret.updatedAt = new Date().toISOString();
  await smRepo.saveSecret(env.DB, secret);
  await publishSecretChanged(env, secret.orgId, secret.id);
  return jsonResponse(secretResponse(secret));
}

export async function handleDeleteSecrets(request: Request, env: Env, userId: string): Promise<Response> {
  const body = await request.json() as { ids?: string[] };
  const ids = body.ids || [];
  const data = [];
  for (const id of ids) {
    const secret = await smRepo.getSecret(env.DB, id);
    if (!secret || !(await requireSmMember(env, userId, secret.orgId))) {
      data.push({ id, error: 'not found' });
      continue;
    }
    secret.deletedAt = new Date().toISOString();
    secret.updatedAt = secret.deletedAt;
    await smRepo.saveSecret(env.DB, secret);
    await publishSecretChanged(env, secret.orgId, secret.id);
    data.push({ id, error: null });
  }
  return jsonResponse({ data, object: 'list', continuationToken: null });
}

export async function handleListProjects(env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const projects = await smRepo.listProjects(env.DB, orgId);
  return jsonResponse({
    data: projects.map((project) => ({
      id: project.id,
      organizationId: project.orgId,
      name: project.name,
      creationDate: project.createdAt,
      revisionDate: project.updatedAt,
      object: 'project',
    })),
    object: 'list',
    continuationToken: null,
  });
}

export async function handleCreateProject(request: Request, env: Env, userId: string, orgId: string): Promise<Response> {
  if (!(await requireSmMember(env, userId, orgId))) return errorResponse('Not found', 404);
  const body = await request.json() as { name?: string };
  const now = new Date().toISOString();
  const project = { id: generateUUID(), orgId, name: String(body.name || 'Project'), createdAt: now, updatedAt: now };
  await smRepo.saveProject(env.DB, project);
  return jsonResponse({
    id: project.id,
    organizationId: project.orgId,
    name: project.name,
    creationDate: project.createdAt,
    revisionDate: project.updatedAt,
    object: 'project',
  });
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
  const now = new Date().toISOString();
  const account = { id: generateUUID(), orgId, name: String(body.name || 'Machine account'), createdAt: now, updatedAt: now };
  await smRepo.saveServiceAccount(env.DB, account);
  await smRepo.replaceServiceAccountProjects(env.DB, account.id, body.projectIds || []);
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
  const body = await request.json() as { name?: string; expireAt?: string | null; wrappedOrgKey?: string };
  const clientSecret = `nws_${generateUUID().replace(/-/g, '')}`;
  const token = {
    id: generateUUID(),
    serviceAccountId,
    name: String(body.name || 'Access token'),
    clientSecretHash: await hashApiKey(clientSecret),
    wrappedOrgKey: body.wrappedOrgKey || null,
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
): Promise<{ orgId: string; serviceAccountId: string; tokenId: string; wrappedOrgKey: string | null } | null> {
  const match = clientId.match(/^organization\.([a-f0-9-]+)\.sa\.([a-f0-9-]+)\.([a-f0-9-]+)$/i);
  if (!match) return null;
  const token = await smRepo.getAccessToken(env.DB, match[3]);
  if (!token || token.revokedAt) return null;
  if (token.expireAt && Date.parse(token.expireAt) < Date.now()) return null;
  if (!(await verifyApiKey(clientSecret, token.clientSecretHash))) return null;
  const account = await smRepo.getServiceAccount(env.DB, token.serviceAccountId);
  if (!account || account.orgId !== match[1]) return null;
  return { orgId: account.orgId, serviceAccountId: account.id, tokenId: token.id, wrappedOrgKey: token.wrappedOrgKey };
}

export async function handlePublicSecretsSync(request: Request, env: Env, orgId: string): Promise<Response> {
  const authorization = String(request.headers.get('Authorization') || '');
  const bearer = authorization.replace(/^Bearer\s+/i, '').trim();
  const [clientId, clientSecret] = bearer.includes('\n') ? bearer.split('\n') : bearer.split(':');
  const machine = await authenticateServiceAccount(env, String(clientId || '').trim(), String(clientSecret || '').trim());
  if (!machine || machine.orgId !== orgId) return errorResponse('Unauthorized', 401);
  return handleSecretsSync(request, env, orgId, machine.serviceAccountId, machine.wrappedOrgKey);
}

export async function handleSecretsSync(
  request: Request,
  env: Env,
  orgId: string,
  serviceAccountId: string,
  wrappedOrgKey: string | null
): Promise<Response> {
  const url = new URL(request.url);
  const lastSynced = url.searchParams.get('lastSyncedDate');
  const lastMs = lastSynced ? Date.parse(lastSynced) : 0;
  const projectIds = await smRepo.listServiceAccountProjectIds(env.DB, serviceAccountId);
  const secrets = (await smRepo.listSecrets(env.DB, orgId)).filter((secret) => {
    if (projectIds.length && !secret.projectIds.some((id) => projectIds.includes(id))) return false;
    return true;
  });
  const changed = !lastMs || secrets.some((secret) => Date.parse(secret.updatedAt) > lastMs);
  return jsonResponse({
    hasChanges: changed,
    wrappedOrgKey,
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
