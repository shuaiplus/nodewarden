import { z } from 'zod';
import type { Principal } from '../services/auth';
import { LIMITS } from '../config/limits';
import { policyConflict, prepareSecretPolicies } from './sm-access-policies';
import { isSerializedEncString } from '../utils/account-passkeys';
import { projectAccess, serviceAccountAccess, secretAccess, canCreateSecret, canUpdateSecret, resolveSmActor, type SmAccess } from '../services/sm-authz';
import type { Env } from '../types';
import * as smRepo from '../services/storage-secret-repo';
import { errorResponse, jsonResponse, parseBody } from '../utils/response';
import { generateUUID } from '../utils/uuid';
import { hashApiKey, randomStringAlphanum } from '../utils/api-key';
import { publishSecretChanged } from '../services/queue-publisher';
import { EventType, listEventsResponse, recordEvents } from '../services/events';
import { canAccessEventLogs, isActiveMember } from '../services/org-authz';
import { MembershipType } from '../services/org-types';
import { getMembershipByUserAndOrg } from '../services/storage-org-repo';

// SM names, keys, values and notes stay client ciphertext: each must be a serialized EncString.
const encrypted = (max: number, error: string) => z.string({ error }).refine(value => value.length <= max && isSerializedEncString(value), { error });
const guids = (error: string) => z.array(z.guid({ error }), { error }).transform(ids => ids.map(id => id.toLowerCase()));
const NAME_ERROR = 'Name must be an encrypted string of at most 1000 characters.';
const NameBody = z.object({ name: encrypted(1000, NAME_ERROR) }, { error: NAME_ERROR });
const IDS_ERROR = 'Ids must be an array of GUIDs.';
const IdsBody = z.object({ ids: guids(IDS_ERROR) }, { error: IDS_ERROR });

// The grant lists stay unknown here because parsePolicyRequests owns their messages.
export const PolicyRequests = z.record(z.string(), z.unknown(), { error: 'Access policies must be an object.' });

const SECRET_ERROR = 'Key, value and note must be encrypted strings within their size limits.';
const SecretBody = z.object({
  key: encrypted(1000, SECRET_ERROR), value: encrypted(35000, SECRET_ERROR), note: encrypted(10000, SECRET_ERROR),
  projectIds: guids('ProjectIds must be an array of GUIDs.').nullish().transform(ids => ids ?? []),
  accessPoliciesRequests: PolicyRequests.nullish(),
}, { error: SECRET_ERROR });

const TOKEN_ERROR = 'Name, encryptedPayload and key must be encrypted strings within their size limits.';
const EXPIRE_ERROR = 'ExpireAt must be in the future.';
const AccessTokenBody = z.object({
  name: encrypted(200, TOKEN_ERROR), encryptedPayload: encrypted(4000, TOKEN_ERROR), key: encrypted(Infinity, TOKEN_ERROR),
  expireAt: z.string({ error: EXPIRE_ERROR }).refine(value => Date.parse(value) > Date.now(), { error: EXPIRE_ERROR })
    .transform(value => new Date(value).toISOString()).nullish(),
}, { error: TOKEN_ERROR });

function eventActor(principal: Principal) {
  return principal.kind === 'user' ? { userId: principal.user.id } : { serviceAccountId: principal.serviceAccountId };
}

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

export async function handleListSecrets(env: Env, principal: Principal, orgId: string, projectId?: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  const secrets = (await smRepo.listSecrets(env.DB, orgId)).filter(secret => !projectId || secret.projectIds.includes(projectId));
  return jsonResponse(await secretsListResponse(env, orgId, secrets, context));
}

export async function handleProjectSecrets(env: Env, principal: Principal, id: string): Promise<Response> {
  const project = await smRepo.getProject(env.DB, id);
  return project ? handleListSecrets(env, principal, project.orgId, id) : errorResponse('Not found', 404);
}

async function secretInput(request: Request) {
  const input = await parseBody(request, SecretBody, SECRET_ERROR);
  if (input instanceof Response || input.projectIds.length <= 1) return input;
  return errorResponse('Only one project assignment is supported.', 400, {}, { ProjectIds: ['Only one project assignment is supported.'] });
}

export async function handleCreateSecret(request: Request, env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  const input = await secretInput(request);
  if (input instanceof Response) return input;
  if (!(await allProjectsInOrg(env, orgId, input.projectIds))) return errorResponse('Resource not found.', 404);
  if (!canCreateSecret(context.actor, context.grants, input.projectIds[0])) return errorResponse('Not found', 404);
  const now = new Date().toISOString();
  const secret = { ...input, id: generateUUID(), orgId, createdAt: now, updatedAt: now, deletedAt: null };
  const policies = await prepareSecretPolicies(env, context, orgId, secret.id, input.accessPoliciesRequests, true);
  if (policies instanceof Response) return policies;
  try { await smRepo.createSecret(env.DB, secret, policies); }
  catch (error) { const conflict = policyConflict(error); if (conflict) return conflict; throw error; }
  await recordEvents(env, request, eventActor(principal), [{ organizationId: orgId, type: EventType.SecretCreated, resourceType: 'secret', resourceId: secret.id }]);
  await publishSecretChanged(env, orgId, secret.id);
  return jsonResponse(secretResponse(secret, await projectNames(env, orgId)));
}

export async function handleGetSecret(request: Request, env: Env, principal: Principal, secretId: string): Promise<Response> {
  const secret = await smRepo.getSecret(env.DB, secretId);
  const context = secret && !secret.deletedAt && await smContext(env, principal, secret.orgId);
  if (!secret || !context) return errorResponse('Not found', 404);
  const access = secretAccess(context.actor, context.grants, secret);
  if (access === 'none') return errorResponse('Not found', 404);
  await recordEvents(env, request, eventActor(principal), [{ organizationId: secret.orgId, type: EventType.SecretRetrieved, resourceType: 'secret', resourceId: secret.id }]);
  return jsonResponse(secretResponse(secret, await projectNames(env, secret.orgId), access));
}

export async function handleUpdateSecret(request: Request, env: Env, principal: Principal, secretId: string): Promise<Response> {
  const existing = await smRepo.getSecret(env.DB, secretId);
  const context = existing && !existing.deletedAt && await smContext(env, principal, existing.orgId);
  if (!existing || !context) return errorResponse('Not found', 404);
  const input = await secretInput(request);
  if (input instanceof Response) return input;
  if (!(await allProjectsInOrg(env, existing.orgId, input.projectIds))) return errorResponse('Resource not found.', 404);
  if (!canUpdateSecret(context.actor, context.grants, existing, input.projectIds)) return errorResponse('Not found', 404);
  const secret = { ...existing, ...input, updatedAt: new Date().toISOString() };
  const policies = await prepareSecretPolicies(env, context, secret.orgId, secret.id, input.accessPoliciesRequests, false);
  if (policies instanceof Response) return policies;
  try {
    if (!await smRepo.updateSecret(env.DB, secret, existing.projectIds, existing.updatedAt, policies)) return errorResponse('Not found', 404);
  } catch (error) { const conflict = policyConflict(error); if (conflict) return conflict; throw error; }
  await recordEvents(env, request, eventActor(principal), [{ organizationId: secret.orgId, type: EventType.SecretEdited, resourceType: 'secret', resourceId: secret.id }]);
  await publishSecretChanged(env, secret.orgId, secret.id);
  return jsonResponse(secretResponse(secret, await projectNames(env, secret.orgId)));
}

export async function handleDeleteSecrets(request: Request, env: Env, principal: Principal): Promise<Response> {
  const ids = await readIds(request, 'Request body must be an array of secret GUIDs');
  if (ids instanceof Response) return ids;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const secrets = await smRepo.getSecretsByIds(env.DB, ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some(secret => secret.orgId !== orgId || secret.deletedAt)) return errorResponse('Not found', 404);
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  const data = secrets.map(secret => ({ id: secret.id, error: secretAccess(context.actor, context.grants, secret) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  const allowed = data.filter(item => !item.error).map(item => item.id);
  const changed = await smRepo.deleteSecrets(env.DB, orgId, allowed);
  await recordEvents(env, request, eventActor(principal), changed.map(resourceId => ({ organizationId: orgId, type: EventType.SecretDeleted, resourceType: 'secret', resourceId })));
  await Promise.all(allowed.map(id => publishSecretChanged(env, orgId, id)));
  return jsonResponse(listResponse(data));
}

export async function handleSecretsByIds(request: Request, env: Env, principal: Principal): Promise<Response> {
  const body = await parseBody(request, IdsBody, IDS_ERROR);
  if (body instanceof Response) return body;
  const { ids } = body;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const secrets = await smRepo.getSecretsByIds(env.DB, ids);
  const orgId = secrets[0]?.orgId;
  if (!orgId || secrets.length !== ids.length || secrets.some(secret => secret.orgId !== orgId || secret.deletedAt)) return errorResponse('Not found', 404);
  const context = await smContext(env, principal, orgId);
  if (!context || secrets.some(secret => secretAccess(context.actor, context.grants, secret) === 'none')) return errorResponse('Not found', 404);
  const names = await projectNames(env, orgId);
  await recordEvents(env, request, eventActor(principal), secrets.map(secret => ({ organizationId: orgId, type: EventType.SecretRetrieved, resourceType: 'secret', resourceId: secret.id })));
  return jsonResponse(listResponse(secrets.map(secret => secretResponse(secret, names, 'read', true))));
}

export async function smContext(env: Env, principal: Principal, orgId: string) {
  const actor = await resolveSmActor(env, principal, orgId);
  return actor ? { actor, grants: await smRepo.loadSmGrants(env.DB, actor, orgId) } : null;
}

export function listResponse<T>(data: T[]) { return { data, object: 'list', continuationToken: null }; }

function projectResponse(project: smRepo.SmProject, level: SmAccess) {
  return { id: project.id, organizationId: project.orgId, name: project.name, creationDate: project.createdAt, revisionDate: project.updatedAt, read: level !== 'none', write: level === 'write', object: 'project' };
}

function readIds(request: Request, message: string) {
  return parseBody(request, guids(message), message);
}

export async function handleListProjects(env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  // ponytail: in-memory filter loads every org row; push grants into SQL if an org passes ~10k secrets.
  const projects = (await smRepo.listProjects(env.DB, orgId)).map(project => projectResponse(project, projectAccess(context.actor, context.grants, project.id))).filter(project => project.read);
  return jsonResponse(listResponse(projects));
}

export async function handleCreateProject(request: Request, env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  const body = await parseBody(request, NameBody, NAME_ERROR);
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const project = { id: generateUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo.createProject(env.DB, project, context.actor);
  await recordEvents(env, request, eventActor(principal), [{ organizationId: orgId, type: EventType.ProjectCreated, resourceType: 'project', resourceId: project.id }]);
  return jsonResponse(projectResponse(project, 'write'));
}

export async function handleProject(request: Request, env: Env, principal: Principal, id: string, counts = false): Promise<Response> {
  const project = await smRepo.getProject(env.DB, id);
  const context = project && await smContext(env, principal, project.orgId);
  if (!project || !context) return errorResponse('Not found', 404);
  const access = projectAccess(context.actor, context.grants, id);
  if (counts) return context.actor.kind === 'serviceAccount' ? errorResponse('Not found', 404) : jsonResponse(await smRepo.projectCounts(env.DB, project, access));
  if (access === 'none' || (request.method === 'PUT' && access !== 'write')) return errorResponse('Not found', 404);
  if (request.method === 'PUT') {
    const body = await parseBody(request, NameBody, NAME_ERROR);
    if (body instanceof Response) return body;
    project.name = body.name; project.updatedAt = new Date().toISOString();
    if (!await smRepo.updateProject(env.DB, project)) return errorResponse('Not found', 404);
  }
  await recordEvents(env, request, eventActor(principal), [{ organizationId: project.orgId, type: request.method === 'PUT' ? EventType.ProjectEdited : EventType.ProjectRetrieved, resourceType: 'project', resourceId: id }]);
  return jsonResponse(projectResponse(project, access));
}

export async function handleDeleteProjects(request: Request, env: Env, principal: Principal): Promise<Response> {
  const ids = await readIds(request, 'Request body must be an array of GUIDs');
  if (ids instanceof Response) return ids;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const projects = await smRepo.getProjectsByIds(env.DB, ids);
  const orgId = projects[0]?.orgId;
  if (!orgId || projects.length !== ids.length || projects.some(project => project.orgId !== orgId)) return errorResponse('Not found', 404);
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  const data = ids.map(id => ({ id, error: projectAccess(context.actor, context.grants, id) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  const changed = await smRepo.deleteProjects(env.DB, orgId, data.filter(item => !item.error).map(item => item.id));
  await recordEvents(env, request, eventActor(principal), changed.map(resourceId => ({ organizationId: orgId, type: EventType.ProjectDeleted, resourceType: 'project', resourceId })));
  return jsonResponse(listResponse(data));
}

function serviceAccountResponse(account: smRepo.SmServiceAccount) {
  return { id: account.id, organizationId: account.orgId, name: account.name, creationDate: account.createdAt, revisionDate: account.updatedAt, object: 'serviceAccount' };
}

export async function handleListServiceAccounts(env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const counts = await smRepo.serviceAccountSecretCounts(env.DB, orgId);
  const accounts = (await smRepo.listServiceAccounts(env.DB, orgId)).filter(account => serviceAccountAccess(context.actor, context.grants, account.id) !== 'none');
  return jsonResponse(listResponse(accounts.map(account => ({ ...serviceAccountResponse(account), accessToSecrets: counts.get(account.id) ?? 0 }))));
}

export async function handleCreateServiceAccount(request: Request, env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const body = await parseBody(request, NameBody, NAME_ERROR);
  if (body instanceof Response) return body;
  const now = new Date().toISOString();
  const account = { id: generateUUID(), orgId, name: body.name, createdAt: now, updatedAt: now };
  await smRepo.createServiceAccount(env.DB, account, context.actor.membershipId);
  await recordEvents(env, request, eventActor(principal), [
    { organizationId: orgId, type: EventType.ServiceAccountCreated, grantedServiceAccountId: account.id },
    { organizationId: orgId, type: EventType.ServiceAccountUserAdded, grantedServiceAccountId: account.id, resourceType: 'organizationUser', resourceId: context.actor.membershipId, userId: context.actor.membershipId },
  ]);
  return jsonResponse(serviceAccountResponse(account));
}

export async function handleServiceAccount(request: Request, env: Env, principal: Principal, id: string, counts = false): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, id);
  const context = account && await smContext(env, principal, account.orgId);
  if (!account || !context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const access = serviceAccountAccess(context.actor, context.grants, id);
  if (counts) return jsonResponse(await smRepo.serviceAccountCounts(env.DB, account, access));
  if (access === 'none') return errorResponse('Not found', 404);
  if (request.method === 'PUT') {
    const body = await parseBody(request, NameBody, NAME_ERROR);
    if (body instanceof Response) return body;
    account.name = body.name; account.updatedAt = new Date().toISOString();
    if (!await smRepo.updateServiceAccount(env.DB, account)) return errorResponse('Not found', 404);
  }
  return jsonResponse(serviceAccountResponse(account));
}

export async function handleDeleteServiceAccounts(request: Request, env: Env, principal: Principal): Promise<Response> {
  const ids = await readIds(request, 'Request body must be an array of GUIDs');
  if (ids instanceof Response) return ids;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const accounts = await smRepo.getServiceAccountsByIds(env.DB, ids);
  const orgId = accounts[0]?.orgId;
  if (!orgId || accounts.length !== ids.length || accounts.some(account => account.orgId !== orgId)) return errorResponse('Not found', 404);
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const data = accounts.map(account => ({ id: account.id, error: serviceAccountAccess(context.actor, context.grants, account.id) === 'write' ? null : 'access denied', object: 'BulkDeleteResponseModel' }));
  const changed = await smRepo.deleteServiceAccounts(env.DB, orgId, data.filter(item => !item.error).map(item => item.id));
  await recordEvents(env, request, eventActor(principal), changed.map(grantedServiceAccountId => ({ organizationId: orgId, type: EventType.ServiceAccountDeleted, grantedServiceAccountId })));
  return jsonResponse(listResponse(data));
}

export async function handleRevokeAccessTokens(request: Request, env: Env, principal: Principal, id: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, id);
  const context = account && await smContext(env, principal, account.orgId);
  if (!context || serviceAccountAccess(context.actor, context.grants, id) !== 'write') return errorResponse('Not found', 404);
  const body = await parseBody(request, IdsBody, IDS_ERROR);
  if (body instanceof Response) return body;
  await smRepo.revokeAccessTokens(env.DB, id, body.ids);
  return new Response(null, { status: 200 });
}

export async function handleSmCounts(env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const [projects, secrets, accounts] = await Promise.all([smRepo.listProjects(env.DB, orgId), smRepo.listSecrets(env.DB, orgId), smRepo.listServiceAccounts(env.DB, orgId)]);
  return jsonResponse({ projects: projects.filter(row => projectAccess(context.actor, context.grants, row.id) !== 'none').length, secrets: secrets.filter(row => secretAccess(context.actor, context.grants, row) !== 'none').length, serviceAccounts: accounts.filter(row => serviceAccountAccess(context.actor, context.grants, row.id) !== 'none').length, object: 'organizationCounts' });
}

export async function handleCreateAccessToken(request: Request, env: Env, principal: Principal, serviceAccountId: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, serviceAccountId);
  const context = account && await smContext(env, principal, account.orgId);
  if (!account || !context || serviceAccountAccess(context.actor, context.grants, account.id) !== 'write') return errorResponse('Not found', 404);
  const body = await parseBody(request, AccessTokenBody, TOKEN_ERROR);
  if (body instanceof Response) return body;
  const clientSecret = randomStringAlphanum(LIMITS.auth.clientSecretLength);
  const token = { id: generateUUID(), serviceAccountId, name: body.name, encryptedPayload: body.encryptedPayload, key: body.key, clientSecretHash: await hashApiKey(clientSecret), expireAt: body.expireAt ?? null, revokedAt: null, createdAt: new Date().toISOString() };
  await smRepo.saveAccessToken(env.DB, token);
  return jsonResponse({ id: token.id, name: token.name, clientSecret, expireAt: token.expireAt, creationDate: token.createdAt, revisionDate: token.createdAt, object: 'accessTokenCreation' });
}

export async function handleListAccessTokens(env: Env, principal: Principal, serviceAccountId: string): Promise<Response> {
  const account = await smRepo.getServiceAccount(env.DB, serviceAccountId);
  const context = account && await smContext(env, principal, account.orgId);
  if (!context || serviceAccountAccess(context.actor, context.grants, serviceAccountId) !== 'write') return errorResponse('Not found', 404);
  const tokens = await smRepo.listAccessTokens(env.DB, serviceAccountId);
  return jsonResponse(listResponse(tokens.map(token => ({ id: token.id, name: token.name, scopes: ['api.secrets'], expireAt: token.expireAt, creationDate: token.createdAt, revisionDate: token.createdAt, object: 'accessToken' }))));
}

export async function handleSmEvents(request: Request, env: Env, principal: Principal, kind: 'projects' | 'secrets' | 'service-account', id: string, orgId?: string): Promise<Response> {
  if (principal.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const row = kind === 'projects' ? await smRepo.getProject(env.DB, id) : kind === 'secrets' ? await smRepo.getSecret(env.DB, id) : await smRepo.getServiceAccount(env.DB, id);
  if (orgId) {
    if (row && row.orgId !== orgId) return errorResponse('Not found', 404);
    const member = await getMembershipByUserAndOrg(env.DB, principal.user.id, orgId);
    // Upstream answers NotFound here too; official web treats 403 as a revoked token and logs out.
    if (!isActiveMember(member) || !canAccessEventLogs(member)) return errorResponse('Not found', 404);
    if (kind === 'secrets') {
      if (!row || ('deletedAt' in row && row.deletedAt)) {
        if (member.type !== MembershipType.Owner && member.type !== MembershipType.Admin) return errorResponse('Not found', 404);
      } else {
        const context = await smContext(env, principal, orgId);
        if (!context || !('projectIds' in row) || secretAccess(context.actor, context.grants, row) === 'none') return errorResponse('Not found', 404);
      }
    }
  } else {
    if (!row) return errorResponse('Not found', 404);
    orgId = row.orgId;
    const context = await smContext(env, principal, orgId);
    if (!context || serviceAccountAccess(context.actor, context.grants, id) === 'none') return errorResponse('Not found', 404);
  }
  return listEventsResponse(request, env, kind === 'service-account'
    ? { organizationId: orgId, serviceAccountId: id }
    : { organizationId: orgId, resourceType: kind === 'secrets' ? 'secret' : 'project', resourceId: id });
}

export async function handleSecretsSync(request: Request, env: Env, principal: Principal, orgId: string): Promise<Response> {
  const lastSyncedDate = new URL(request.url).searchParams.get('lastSyncedDate');
  const lastSynced = lastSyncedDate === null ? null : Date.parse(lastSyncedDate);
  if (lastSynced !== null && (!Number.isFinite(lastSynced) || lastSynced > Date.now())) return errorResponse('LastSyncedDate must be a valid date in the past.', 400);
  const context = await smContext(env, principal, orgId);
  if (!context) return errorResponse('Not found', 404);
  if (context.actor.kind !== 'serviceAccount') return errorResponse('Only service accounts can sync secrets.', 400);
  const account = await smRepo.getServiceAccount(env.DB, context.actor.serviceAccountId);
  if (!account) return errorResponse('Not found', 404);
  const hasChanges = lastSynced === null || lastSynced <= Date.parse(account.updatedAt);
  if (!hasChanges) return jsonResponse({ hasChanges, secrets: null, object: 'secretsSync' });
  const names = await projectNames(env, orgId);
  const secrets = (await smRepo.listSecrets(env.DB, orgId)).filter(secret => secretAccess(context.actor, context.grants, secret) !== 'none');
  await recordEvents(env, request, eventActor(principal), secrets.map(secret => ({ organizationId: orgId, type: EventType.SecretRetrieved, resourceType: 'secret', resourceId: secret.id })));
  return jsonResponse({ hasChanges, secrets: listResponse(secrets.map(secret => secretResponse(secret, names, 'read', true))), object: 'secretsSync' });
}

export async function handleSecretsTrash(request: Request, env: Env, principal: Principal, orgId: string, action?: 'empty' | 'restore'): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind !== 'admin') return errorResponse('Not found', 404);
  if (!action) return jsonResponse(await secretsListResponse(env, orgId, (await smRepo.listSecrets(env.DB, orgId, true)).filter(secret => !!secret.deletedAt), context));
  const ids = await readIds(request, 'Request body must be an array of GUIDs');
  if (ids instanceof Response) return ids;
  if (!ids.length || new Set(ids).size !== ids.length) return errorResponse('Not found', 404);
  const secrets = await smRepo.getSecretsByIds(env.DB, ids);
  if (secrets.length !== ids.length || secrets.some(secret => secret.orgId !== orgId || !secret.deletedAt)) return errorResponse('Not found', 404);
  const changed = await smRepo.changeSecretsTrash(env.DB, orgId, ids, action === 'restore');
  await recordEvents(env, request, eventActor(principal), changed.map(resourceId => ({ organizationId: orgId, type: action === 'restore' ? EventType.SecretRestored : EventType.SecretPermanentlyDeleted, resourceType: 'secret', resourceId })));
  await Promise.all(ids.map(id => publishSecretChanged(env, orgId, id)));
  return new Response(null, { status: 200 });
}
