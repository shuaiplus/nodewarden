import type { Principal } from '../services/auth';
import type { Env } from '../types';
import { MembershipStatus } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import * as smRepo from '../services/storage-secret-repo';
import { diffPolicies, parsePolicyRequests, projectAccess, secretAccess, serviceAccountAccess } from '../services/sm-authz';
import { errorResponse, jsonResponse } from '../utils/response';
import { listResponse, smContext } from './secrets-manager';
import { EventType, recordEvents, type EventInput } from '../services/events';

export async function peopleDirectory(env: Env, orgId: string, membershipId: string) {
  const [members, groups, ownGroups] = await Promise.all([
    orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId), orgRepo.listGroupsByOrg(env.DB, orgId),
    env.DB.prepare('SELECT g.id FROM org_groups g JOIN org_group_members gm ON gm.group_id = g.id WHERE g.org_id = ? AND gm.membership_id = ?').bind(orgId, membershipId).all<{ id: string }>(),
  ]);
  return { members, groups, ownGroups: new Set(ownGroups.results.map(row => row.id)) };
}

export async function handlePotentialPeople(env: Env, principal: Principal, orgId: string): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const membershipId = context.actor.membershipId;
  const { members, groups, ownGroups } = await peopleDirectory(env, orgId, membershipId);
  return jsonResponse(listResponse([
    ...members.filter(({ item }) => item.status === MembershipStatus.Confirmed).map(({ item, account }) => ({ id: item.id, name: account?.name || account?.email || item.email || '', email: account?.email || item.email, type: 'user', currentUser: item.id === membershipId, object: 'potentialGrantee' })),
    ...groups.map(group => ({ id: group.id, name: group.name, type: 'group', currentUserInGroup: ownGroups.has(group.id), object: 'potentialGrantee' })),
  ]));
}

export async function peoplePolicyResponse(env: Env, kind: smRepo.SmPeopleTarget, id: string, orgId: string, membershipId: string) {
  const [{ users, groups: policies }, directory] = await Promise.all([smRepo.readPeoplePolicies(env.DB, kind, id), peopleDirectory(env, orgId, membershipId)]);
  return {
    userAccessPolicies: directory.members.filter(({ item }) => users.has(item.id)).map(({ item, account }) => ({ organizationUserId: item.id, organizationUserName: account?.name || account?.email || item.email || '', currentUser: item.id === membershipId, read: true, write: users.get(item.id) === 'write', object: 'userAccessPolicy' })),
    groupAccessPolicies: directory.groups.filter(group => policies.has(group.id)).map(group => ({ groupId: group.id, groupName: group.name, currentUserInGroup: directory.ownGroups.has(group.id), read: true, write: policies.get(group.id) === 'write', object: 'groupAccessPolicy' })),
    object: kind === 'project' ? 'projectPeopleAccessPolicies' : kind === 'secret' ? 'secretAccessPolicies' : 'serviceAccountAccessPolicies',
  };
}

export async function handlePeoplePolicies(request: Request, env: Env, principal: Principal, kind: 'project' | 'serviceAccount', id: string): Promise<Response> {
  const row = kind === 'project' ? await smRepo.getProject(env.DB, id) : await smRepo.getServiceAccount(env.DB, id);
  const context = row && await smContext(env, principal, row.orgId);
  if (!row || !context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const access = kind === 'project' ? projectAccess(context.actor, context.grants, id) : serviceAccountAccess(context.actor, context.grants, id);
  if (access !== 'write') return errorResponse('Not found', 404);
  if (request.method === 'PUT') {
    const body = await request.json().catch(() => null) as Record<string, unknown> | null;
    if (!body || Array.isArray(body) || typeof body !== 'object') return errorResponse('Access policies must be an object.', 400);
    const users = parsePolicyRequests(body.userAccessPolicyRequests ?? [], 'granteeId', kind === 'serviceAccount');
    const groups = parsePolicyRequests(body.groupAccessPolicyRequests ?? [], 'granteeId', kind === 'serviceAccount');
    if (!users.ok) return errorResponse(users.message, 400);
    if (!groups.ok) return errorResponse(groups.message, 400);
    const directory = await peopleDirectory(env, row.orgId, context.actor.membershipId);
    const memberIds = new Set(directory.members.map(({ item }) => item.id));
    const groupIds = new Set(directory.groups.map(group => group.id));
    if ([...users.value.keys()].some(id => !memberIds.has(id)) || [...groups.value.keys()].some(id => !groupIds.has(id))) return errorResponse('Not found', 404);
    const current = await smRepo.replacePeoplePolicies(env.DB, kind, id, users.value, groups.value);
    if (kind === 'serviceAccount' && principal.kind === 'user') {
      const userChanges = diffPolicies(current.users, users.value);
      const groupChanges = diffPolicies(current.groups, groups.value);
      const events: EventInput[] = [
        ...userChanges.created.map(resourceId => ({ type: EventType.ServiceAccountUserAdded, resourceType: 'organizationUser' as const, resourceId })),
        ...userChanges.deleted.map(resourceId => ({ type: EventType.ServiceAccountUserRemoved, resourceType: 'organizationUser' as const, resourceId })),
        ...groupChanges.created.map(resourceId => ({ type: EventType.ServiceAccountGroupAdded, resourceType: 'group' as const, resourceId })),
        ...groupChanges.deleted.map(resourceId => ({ type: EventType.ServiceAccountGroupRemoved, resourceType: 'group' as const, resourceId })),
      ].map(event => ({ ...event, organizationId: row.orgId, grantedServiceAccountId: id,
        userId: event.resourceType === 'organizationUser' ? event.resourceId : undefined }));
      await recordEvents(env, request, { userId: principal.user.id }, events);
    }
  }
  return jsonResponse(await peoplePolicyResponse(env, kind, id, row.orgId, context.actor.membershipId));
}

export async function handlePotentialMachines(env: Env, principal: Principal, orgId: string, kind: 'projects' | 'serviceAccounts'): Promise<Response> {
  const context = await smContext(env, principal, orgId);
  if (!context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const rows = kind === 'projects' ? await smRepo.listProjects(env.DB, orgId) : await smRepo.listServiceAccounts(env.DB, orgId);
  const access = kind === 'projects' ? projectAccess : serviceAccountAccess;
  return jsonResponse(listResponse(rows.filter(row => access(context.actor, context.grants, row.id) === 'write').map(row => ({ id: row.id, name: row.name, type: kind === 'projects' ? 'project' : 'serviceAccount', object: 'potentialGrantee' }))));
}

export function policyConflict(error: unknown): Response | null {
  let cause: unknown = error;
  while (cause instanceof Error) {
    if (cause.message.includes('UNIQUE constraint failed: sm_')) return errorResponse('Access policy already exists.', 409);
    cause = cause.cause;
  }
  return null;
}

export async function handleMachinePolicies(request: Request, env: Env, principal: Principal, kind: 'project' | 'serviceAccount', id: string): Promise<Response> {
  const row = kind === 'project' ? await smRepo.getProject(env.DB, id) : await smRepo.getServiceAccount(env.DB, id);
  const context = row && await smContext(env, principal, row.orgId);
  if (!row || !context || context.actor.kind === 'serviceAccount') return errorResponse('Not found', 404);
  const access = kind === 'project' ? projectAccess(context.actor, context.grants, id) : serviceAccountAccess(context.actor, context.grants, id);
  if (access !== 'write') return errorResponse('Not found', 404);
  let policies = kind === 'project' ? await smRepo.readProjectMachinePolicies(env.DB, row.orgId, id) : await smRepo.readGrantedProjects(env.DB, row.orgId, id);
  if (request.method === 'PUT') {
    const body = await request.json().catch(() => null) as Record<string, unknown> | null;
    const parsed = parsePolicyRequests(body?.[kind === 'project' ? 'serviceAccountAccessPolicyRequests' : 'projectGrantedPolicyRequests'], kind === 'project' ? 'granteeId' : 'grantedId', false);
    if (!parsed.ok) return errorResponse(parsed.message, 400);
    const current = new Map(policies.map(policy => [policy.id, policy.write_access ? 'write' as const : 'read' as const]));
    const { created, updated, deleted } = diffPolicies(current, parsed.value);
    const known = kind === 'project' ? new Set((await smRepo.listServiceAccounts(env.DB, row.orgId)).map(account => account.id)) : await smRepo.projectsInOrg(env.DB, row.orgId, [...parsed.value.keys()]);
    if ([...parsed.value.keys()].some(id => !known.has(id))) return errorResponse('Not found', 404);
    if (kind === 'project' ? created.some(id => serviceAccountAccess(context.actor, context.grants, id) !== 'write') : [...created, ...updated, ...deleted].some(id => projectAccess(context.actor, context.grants, id) !== 'write')) return errorResponse('Not found', 404);
    try {
      await env.DB.batch([...smRepo.policyDiffStatements(env.DB, kind === 'project' ? 'projectServiceAccounts' : 'serviceAccountProjects', id, current, parsed.value), smRepo.revisionStatement(env.DB, row.orgId)]);
    } catch (error) {
      const conflict = policyConflict(error);
      if (conflict) return conflict;
      throw error;
    }
    policies = kind === 'project' ? await smRepo.readProjectMachinePolicies(env.DB, row.orgId, id) : await smRepo.readGrantedProjects(env.DB, row.orgId, id);
  }
  return jsonResponse(kind === 'project' ? {
    serviceAccountAccessPolicies: policies.map(policy => ({ serviceAccountId: policy.id, serviceAccountName: policy.name, read: true, write: !!policy.write_access, object: 'serviceAccountProjectAccessPolicy' })), object: 'ProjectServiceAccountsAccessPolicies',
  } : {
    grantedProjectPolicies: policies.map(policy => ({ accessPolicy: { grantedProjectId: policy.id, grantedProjectName: policy.name, read: true, write: !!policy.write_access, object: 'grantedProjectAccessPolicy' }, hasPermission: projectAccess(context.actor, context.grants, policy.id) === 'write', object: 'grantedProjectAccessPolicyPermissionDetails' })), object: 'ServiceAccountGrantedPoliciesPermissionDetails',
  });
}

export async function prepareSecretPolicies(env: Env, context: NonNullable<Awaited<ReturnType<typeof smContext>>>, orgId: string, secretId: string, input: unknown, creating: boolean): Promise<D1PreparedStatement[] | Response> {
  if (input == null) return [];
  if (!input || typeof input !== 'object' || Array.isArray(input)) return errorResponse('Access policies must be an object.', 400);
  const body = input as Record<string, unknown>;
  const users = parsePolicyRequests(body.userAccessPolicyRequests, 'granteeId', false);
  const groups = parsePolicyRequests(body.groupAccessPolicyRequests, 'granteeId', false);
  const accounts = parsePolicyRequests(body.serviceAccountAccessPolicyRequests, 'granteeId', false);
  if (!users.ok) return errorResponse(users.message, 400);
  if (!groups.ok) return errorResponse(groups.message, 400);
  if (!accounts.ok) return errorResponse(accounts.message, 400);
  if (context.actor.kind === 'serviceAccount') return users.value.size || groups.value.size || accounts.value.size ? errorResponse('Not found', 404) : [];
  const directory = await peopleDirectory(env, orgId, context.actor.membershipId);
  const members = new Set(directory.members.map(({ item }) => item.id));
  const groupIds = new Set(directory.groups.map(group => group.id));
  const machines = new Set((await smRepo.listServiceAccounts(env.DB, orgId)).map(account => account.id));
  if ([...users.value.keys()].some(id => !members.has(id)) || [...groups.value.keys()].some(id => !groupIds.has(id)) || [...accounts.value.keys()].some(id => !machines.has(id))) return errorResponse('Not found', 404);
  const current = creating ? { users: new Map(), groups: new Map() } : await smRepo.readPeoplePolicies(env.DB, 'secret', secretId);
  const currentAccounts = new Map((creating ? [] : await smRepo.readSecretMachinePolicies(env.DB, orgId, secretId)).map(policy => [policy.id, policy.write_access ? 'write' as const : 'read' as const]));
  if (diffPolicies(currentAccounts, accounts.value).created.some(id => serviceAccountAccess(context.actor, context.grants, id) !== 'write')) return errorResponse('Not found', 404);
  return [
    ...smRepo.policyDiffStatements(env.DB, 'secretMembers', secretId, current.users, users.value),
    ...smRepo.policyDiffStatements(env.DB, 'secretGroups', secretId, current.groups, groups.value),
    ...smRepo.policyDiffStatements(env.DB, 'secretServiceAccounts', secretId, currentAccounts, accounts.value),
  ];
}

export async function handleSecretPolicies(env: Env, principal: Principal, id: string): Promise<Response> {
  const secret = await smRepo.getSecret(env.DB, id);
  const context = secret && !secret.deletedAt && await smContext(env, principal, secret.orgId);
  if (!secret || !context || context.actor.kind === 'serviceAccount' || secretAccess(context.actor, context.grants, secret) !== 'write') return errorResponse('Not found', 404);
  const people = await peoplePolicyResponse(env, 'secret', id, secret.orgId, context.actor.membershipId);
  const accounts = await smRepo.readSecretMachinePolicies(env.DB, secret.orgId, id);
  return jsonResponse({ ...people, serviceAccountAccessPolicies: accounts.map(policy => ({ serviceAccountId: policy.id, serviceAccountName: policy.name, read: true, write: !!policy.write_access, object: 'serviceAccountProjectAccessPolicy' })) });
}
