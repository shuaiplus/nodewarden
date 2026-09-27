import type { Principal } from './services/auth';
import { handleMachinePolicies, handlePotentialMachines, handleSecretPolicies, handlePeoplePolicies, handlePotentialPeople } from './handlers/sm-access-policies';
import type { Env } from './types';
import { errorResponse } from './utils/response';
import {
  handleCreateAccessToken,
  handleCreateProject,
  handleProject,
  handleDeleteProjects,
  handleCreateSecret,
  handleCreateServiceAccount,
  handleServiceAccount,
  handleDeleteServiceAccounts,
  handleRevokeAccessTokens,
  handleSmCounts,
  handleSmEvents,
  handleDeleteSecrets,
  handleGetSecret,
  handleProjectSecrets,
  handleSecretsByIds,
  handleListAccessTokens,
  handleListProjects,
  handleListSecrets,
  handleListServiceAccounts,
  handleUpdateSecret,
  handleSecretsSync,
  handleSecretsTrash,
} from './handlers/secrets-manager';

export async function handleSmRoute(request: Request, env: Env, principal: Principal, path: string, method: string): Promise<Response | null> {
  path = path.toLowerCase();
  const trash = path.match(/^\/api\/secrets\/([a-f0-9-]+)\/trash(?:\/(empty|restore))?$/i);
  if (trash && ((!trash[2] && method === 'GET') || (trash[2] && method === 'POST'))) return handleSecretsTrash(request, env, principal, trash[1], trash[2] as 'empty' | 'restore' | undefined);
  const secretPolicies = path.match(/^\/api\/secrets\/([a-f0-9-]+)\/access-policies$/i);
  if (secretPolicies && method === 'GET') return handleSecretPolicies(env, principal, secretPolicies[1]);
  const machinePolicies = path.match(/^\/api\/projects\/([a-f0-9-]+)\/access-policies\/service-accounts$/i);
  if (machinePolicies && (method === 'GET' || method === 'PUT')) return handleMachinePolicies(request, env, principal, 'project', machinePolicies[1]);
  const granted = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)\/granted-policies$/i);
  if (granted && (method === 'GET' || method === 'PUT')) return handleMachinePolicies(request, env, principal, 'serviceAccount', granted[1]);
  const people = path.match(/^\/api\/(projects|service-accounts)\/([a-f0-9-]+)\/access-policies\/people$/i);
  if (people && (method === 'GET' || method === 'PUT')) return handlePeoplePolicies(request, env, principal, people[1] === 'projects' ? 'project' : 'serviceAccount', people[2]);
  const event = path.match(/^\/api\/organization\/([a-f0-9-]+)\/(projects|secrets|service-account)\/([a-f0-9-]+)\/events$/i);
  if (event && method === 'GET') return handleSmEvents(request, env, principal, event[2] as 'projects' | 'secrets' | 'service-account', event[3], event[1]);
  const accountEvent = path.match(/^\/api\/sm\/events\/service-accounts\/([a-f0-9-]+)$/i);
  if (accountEvent && method === 'GET') return handleSmEvents(request, env, principal, 'service-account', accountEvent[1]);
  if (path === '/api/service-accounts/delete' && method === 'POST') return handleDeleteServiceAccounts(request, env, principal);
  const account = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)(\/sm-counts)?$/i);
  if (account && (method === 'GET' || (!account[2] && method === 'PUT'))) return handleServiceAccount(request, env, principal, account[1], !!account[2]);
  const revoke = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)\/access-tokens\/revoke$/i);
  if (revoke && method === 'POST') return handleRevokeAccessTokens(request, env, principal, revoke[1]);
  if (path === '/api/projects/delete' && method === 'POST') return handleDeleteProjects(request, env, principal);
  if (path === '/api/secrets/get-by-ids' && method === 'POST') return handleSecretsByIds(request, env, principal);
  const projectSecrets = path.match(/^\/api\/projects\/([a-f0-9-]+)\/secrets$/i);
  if (projectSecrets && method === 'GET') return handleProjectSecrets(env, principal, projectSecrets[1]);
  const project = path.match(/^\/api\/projects\/([a-f0-9-]+)(\/sm-counts)?$/i);
  if (project && (method === 'GET' || (!project[2] && method === 'PUT'))) return handleProject(request, env, principal, project[1], !!project[2]);
  if (path === '/api/secrets/delete' && method === 'POST') return handleDeleteSecrets(request, env, principal);

  const secretMatch = path.match(/^\/api\/secrets\/([a-f0-9-]+)$/i);
  if (secretMatch) {
    if (method === 'GET') return handleGetSecret(request, env, principal, secretMatch[1]);
    if (method === 'PUT') return handleUpdateSecret(request, env, principal, secretMatch[1]);
  }

  const saTokenMatch = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)\/access-tokens$/i);
  if (saTokenMatch) {
    if (method === 'GET') return handleListAccessTokens(env, principal, saTokenMatch[1]);
    if (method === 'POST') return handleCreateAccessToken(request, env, principal, saTokenMatch[1]);
  }

  const orgMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)(\/.*)?$/i);
  if (!orgMatch) return null;
  const orgId = orgMatch[1];
  const sub = orgMatch[2] || '';
  if (sub === '/access-policies/service-accounts/potential-grantees' && method === 'GET') return handlePotentialMachines(env, principal, orgId, 'serviceAccounts');
  if (sub === '/access-policies/projects/potential-grantees' && method === 'GET') return handlePotentialMachines(env, principal, orgId, 'projects');
  if (sub === '/access-policies/people/potential-grantees' && method === 'GET') return handlePotentialPeople(env, principal, orgId);
  if (sub === '/sm-counts' && method === 'GET') return handleSmCounts(env, principal, orgId);
  if (sub === '/secrets' && method === 'GET') return handleListSecrets(env, principal, orgId);
  if (sub === '/secrets' && method === 'POST') return handleCreateSecret(request, env, principal, orgId);
  if (sub === '/secrets/sync' && method === 'GET') return handleSecretsSync(request, env, principal, orgId);
  if (sub === '/projects' && method === 'GET') return handleListProjects(env, principal, orgId);
  if (sub === '/projects' && method === 'POST') return handleCreateProject(request, env, principal, orgId);
  if (sub === '/service-accounts' && method === 'GET') return handleListServiceAccounts(env, principal, orgId);
  if (sub === '/service-accounts' && method === 'POST') return handleCreateServiceAccount(request, env, principal, orgId);

  return null;
}

export async function handleSmMachineRoute(request: Request, env: Env, principal: Extract<Principal, { kind: 'serviceAccount' }>, path: string, method: string): Promise<Response> {
  const allowed = ((method === 'GET' || method === 'POST') && /^\/api\/organizations\/[a-f0-9-]+\/(projects|secrets)$/i.test(path))
    || ((method === 'GET' || method === 'PUT') && /^\/api\/(projects|secrets)\/[a-f0-9-]+$/i.test(path))
    || (method === 'POST' && /^\/api\/(projects\/delete|secrets\/(delete|get-by-ids))$/i.test(path))
    || (method === 'GET' && /^\/api\/projects\/[a-f0-9-]+\/secrets$/i.test(path))
    || (method === 'GET' && /^\/api\/organizations\/[a-f0-9-]+\/secrets\/sync$/i.test(path));
  return allowed ? (await handleSmRoute(request, env, principal, path, method)) ?? errorResponse('Not found', 404) : errorResponse('Not found', 404);
}
