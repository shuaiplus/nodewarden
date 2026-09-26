import { handlePeoplePolicies, handlePotentialPeople } from './handlers/sm-access-policies';
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
} from './handlers/secrets-manager';

export async function handleSmRoute(request: Request, env: Env, userId: string, path: string, method: string): Promise<Response | null> {
  const people = path.match(/^\/api\/(projects|service-accounts)\/([a-f0-9-]+)\/access-policies\/people$/i);
  if (people && (method === 'GET' || method === 'PUT')) return handlePeoplePolicies(request, env, userId, people[1] === 'projects' ? 'project' : 'serviceAccount', people[2]);
  const event = path.match(/^\/api\/organization\/([a-f0-9-]+)\/(projects|secrets|service-account)\/([a-f0-9-]+)\/events$/i);
  if (event && method === 'GET') return handleSmEvents(env, userId, event[2] as 'projects' | 'secrets' | 'service-account', event[3], event[1]);
  const accountEvent = path.match(/^\/api\/sm\/events\/service-accounts\/([a-f0-9-]+)$/i);
  if (accountEvent && method === 'GET') return handleSmEvents(env, userId, 'service-account', accountEvent[1]);
  if (path === '/api/service-accounts/delete' && method === 'POST') return handleDeleteServiceAccounts(request, env, userId);
  const account = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)(\/sm-counts)?$/i);
  if (account && (method === 'GET' || (!account[2] && method === 'PUT'))) return handleServiceAccount(request, env, userId, account[1], !!account[2]);
  const revoke = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)\/access-tokens\/revoke$/i);
  if (revoke && method === 'POST') return handleRevokeAccessTokens(request, env, userId, revoke[1]);
  if (path === '/api/projects/delete' && method === 'POST') return handleDeleteProjects(request, env, userId);
  if (path === '/api/secrets/get-by-ids' && method === 'POST') return handleSecretsByIds(request, env, userId);
  const projectSecrets = path.match(/^\/api\/projects\/([a-f0-9-]+)\/secrets$/i);
  if (projectSecrets && method === 'GET') return handleProjectSecrets(env, userId, projectSecrets[1]);
  const project = path.match(/^\/api\/projects\/([a-f0-9-]+)(\/sm-counts)?$/i);
  if (project && (method === 'GET' || (!project[2] && method === 'PUT'))) return handleProject(request, env, userId, project[1], !!project[2]);
  if (path === '/api/secrets/delete' && method === 'POST') return handleDeleteSecrets(request, env, userId);

  const secretMatch = path.match(/^\/api\/secrets\/([a-f0-9-]+)$/i);
  if (secretMatch) {
    if (method === 'GET') return handleGetSecret(env, userId, secretMatch[1]);
    if (method === 'PUT') return handleUpdateSecret(request, env, userId, secretMatch[1]);
  }

  const saTokenMatch = path.match(/^\/api\/service-accounts\/([a-f0-9-]+)\/access-tokens$/i);
  if (saTokenMatch) {
    if (method === 'GET') return handleListAccessTokens(env, userId, saTokenMatch[1]);
    if (method === 'POST') return handleCreateAccessToken(request, env, userId, saTokenMatch[1]);
  }

  const orgMatch = path.match(/^\/api\/organizations\/([a-f0-9-]+)(\/.*)?$/i);
  if (!orgMatch) return null;
  const orgId = orgMatch[1];
  const sub = orgMatch[2] || '';
  if (sub === '/access-policies/people/potential-grantees' && method === 'GET') return handlePotentialPeople(env, userId, orgId);
  if (sub === '/sm-counts' && method === 'GET') return handleSmCounts(env, userId, orgId);
  if (sub === '/secrets' && method === 'GET') return handleListSecrets(env, userId, orgId);
  if (sub === '/secrets' && method === 'POST') return handleCreateSecret(request, env, userId, orgId);
  if (sub === '/secrets/sync' && method === 'GET') return errorResponse('Service account required', 400);
  if (sub === '/projects' && method === 'GET') return handleListProjects(env, userId, orgId);
  if (sub === '/projects' && method === 'POST') return handleCreateProject(request, env, userId, orgId);
  if (sub === '/service-accounts' && method === 'GET') return handleListServiceAccounts(env, userId, orgId);
  if (sub === '/service-accounts' && method === 'POST') return handleCreateServiceAccount(request, env, userId, orgId);

  return null;
}
