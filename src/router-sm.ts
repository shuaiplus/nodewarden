import type { Env } from './types';
import { errorResponse } from './utils/response';
import {
  handleCreateAccessToken,
  handleCreateProject,
  handleProject,
  handleDeleteProjects,
  handleCreateSecret,
  handleCreateServiceAccount,
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
  if (sub === '/secrets' && method === 'GET') return handleListSecrets(env, userId, orgId);
  if (sub === '/secrets' && method === 'POST') return handleCreateSecret(request, env, userId, orgId);
  if (sub === '/secrets/sync' && method === 'GET') return errorResponse('Service account required', 400);
  if (sub === '/projects' && method === 'GET') return handleListProjects(env, userId, orgId);
  if (sub === '/projects' && method === 'POST') return handleCreateProject(request, env, userId, orgId);
  if (sub === '/service-accounts' && method === 'GET') return handleListServiceAccounts(env, userId, orgId);
  if (sub === '/service-accounts' && method === 'POST') return handleCreateServiceAccount(request, env, userId, orgId);

  return null;
}
