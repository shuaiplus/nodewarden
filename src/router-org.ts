import type { Env, User } from './types';
import { errorResponse, jsonResponse } from './utils/response';
import {
  handleAcceptInvite,
  handleConfirmMember,
  handleCreateOrgCollection,
  handleCreateOrganization,
  handleDeleteGroup,
  handleDeleteMember,
  handleDeleteOrgCollection,
  handleDeleteOrganization,
  handleEditMember,
  handleGetAutoEnrollStatus,
  handleGetOrganization,
  handleGetOrganizationKeys,
  handleGetPlans,
  handleInviteMembers,
  handleLeaveOrganization,
  handleListGroups,
  handleListMembers,
  handleListOrgCollections,
  handleListPolicies,
  handleOrgApiKey,
  handlePostOrganizationKeys,
  handlePutPolicy,
  handleRestoreMember,
  handleRevokeMember,
  handleRotateScimKey,
  handleSaveGroup,
  handleUpdateOrgCollection,
  handleUpdateOrganization,
} from './handlers/organizations';
import {
  enterpriseLicenseFileResponse,
  handleCreateSelfHostedOrganizationLicense,
  handleSyncSelfHostedOrganizationLicense,
  handleUpdateSelfHostedOrganizationLicense,
} from './handlers/licenses';
import {
  handleCreateAccessToken,
  handleCreateProject,
  handleCreateSecret,
  handleCreateServiceAccount,
  handleDeleteSecrets,
  handleGetSecret,
  handleListAccessTokens,
  handleListProjects,
  handleListSecrets,
  handleListServiceAccounts,
  handleSecretsSync,
  handleUpdateSecret,
} from './handlers/secrets-manager';

export async function handleOrganizationRoute(
  request: Request,
  env: Env,
  userId: string,
  currentUser: User,
  path: string,
  method: string
): Promise<Response | null> {
  if ((path === '/api/organizations' || path === '/organizations') && method === 'POST') {
    return handleCreateOrganization(request, env, currentUser);
  }
  if ((path === '/api/plans' || path === '/plans') && method === 'GET') return handleGetPlans();
  if ((path === '/api/licenses/nodewarden-enterprise.json' || path === '/licenses/nodewarden-enterprise.json') && method === 'GET') {
    return enterpriseLicenseFileResponse(currentUser);
  }
  if ((path === '/api/organizations/licenses/self-hosted' || path === '/organizations/licenses/self-hosted') && method === 'POST') {
    return handleCreateSelfHostedOrganizationLicense(request, env, currentUser);
  }
  const licenseUpdate = path.match(/^\/(?:api\/)?organizations\/licenses\/self-hosted\/([a-f0-9-]+)(\/sync)?\/?$/i);
  if (licenseUpdate && method === 'POST') {
    if (licenseUpdate[2]) return handleSyncSelfHostedOrganizationLicense(env, currentUser, licenseUpdate[1]);
    return handleUpdateSelfHostedOrganizationLicense(request, env, currentUser, licenseUpdate[1]);
  }
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

  if (sub === '' || sub === '/') {
    if (method === 'GET') return handleGetOrganization(request, env, userId, orgId);
    if (method === 'PUT' || method === 'POST') return handleUpdateOrganization(request, env, userId, orgId);
    if (method === 'DELETE') return handleDeleteOrganization(env, userId, orgId);
  }
  if (sub === '/delete' && method === 'POST') return handleDeleteOrganization(env, userId, orgId);
  if (sub === '/leave' && method === 'POST') return handleLeaveOrganization(env, userId, orgId);
  if (sub === '/keys' && method === 'POST') return handlePostOrganizationKeys(request, env, userId, orgId);
  if ((sub === '/keys' || sub === '/public-key') && method === 'GET') return handleGetOrganizationKeys(env, userId, orgId);
  if (sub === '/auto-enroll-status' && method === 'GET') return handleGetAutoEnrollStatus(env, userId, orgId);
  if (sub === '/billing/metadata' && method === 'GET') {
    return jsonResponse({ object: 'list', data: [], continuationToken: null });
  }
  if (sub === '/billing/vnext/warnings' && method === 'GET') {
    return jsonResponse({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null });
  }
  if (sub === '/billing/vnext/self-host/metadata' && method === 'GET') {
    return jsonResponse({ isOnSecretsManagerStandalone: false, organizationOccupiedSeats: 0 });
  }

  if (sub === '/collections' || sub === '/collections/details') {
    if (method === 'GET') return handleListOrgCollections(env, userId, orgId, sub.endsWith('/details'));
    if (method === 'POST') return handleCreateOrgCollection(request, env, userId, orgId);
  }
  const colMatch = sub.match(/^\/collections\/([a-f0-9-]+)(?:\/(delete|details|users))?$/i);
  if (colMatch) {
    if ((method === 'PUT' || method === 'POST') && !colMatch[2]) return handleUpdateOrgCollection(request, env, userId, orgId, colMatch[1]);
    if ((method === 'DELETE' || (method === 'POST' && colMatch[2] === 'delete'))) return handleDeleteOrgCollection(env, userId, orgId, colMatch[1]);
    if (method === 'GET') return handleListOrgCollections(env, userId, orgId, true);
  }

  if (sub === '/users' && method === 'GET') return handleListMembers(env, userId, orgId);
  if (sub === '/users/invite' && method === 'POST') return handleInviteMembers(request, env, currentUser, orgId);
  const userMatch = sub.match(/^\/users\/([a-f0-9-]+)(?:\/(accept|confirm|revoke|restore|restore\/vnext))?$/i);
  if (userMatch) {
    const memberId = userMatch[1];
    const action = userMatch[2] || '';
    if (action === 'accept' && method === 'POST') return handleAcceptInvite(request, env, currentUser, orgId, memberId);
    if (action === 'confirm' && method === 'POST') return handleConfirmMember(request, env, userId, orgId, memberId);
    if (action === 'revoke' && method === 'PUT') return handleRevokeMember(env, userId, orgId, memberId);
    if ((action === 'restore' || action === 'restore/vnext') && method === 'PUT') return handleRestoreMember(env, userId, orgId, memberId);
    if ((method === 'PUT' || method === 'POST') && !action) return handleEditMember(request, env, userId, orgId, memberId);
    if (method === 'DELETE') return handleDeleteMember(env, userId, orgId, memberId);
  }

  if ((sub === '/groups' || sub === '/groups/details') && method === 'GET') return handleListGroups(env, userId, orgId);
  if (sub === '/groups' && method === 'POST') return handleSaveGroup(request, env, userId, orgId);
  const groupMatch = sub.match(/^\/groups\/([a-f0-9-]+)(?:\/delete)?$/i);
  if (groupMatch) {
    if (method === 'POST' || method === 'PUT') return handleSaveGroup(request, env, userId, orgId, groupMatch[1]);
    if (method === 'DELETE') return handleDeleteGroup(env, userId, orgId, groupMatch[1]);
  }

  if (sub === '/policies' && method === 'GET') return handleListPolicies(env, userId, orgId);
  const policyMatch = sub.match(/^\/policies\/(\d+)(?:\/vnext)?$/i);
  if (policyMatch && (method === 'PUT' || method === 'GET')) {
    if (method === 'PUT') return handlePutPolicy(request, env, userId, orgId, Number(policyMatch[1]));
    return handleListPolicies(env, userId, orgId);
  }

  if ((sub === '/api-key' || sub === '/rotate-api-key') && method === 'POST') {
    return handleOrgApiKey(request, env, userId, orgId, sub.includes('rotate'));
  }
  if ((sub === '/scim-key' || sub === '/rotate-scim-key') && method === 'POST') {
    return handleRotateScimKey(env, userId, orgId);
  }

  if (sub === '/secrets' && method === 'GET') return handleListSecrets(env, userId, orgId);
  if (sub === '/secrets' && method === 'POST') return handleCreateSecret(request, env, userId, orgId);
  if (sub === '/secrets/sync' && method === 'GET') return errorResponse('Service account required', 400);
  if (sub === '/projects' && method === 'GET') return handleListProjects(env, userId, orgId);
  if (sub === '/projects' && method === 'POST') return handleCreateProject(request, env, userId, orgId);
  if (sub === '/service-accounts' && method === 'GET') return handleListServiceAccounts(env, userId, orgId);
  if (sub === '/service-accounts' && method === 'POST') return handleCreateServiceAccount(request, env, userId, orgId);

  return errorResponse('Not found', 404);
}

export { handleSecretsSync };
