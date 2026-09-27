import { Hono } from 'hono';
import { errorResponse, jsonResponse } from './utils/response';
import {
  handleAcceptInvite,
  handleBulkConfirmMembers,
  handleBulkMemberAction,
  handleBulkReinviteMembers,
  handleConfirmMember,
  handleCreateOrgCollection,
  handleCreateOrganization,
  handleDeleteGroup,
  handleDeleteMember,
  handleDeleteOrgCollection,
  handleDeleteOrganization,
  handleEditMember,
  handleEnableSecretsManager,
  handleGetAutoEnrollStatus,
  handleGetMember,
  handleGetOrganization,
  handleGetOrganizationKeys,
  handleGetOrgCollectionDetails,
  handleGetPlans,
  handleGetPolicy,
  handleInviteMembers,
  handleLeaveOrganization,
  handleListGroups,
  handleListMemberMiniDetails,
  handleListMemberPublicKeys,
  handleListMembers,
  handleListOrgCollectionDetails,
  handleListOrgCollectionUsers,
  handleListOrgCollections,
  handleListPolicies,
  handleOrgApiKey,
  handlePostOrganizationKeys,
  handlePutPolicy,
  handleReinviteMember,
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
import type { AppEnv } from './router';

export const organizationRoutes = new Hono<AppEnv>();

organizationRoutes.on('POST', ['/api/organizations', '/organizations'], (c) => handleCreateOrganization(c.req.raw, c.env, c.get('currentUser')));
organizationRoutes.on('GET', ['/api/plans', '/plans'], () => handleGetPlans());
organizationRoutes.on('GET', ['/api/licenses/nodewarden-enterprise.json', '/licenses/nodewarden-enterprise.json'], (c) => enterpriseLicenseFileResponse(c.get('currentUser')));
organizationRoutes.on('POST', ['/api/organizations/licenses/self-hosted', '/organizations/licenses/self-hosted'], (c) => handleCreateSelfHostedOrganizationLicense(c.req.raw, c.env, c.get('currentUser')));
const license = '/organizations/licenses/self-hosted/:orgId{[a-f0-9-]+}';
organizationRoutes.on('POST', [`/api${license}/sync`, `${license}/sync`], (c) => handleSyncSelfHostedOrganizationLicense(c.env, c.get('currentUser'), c.req.param('orgId')));
organizationRoutes.on('POST', [`/api${license}`, license], (c) => handleUpdateSelfHostedOrganizationLicense(c.env, c.get('currentUser'), c.req.param('orgId')));

const org = '/api/organizations/:orgId{[a-f0-9-]+}';
organizationRoutes.get(org, (c) => handleGetOrganization(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.on(['PUT', 'POST'], org, (c) => handleUpdateOrganization(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.delete(org, (c) => handleDeleteOrganization(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/delete`, (c) => handleDeleteOrganization(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/leave`, (c) => handleLeaveOrganization(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/keys`, (c) => handlePostOrganizationKeys(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.on('GET', [`${org}/keys`, `${org}/public-key`], (c) => handleGetOrganizationKeys(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.get(`${org}/auto-enroll-status`, (c) => handleGetAutoEnrollStatus(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.get(`${org}/billing/metadata`, () => jsonResponse({ object: 'list', data: [], continuationToken: null }));
organizationRoutes.get(`${org}/billing/vnext/warnings`, () => jsonResponse({ freeTrial: null, inactiveSubscription: null, resellerRenewal: null, taxId: null }));
organizationRoutes.get(`${org}/billing/vnext/self-host/metadata`, () => jsonResponse({ isOnSecretsManagerStandalone: true, organizationOccupiedSeats: 0 }));

organizationRoutes.get(`${org}/collections/details`, (c) => handleListOrgCollectionDetails(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.get(`${org}/collections`, (c) => handleListOrgCollections(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.on('POST', [`${org}/collections`, `${org}/collections/details`], (c) => handleCreateOrgCollection(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
const collection = `${org}/collections/:collectionId{[a-f0-9-]+}`;
organizationRoutes.on(['PUT', 'POST'], collection, (c) => handleUpdateOrgCollection(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('collectionId')));
organizationRoutes.on('DELETE', [collection, `${collection}/delete`, `${collection}/details`, `${collection}/users`], (c) => handleDeleteOrgCollection(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('collectionId')));
organizationRoutes.post(`${collection}/delete`, (c) => handleDeleteOrgCollection(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('collectionId')));
organizationRoutes.get(`${collection}/details`, (c) => handleGetOrgCollectionDetails(c.env, c.get('userId'), c.req.param('orgId'), c.req.param('collectionId')));
organizationRoutes.get(`${collection}/users`, (c) => handleListOrgCollectionUsers(c.env, c.get('userId'), c.req.param('orgId'), c.req.param('collectionId')));

organizationRoutes.put(`${org}/users/enable-secrets-manager`, (c) => handleEnableSecretsManager(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.get(`${org}/users`, (c) => handleListMembers(c.env, c.get('userId'), c.req.param('orgId'), c.req.query('includeGroups') === 'true'));
organizationRoutes.get(`${org}/users/mini-details`, (c) => handleListMemberMiniDetails(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/users/invite`, (c) => handleInviteMembers(c.req.raw, c.env, c.get('currentUser'), c.req.param('orgId')));
organizationRoutes.post(`${org}/users/public-keys`, (c) => handleListMemberPublicKeys(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/users/confirm`, (c) => handleBulkConfirmMembers(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/users/reinvite`, (c) => handleBulkReinviteMembers(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.delete(`${org}/users`, (c) => handleBulkMemberAction(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), 'remove'));
organizationRoutes.post(`${org}/users/remove`, (c) => handleBulkMemberAction(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), 'remove'));
organizationRoutes.on(['PUT', 'PATCH'], `${org}/users/revoke`, (c) => handleBulkMemberAction(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), 'revoke'));
organizationRoutes.on(['PUT', 'PATCH'], `${org}/users/restore`, (c) => handleBulkMemberAction(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), 'restore'));
const member = `${org}/users/:memberId{[a-f0-9-]+}`;
organizationRoutes.post(`${member}/accept`, (c) => handleAcceptInvite(c.req.raw, c.env, c.get('currentUser'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.post(`${member}/confirm`, (c) => handleConfirmMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.post(`${member}/reinvite`, (c) => handleReinviteMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.on(['PUT', 'PATCH'], `${member}/revoke`, (c) => handleRevokeMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.on(['PUT', 'PATCH'], [`${member}/restore`, `${member}/restore/vnext`], (c) => handleRestoreMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.get(member, (c) => handleGetMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.on(['PUT', 'POST'], member, (c) => handleEditMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));
organizationRoutes.on('DELETE', [member, `${member}/accept`, `${member}/confirm`, `${member}/reinvite`, `${member}/revoke`, `${member}/restore`, `${member}/restore/vnext`], (c) => handleDeleteMember(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('memberId')));

organizationRoutes.on('GET', [`${org}/groups`, `${org}/groups/details`], (c) => handleListGroups(c.env, c.get('userId'), c.req.param('orgId')));
organizationRoutes.post(`${org}/groups`, (c) => handleSaveGroup(c.req.raw, c.env, c.get('userId'), c.req.param('orgId')));
const group = [`${org}/groups/:groupId{[a-f0-9-]+}`, `${org}/groups/:groupId{[a-f0-9-]+}/delete`] as const;
organizationRoutes.on(['POST', 'PUT'], [...group], (c) => handleSaveGroup(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('groupId')));
organizationRoutes.on('DELETE', [...group], (c) => handleDeleteGroup(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), c.req.param('groupId')));

organizationRoutes.get(`${org}/policies`, (c) => handleListPolicies(c.env, c.get('userId'), c.req.param('orgId')));
const policy = [`${org}/policies/:type{[0-9]+}`, `${org}/policies/:type{[0-9]+}/vnext`] as const;
organizationRoutes.on('PUT', [...policy], (c) => handlePutPolicy(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), Number(c.req.param('type'))));
organizationRoutes.on('GET', [...policy], (c) => handleGetPolicy(c.env, c.get('userId'), c.req.param('orgId'), Number(c.req.param('type'))));

organizationRoutes.post(`${org}/api-key`, (c) => handleOrgApiKey(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), false));
organizationRoutes.post(`${org}/rotate-api-key`, (c) => handleOrgApiKey(c.req.raw, c.env, c.get('userId'), c.req.param('orgId'), true));
organizationRoutes.on('POST', [`${org}/scim-key`, `${org}/rotate-scim-key`], (c) => handleRotateScimKey(c.env, c.get('userId'), c.req.param('orgId')));

// Anything else under a well-formed organization id is unknown rather than an empty list.
organizationRoutes.on('ALL', [org, `${org}/*`], () => errorResponse('Not found', 404));
