import type { AuthedFetch } from './shared';
import { createApiError, parseErrorMessage, parseJson } from './shared';

export interface ProfileOrganization {
  id: string;
  name: string;
  key: string;
  status: number;
  type: number;
  organizationUserId: string;
  accessAll?: boolean;
  useSso?: boolean;
  useScim?: boolean;
  useSecretsManager?: boolean;
  accessSecretsManager?: boolean;
  permissions?: Record<string, boolean> | null;
}

export interface OrgCollection {
  id: string;
  organizationId: string;
  name: string;
  externalId?: string | null;
  readOnly?: boolean;
  hidePasswords?: boolean;
  manage?: boolean;
}

export interface OrgMember {
  id: string;
  userId: string | null;
  email: string;
  name: string | null;
  status: number;
  type: number;
  accessAll: boolean;
}

export interface OrgGroup {
  id: string;
  name: string;
  accessAll: boolean;
  users: string[];
}

export interface OrgPolicy {
  id: string;
  organizationId: string;
  type: number;
  enabled: boolean;
  data: Record<string, unknown>;
}

export interface SmProject {
  id: string;
  name: string;
}

export interface SmSecret {
  id: string;
  key: string;
  value: string;
  note: string | null;
  projectIds: string[];
}

async function readList<T>(resp: Response, fallback: T[] = []): Promise<T[]> {
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Request failed'));
  const body = await parseJson<{ data?: T[] }>(resp);
  return body?.data || fallback;
}

export async function createOrganization(
  authedFetch: AuthedFetch,
  payload: { name: string; billingEmail: string; collectionName: string; key: string; keys?: { publicKey: string; encryptedPrivateKey: string } }
) {
  const resp = await authedFetch('/api/organizations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Create organization failed'));
  return parseJson<{ id: string; name: string }>(resp);
}

export async function listCollections(authedFetch: AuthedFetch, orgId: string): Promise<OrgCollection[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/collections/details`);
  return readList<OrgCollection>(resp);
}

export async function createCollection(authedFetch: AuthedFetch, orgId: string, name: string): Promise<OrgCollection> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/collections`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Create collection failed'));
  const collection = await parseJson<OrgCollection>(resp);
  if (!collection) throw createApiError('Create collection failed', 500);
  return collection;
}

export async function listMembers(authedFetch: AuthedFetch, orgId: string): Promise<OrgMember[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/users`);
  return readList<OrgMember>(resp);
}

export async function inviteMembers(authedFetch: AuthedFetch, orgId: string, emails: string[], type = 2): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/users/invite`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ emails, type, accessAll: type <= 1 }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Invite failed'));
}

export async function confirmMember(authedFetch: AuthedFetch, orgId: string, memberId: string, key: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/users/${encodeURIComponent(memberId)}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Confirm failed'));
}

export async function removeMember(authedFetch: AuthedFetch, orgId: string, memberId: string): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/users/${encodeURIComponent(memberId)}`, { method: 'DELETE' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Remove member failed'));
}

export async function listGroups(authedFetch: AuthedFetch, orgId: string): Promise<OrgGroup[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/groups`);
  return readList<OrgGroup>(resp);
}

export async function saveGroup(authedFetch: AuthedFetch, orgId: string, name: string, users: string[] = []): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, users, accessAll: false }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Save group failed'));
}

export async function listPolicies(authedFetch: AuthedFetch, orgId: string): Promise<OrgPolicy[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/policies`);
  return readList<OrgPolicy>(resp);
}

export async function putPolicy(authedFetch: AuthedFetch, orgId: string, type: number, enabled: boolean, data: Record<string, unknown> = {}): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/policies/${type}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled, data }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Save policy failed'));
}

export async function rotateScimKey(authedFetch: AuthedFetch, orgId: string): Promise<string> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/scim-key`, { method: 'POST' });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'SCIM key failed'));
  const body = await parseJson<{ token?: string }>(resp);
  if (!body?.token) throw createApiError('SCIM key failed', 500);
  return body.token;
}

export async function listProjects(authedFetch: AuthedFetch, orgId: string): Promise<SmProject[]> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/projects`);
  return readList<SmProject>(resp);
}

export async function createProject(authedFetch: AuthedFetch, orgId: string, name: string): Promise<SmProject> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Create project failed'));
  const project = await parseJson<SmProject>(resp);
  if (!project) throw createApiError('Create project failed', 500);
  return project;
}

export async function listSecrets(authedFetch: AuthedFetch, orgId: string): Promise<Array<{ id: string; key: string }>> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/secrets`);
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'List secrets failed'));
  const body = await parseJson<{ secrets?: Array<{ id: string; key: string }> }>(resp);
  return body?.secrets || [];
}

export async function createSecret(
  authedFetch: AuthedFetch,
  orgId: string,
  payload: { key: string; value: string; note?: string; projectIds?: string[] }
): Promise<void> {
  const resp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/secrets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, 'Create secret failed'));
}

export async function createServiceAccountToken(
  authedFetch: AuthedFetch,
  orgId: string,
  name: string,
  wrappedOrgKey: string
): Promise<{ clientId: string; clientSecret: string }> {
  const accountResp = await authedFetch(`/api/organizations/${encodeURIComponent(orgId)}/service-accounts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name }),
  });
  if (!accountResp.ok) throw new Error(await parseErrorMessage(accountResp, 'Create service account failed'));
  const account = await parseJson<{ id: string }>(accountResp);
  if (!account?.id) throw createApiError('Create service account failed', 500);
  const tokenResp = await authedFetch(`/api/service-accounts/${encodeURIComponent(account.id)}/access-tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `${name} token`, wrappedOrgKey }),
  });
  if (!tokenResp.ok) throw new Error(await parseErrorMessage(tokenResp, 'Create access token failed'));
  const token = await parseJson<{ clientId: string; clientSecret: string }>(tokenResp);
  if (!token?.clientId || !token.clientSecret) throw createApiError('Create access token failed', 500);
  return token;
}
