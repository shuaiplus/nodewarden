// Organization API client for the NodeWarden webapp. Shapes mirror the
// server responses from src/handlers/organizations.ts.
import { parseJson, type AuthedFetch } from './shared';

export interface OrganizationSummary {
  id: string;
  name: string;
  billingEmail?: string | null;
  status: number;
  type: number;
  organizationUserId: string;
  ownerEmail?: string | null;
  /** Org key wrapped for this member ("4." EncString, confirmed members only). */
  key?: string | null;
  [k: string]: unknown;
}

export interface OrganizationMember {
  id: string;
  userId: string | null;
  name: string | null;
  email: string;
  type: number;
  status: number;
  accessAll: boolean;
  twoFactorEnabled?: boolean;
  publicKey?: string | null;
  collections?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean }>;
  invitationDate?: string | null;
  userCreatedAt?: string | null;
  object?: string;
}

export interface OrganizationCollection {
  id: string;
  organizationId: string;
  name: string;
  externalId?: string | null;
  object?: string;
  [k: string]: unknown;
}

export interface OrganizationCollectionDetails extends OrganizationCollection {
  users?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean }>;
  groups?: unknown[];
}

export interface InviteOrganizationUsersResult {
  invited: Array<{
    email: string;
    organizationUserId: string;
    registered: boolean;
    inviteCode?: string;
    requiresAdminRegistration?: boolean;
  }>;
  skipped: Array<{ email: string; reason: string }>;
}

export interface CreateOrganizationPayload {
  name: string;
  key: string;
  keys: { publicKey: string; encryptedPrivateKey: string };
  collectionName: string;
  billingEmail?: string | null;
}

export interface CollectionAccessInput {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
}

async function requestJson<T>(authedFetch: AuthedFetch, url: string, init?: RequestInit): Promise<T> {
  const resp = await authedFetch(url, init);
  if (!resp.ok) {
    let message = `Request failed (${resp.status})`;
    try {
      const body = await parseJson<{ error?: string; message?: string; Message?: string }>(resp);
      message = String(body?.error || body?.message || body?.Message || message);
    } catch {
      // keep default message
    }
    throw new Error(message);
  }
  if (resp.status === 204) return null as unknown as T;
  return (await parseJson<T>(resp)) as T;
}

export async function listMyOrganizations(authedFetch: AuthedFetch): Promise<OrganizationSummary[]> {
  const body = await requestJson<{ data?: OrganizationSummary[] }>(authedFetch, '/api/organizations');
  return Array.isArray(body?.data) ? body.data : [];
}

export async function getOrganization(authedFetch: AuthedFetch, organizationId: string): Promise<OrganizationSummary> {
  return requestJson<OrganizationSummary>(authedFetch, `/api/organizations/${organizationId}`);
}

export async function createOrganization(
  authedFetch: AuthedFetch,
  payload: CreateOrganizationPayload
): Promise<OrganizationSummary> {
  return requestJson<OrganizationSummary>(authedFetch, '/api/organizations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

export async function updateOrganization(
  authedFetch: AuthedFetch,
  organizationId: string,
  nameEnc: string
): Promise<OrganizationSummary> {
  return requestJson<OrganizationSummary>(authedFetch, `/api/organizations/${organizationId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: nameEnc }),
  });
}

export async function deleteOrganization(authedFetch: AuthedFetch, organizationId: string): Promise<void> {
  await requestJson<unknown>(authedFetch, `/api/organizations/${organizationId}`, { method: 'DELETE' });
}

export async function leaveOrganization(authedFetch: AuthedFetch, organizationId: string): Promise<void> {
  await requestJson<unknown>(authedFetch, `/api/organizations/${organizationId}/leave`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
}

export async function listOrganizationMembers(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationMember[]> {
  const body = await requestJson<{ data?: OrganizationMember[] }>(
    authedFetch,
    `/api/organizations/${organizationId}/users`
  );
  return Array.isArray(body?.data) ? body.data : [];
}

export async function getOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  organizationUserId: string
): Promise<OrganizationMember> {
  return requestJson<OrganizationMember>(
    authedFetch,
    `/api/organizations/${organizationId}/users/${organizationUserId}`
  );
}

export async function inviteOrganizationMembers(
  authedFetch: AuthedFetch,
  organizationId: string,
  payload: {
    emails: string[];
    accessAll: boolean;
    type?: number;
    collections?: CollectionAccessInput[];
  }
): Promise<InviteOrganizationUsersResult> {
  return requestJson<InviteOrganizationUsersResult>(
    authedFetch,
    `/api/organizations/${organizationId}/invites`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }
  );
}

export async function acceptOrganizationInvitation(
  authedFetch: AuthedFetch,
  organizationId: string,
  organizationUserId: string
): Promise<void> {
  await requestJson<unknown>(
    authedFetch,
    `/api/organizations/${organizationId}/users/${organizationUserId}/accept`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: '' }),
    }
  );
}

export async function confirmOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  organizationUserId: string,
  keyEnc: string
): Promise<void> {
  await requestJson<unknown>(
    authedFetch,
    `/api/organizations/${organizationId}/users/${organizationUserId}/confirm`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: keyEnc }),
    }
  );
}

export async function updateOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  organizationUserId: string,
  payload: { type?: number; accessAll?: boolean; collections?: CollectionAccessInput[] }
): Promise<void> {
  await requestJson<unknown>(
    authedFetch,
    `/api/organizations/${organizationId}/users/${organizationUserId}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    }
  );
}

export async function removeOrganizationMember(
  authedFetch: AuthedFetch,
  organizationId: string,
  organizationUserId: string
): Promise<void> {
  await requestJson<unknown>(
    authedFetch,
    `/api/organizations/${organizationId}/users/${organizationUserId}`,
    { method: 'DELETE' }
  );
}

export async function listOrganizationCollections(
  authedFetch: AuthedFetch,
  organizationId: string
): Promise<OrganizationCollection[]> {
  const body = await requestJson<{ data?: OrganizationCollection[] }>(
    authedFetch,
    `/api/organizations/${organizationId}/collections`
  );
  return Array.isArray(body?.data) ? body.data : [];
}

export async function getOrganizationCollectionDetails(
  authedFetch: AuthedFetch,
  organizationId: string,
  collectionId: string
): Promise<OrganizationCollectionDetails> {
  return requestJson<OrganizationCollectionDetails>(
    authedFetch,
    `/api/organizations/${organizationId}/collections/${collectionId}/details`
  );
}

export async function createOrganizationCollection(
  authedFetch: AuthedFetch,
  organizationId: string,
  nameEnc: string,
  users?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean }>
): Promise<OrganizationCollection> {
  return requestJson<OrganizationCollection>(
    authedFetch,
    `/api/organizations/${organizationId}/collections`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: nameEnc, externalId: null, groups: [], users: users || [] }),
    }
  );
}

export async function updateOrganizationCollection(
  authedFetch: AuthedFetch,
  organizationId: string,
  collectionId: string,
  payload: { name: string; users?: Array<{ id: string; readOnly: boolean; hidePasswords: boolean }> }
): Promise<OrganizationCollection> {
  return requestJson<OrganizationCollection>(
    authedFetch,
    `/api/organizations/${organizationId}/collections/${collectionId}`,
    {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ externalId: null, groups: [], ...payload }),
    }
  );
}

export async function deleteOrganizationCollection(
  authedFetch: AuthedFetch,
  organizationId: string,
  collectionId: string
): Promise<void> {
  await requestJson<unknown>(
    authedFetch,
    `/api/organizations/${organizationId}/collections/${collectionId}`,
    { method: 'DELETE' }
  );
}
