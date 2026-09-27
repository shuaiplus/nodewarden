import assert from 'node:assert/strict';

import { EMPTY_PERMISSIONS, MembershipStatus, MembershipType, type CollectionAccess, type MembershipRecord, type OrgPermissions } from '../../src/services/org-types';
import { AuthService, type Principal } from '../../src/services/auth';
import * as orgRepo from '../../src/services/storage-org-repo';
import type { Env, User } from '../../src/types';
import { authedFetch, seedUser } from './env';

// The organization handlers reach cloudflare:workers, which env.ts maps only once it has run.
const { createOwnedOrganization } = await import('../../src/handlers/organizations');

// The server stores org and membership keys as sent, so any EncString-shaped value will do.
export const TEST_ORG_KEY = '4.dGVzdA==';
export const TEST_ORG_NAME = 'Acme';

// Stored as sent; official web encrypts SM names, keys and values with the org key.
export const ENCRYPTED_FIELD = '2.dGVzdA==|dGVzdA==|dGVzdA==';
export const TOKEN_FIELDS = { name: ENCRYPTED_FIELD, encryptedPayload: ENCRYPTED_FIELD, key: ENCRYPTED_FIELD };

export function smLogin(env: Env, tokenId: string, secret: string): Promise<Response> {
  return authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'api.secrets', client_id: tokenId, client_secret: secret }) });
}

export async function smUser(env: Env, user: User): Promise<Principal> {
  const auth = new AuthService(env);
  const principal = await auth.verifyPrincipal(`Bearer ${await auth.generateAccessToken(user)}`);
  assert.ok(principal);
  assert.equal(principal.kind, 'user');
  return principal;
}

// Official web creates an org through POST /organizations, or self-hosted through the license
// upload, which NodeWarden accepts with any JSON.
export const ORG_CREATE_PATHS = ['/api/organizations', '/api/organizations/licenses/self-hosted'] as const;

export interface SmOrg {
  orgId: string;
  owner: User;
  admin: User;
}

// Fails on anything but 200 so a broken setup call cannot pass for the behavior under test.
export async function postJson<T>(env: Env, owner: User, path: string, body: unknown): Promise<T> {
  const response = await authedFetch(env, { method: 'POST', path, body, userId: owner.id });
  assert.equal(response.status, 200, `${path} answered ${response.status}`);
  return await response.json() as T;
}

// Column overrides for one membership row, plus the member's direct collection access. Partial
// `permissions` are completed with EMPTY_PERMISSIONS the way the member dialog sends them.
export type MembershipSeed = Omit<Partial<MembershipRecord>, 'permissions'> & {
  permissions?: Partial<OrgPermissions> | null;
  collections?: CollectionAccess[];
};

// One membership row of `orgId`: a confirmed plain User with no account bound, unless overridden.
// Only confirming a member stores the org key, so other statuses keep it empty as the invite flow
// does. Returns the membership id.
export async function seedMembership(env: Env, orgId: string, { collections, permissions = null, ...fields }: MembershipSeed = {}): Promise<string> {
  const now = new Date().toISOString();
  const status = fields.status ?? MembershipStatus.Confirmed;
  const member: MembershipRecord = {
    id: crypto.randomUUID(),
    userId: null,
    orgId,
    email: null,
    invitedByEmail: null,
    accessAll: false,
    key: status === MembershipStatus.Confirmed ? TEST_ORG_KEY : '',
    status,
    type: MembershipType.User,
    permissions: permissions && { ...EMPTY_PERMISSIONS, ...permissions },
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
    ...fields,
  };
  await orgRepo.saveMembershipWithAccess(env.DB, member, { collections });
  return member.id;
}

// A new account, seeded with the `user` overrides, holding a membership of `orgId`.
export async function seedMember(
  env: Env, orgId: string, { user: account, ...membership }: MembershipSeed & { user?: Partial<User> } = {},
): Promise<{ user: User; memberId: string }> {
  const user = await seedUser(env, account);
  return { user, memberId: await seedMembership(env, orgId, { userId: user.id, email: user.email, ...membership }) };
}

// An org its owner created by posting `createBody` to `createPath`, plus a confirmed Admin.
export async function seedSmOrg(
  env: Env,
  createPath: string = ORG_CREATE_PATHS[0],
  createBody: unknown = { name: TEST_ORG_NAME, key: TEST_ORG_KEY },
): Promise<SmOrg> {
  const owner = await seedUser(env);
  const created = await authedFetch(env, { method: 'POST', path: createPath, body: createBody, userId: owner.id });
  if (!created.ok) throw new Error(`seedSmOrg: ${createPath} answered ${created.status}`);
  const { id: orgId } = await created.json() as { id: string };
  return { orgId, owner, admin: (await seedMember(env, orgId, { type: MembershipType.Admin })).user };
}

// An org `owner` created directly, as the create routes are covered on their own.
export async function createOrg(env: Env, owner: User): Promise<string> {
  return (await createOwnedOrganization(env, owner, { name: TEST_ORG_NAME, key: TEST_ORG_KEY })).id;
}

export async function createCollection(env: Env, owner: User, orgId: string): Promise<string> {
  return (await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/collections`, { name: ENCRYPTED_FIELD })).id;
}

export async function createGroup(env: Env, owner: User, orgId: string): Promise<string> {
  return (await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/groups`, { name: 'Group' })).id;
}

export async function errorMessage(response: Response): Promise<string> {
  return ((await response.json()) as { error: string }).error;
}

// One SelectionReadOnly entry, as the collection and member dialogs post and read access.
export interface SelectionReadOnly {
  id: string;
  readOnly: boolean;
  hidePasswords: boolean;
  manage: boolean;
}

export const manageAccess = (id: string): SelectionReadOnly => ({ id, readOnly: false, hidePasswords: false, manage: true });
export const editAccess = (id: string): SelectionReadOnly => ({ id, readOnly: false, hidePasswords: false, manage: false });
export const viewAccess = (id: string): SelectionReadOnly => ({ id, readOnly: true, hidePasswords: false, manage: false });
export const byId = (left: { id: string }, right: { id: string }): number => left.id.localeCompare(right.id);
