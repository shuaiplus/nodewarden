import { MembershipStatus, MembershipType } from '../../src/services/org-types';
import * as orgRepo from '../../src/services/storage-org-repo';
import type { Env, User } from '../../src/types';
import { authedFetch, seedUser } from './env';

// The server stores org and membership keys as sent, so any EncString-shaped value will do.
export const TEST_ORG_KEY = '4.dGVzdA==';

// Official web creates an org through POST /organizations, or self-hosted through the license
// upload, which NodeWarden accepts with any JSON.
export const ORG_CREATE_PATHS = ['/api/organizations', '/api/organizations/licenses/self-hosted'] as const;

export interface SmOrg {
  orgId: string;
  owner: User;
  admin: User;
}

// A new account holding a membership of `orgId` in the given role and status. Only confirming a
// member stores the org key, so earlier statuses keep it empty as the invite flow does.
export async function seedMember(env: Env, orgId: string, type: number, status: number = MembershipStatus.Confirmed): Promise<User> {
  const user = await seedUser(env);
  const now = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, {
    id: crypto.randomUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: false,
    key: status === MembershipStatus.Confirmed ? TEST_ORG_KEY : '',
    status,
    type,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  return user;
}

// An org its owner created by posting `createBody` to `createPath`, plus a confirmed Admin.
export async function seedSmOrg(
  env: Env,
  createPath: string = ORG_CREATE_PATHS[0],
  createBody: unknown = { name: 'Acme', key: TEST_ORG_KEY },
): Promise<SmOrg> {
  const owner = await seedUser(env);
  const created = await authedFetch(env, { method: 'POST', path: createPath, body: createBody, userId: owner.id });
  if (!created.ok) throw new Error(`seedSmOrg: ${createPath} answered ${created.status}`);
  const { id: orgId } = await created.json() as { id: string };
  return { orgId, owner, admin: await seedMember(env, orgId, MembershipType.Admin) };
}
