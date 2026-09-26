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

  const admin = await seedUser(env);
  const now = new Date().toISOString();
  await orgRepo.saveMembership(env.DB, {
    id: crypto.randomUUID(),
    userId: admin.id,
    orgId,
    email: admin.email,
    invitedByEmail: null,
    accessAll: false,
    key: TEST_ORG_KEY,
    status: MembershipStatus.Confirmed,
    type: MembershipType.Admin,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  });
  return { orgId, owner, admin };
}
