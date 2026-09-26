import { readMailConfig } from '../services/mail';
import type { Env, ProfileResponse, User } from '../types';
import { buildAccountKeys } from './user-decryption';
import { StorageService } from '../services/storage';
import { twoFactorProviders } from '../services/two-factor-providers';
import { isYubiKeyEnabled } from './yubico-otp';
import * as orgRepo from '../services/storage-org-repo';
import { MembershipStatus } from '../services/org-types';
import { isSsoEnabled } from '../handlers/sso';
import { profileOrganizationResponse } from './org-response';

export async function buildProfileResponse(user: User, env?: Env): Promise<ProfileResponse> {
  const organizations: any[] = [];
  if (env?.DB) {
    const memberships = await orgRepo.listMembershipsByUser(env.DB, user.id);
    for (const member of memberships) {
      if (member.status !== MembershipStatus.Confirmed && member.status !== MembershipStatus.Accepted && member.status !== MembershipStatus.Invited) {
        continue;
      }
      const org = await orgRepo.getOrganization(env.DB, member.orgId);
      if (!org) continue;
      organizations.push(profileOrganizationResponse(org, member, { useSso: isSsoEnabled(env), useScim: true }));
    }
  }
  const accountKeys = buildAccountKeys(user);
  const mail = env ? readMailConfig(env) : null;
  const hasTwoFactorPasskey = env?.DB ? await new StorageService(env.DB).countAccountPasskeyCredentialsByUserId(user.id, 'twoFactor') > 0 : false;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    emailVerified: true,
    premium: true,
    premiumFromOrganization: true,
    usesKeyConnector: false,
    masterPasswordHint: user.masterPasswordHint,
    culture: 'en-US',
    twoFactorEnabled: twoFactorProviders(user, hasTwoFactorPasskey).length > 0,
    yubikeyEnabled: isYubiKeyEnabled(user),
    key: user.key,
    privateKey: user.privateKey,
    accountKeys,
    securityStamp: user.securityStamp || user.id,
    organizations,
    organizationsNew: organizations,
    providers: [],
    providerOrganizations: [],
    forcePasswordReset: false,
    avatarColor: null,
    creationDate: user.createdAt,
    verifyDevices: mail?.kind === 'enabled' && mail.newDeviceVerification && !!user.verifyDevices,
    role: user.role,
    status: user.status,
    object: 'profile',
  };
}
