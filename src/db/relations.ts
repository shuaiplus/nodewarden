// Relational Queries v2 graph for the NodeWarden D1 schema.
//
// Every relation here mirrors a real foreign key in src/db/schema.ts, plus the
// `.through()` shortcuts across the junction tables so `db.query.*` can hop
// them without materialising the junction rows.
import { defineRelations } from 'drizzle-orm';

import * as schema from './schema';

export const relations = defineRelations(schema, (r) => ({
  users: {
    domainSettings: r.one.domainSettings({ from: r.users.id, to: r.domainSettings.userId }),
    revision: r.one.userRevisions({ from: r.users.id, to: r.userRevisions.userId }),
    ssoUser: r.one.ssoUsers({ from: r.users.id, to: r.ssoUsers.userId }),
    // Personal vault only: org-owned ciphers are reached through the org.
    personalCiphers: r.many.ciphers({
      from: r.users.id,
      to: r.ciphers.userId,
      where: { organizationId: { isNull: true } },
    }),
    ciphers: r.many.ciphers({ from: r.users.id, to: r.ciphers.userId, alias: 'user_all_ciphers' }),
    folders: r.many.folders(),
    sends: r.many.sends(),
    sessions: r.many.session(),
    accounts: r.many.account(),
    twoFactor: r.one.twoFactor({ from: r.users.id, to: r.twoFactor.userId }),
    devices: r.many.devices(),
    authRequests: r.many.authRequests(),
    trustedTwoFactorDeviceTokens: r.many.trustedTwoFactorDeviceTokens(),
    totpLoginReplays: r.many.totpLoginReplays(),
    webauthnCredentials: r.many.webauthnCredentials(),
    auditLogs: r.many.auditLogs(),
    createdInvites: r.many.invites({ from: r.users.id, to: r.invites.createdBy, alias: 'invite_creator' }),
    usedInvites: r.many.invites({ from: r.users.id, to: r.invites.usedBy, alias: 'invite_user' }),
    memberships: r.many.organizationMemberships(),
    grantedEmergencyAccess: r.many.emergencyAccess({
      from: r.users.id,
      to: r.emergencyAccess.grantorId,
      alias: 'emergency_grantor',
    }),
    receivedEmergencyAccess: r.many.emergencyAccess({
      from: r.users.id,
      to: r.emergencyAccess.granteeId,
      alias: 'emergency_grantee',
    }),
    collections: r.many.collections({
      from: r.users.id.through(r.collectionUsers.userId),
      to: r.collections.id.through(r.collectionUsers.collectionId),
    }),
  },

  domainSettings: {
    user: r.one.users({ from: r.domainSettings.userId, to: r.users.id, optional: false }),
  },

  userRevisions: {
    user: r.one.users({ from: r.userRevisions.userId, to: r.users.id, optional: false }),
  },

  ciphers: {
    user: r.one.users({ from: r.ciphers.userId, to: r.users.id, optional: false, alias: 'user_all_ciphers' }),
    attachments: r.many.attachments(),
    collections: r.many.collections({
      from: r.ciphers.id.through(r.cipherCollections.cipherId),
      to: r.collections.id.through(r.cipherCollections.collectionId),
    }),
    cipherCollections: r.many.cipherCollections(),
  },

  folders: {
    user: r.one.users({ from: r.folders.userId, to: r.users.id, optional: false }),
  },

  attachments: {
    cipher: r.one.ciphers({ from: r.attachments.cipherId, to: r.ciphers.id, optional: false }),
  },

  sends: {
    user: r.one.users({ from: r.sends.userId, to: r.users.id, optional: false }),
  },

  session: {
    user: r.one.users({ from: r.session.userId, to: r.users.id, optional: false }),
  },

  account: {
    user: r.one.users({ from: r.account.userId, to: r.users.id, optional: false }),
  },

  twoFactor: {
    user: r.one.users({ from: r.twoFactor.userId, to: r.users.id, optional: false }),
  },

  invites: {
    creator: r.one.users({ from: r.invites.createdBy, to: r.users.id, optional: false, alias: 'invite_creator' }),
    redeemer: r.one.users({ from: r.invites.usedBy, to: r.users.id, alias: 'invite_user' }),
  },

  auditLogs: {
    actor: r.one.users({ from: r.auditLogs.actorUserId, to: r.users.id }),
  },

  devices: {
    user: r.one.users({ from: r.devices.userId, to: r.users.id, optional: false }),
  },

  authRequests: {
    user: r.one.users({ from: r.authRequests.userId, to: r.users.id, optional: false }),
  },

  trustedTwoFactorDeviceTokens: {
    user: r.one.users({ from: r.trustedTwoFactorDeviceTokens.userId, to: r.users.id, optional: false }),
  },

  totpLoginReplays: {
    user: r.one.users({ from: r.totpLoginReplays.userId, to: r.users.id, optional: false }),
  },

  webauthnCredentials: {
    user: r.one.users({ from: r.webauthnCredentials.userId, to: r.users.id, optional: false }),
  },

  organizations: {
    memberships: r.many.organizationMemberships(),
    collections: r.many.collections(),
    groups: r.many.orgGroups(),
    policies: r.many.orgPolicies(),
    apiKeys: r.many.organizationApiKeys(),
    scimToken: r.one.organizationScimTokens({
      from: r.organizations.id,
      to: r.organizationScimTokens.orgId,
    }),
    smProjects: r.many.smProjects(),
    smSecrets: r.many.smSecrets(),
    smServiceAccounts: r.many.smServiceAccounts(),
  },

  organizationMemberships: {
    organization: r.one.organizations({
      from: r.organizationMemberships.orgId,
      to: r.organizations.id,
      optional: false,
    }),
    user: r.one.users({ from: r.organizationMemberships.userId, to: r.users.id }),
    groups: r.many.orgGroups({
      from: r.organizationMemberships.id.through(r.orgGroupMembers.membershipId),
      to: r.orgGroups.id.through(r.orgGroupMembers.groupId),
    }),
  },

  collections: {
    organization: r.one.organizations({ from: r.collections.orgId, to: r.organizations.id, optional: false }),
    users: r.many.users(),
    ciphers: r.many.ciphers(),
    groups: r.many.orgGroups({
      from: r.collections.id.through(r.collectionGroups.collectionId),
      to: r.orgGroups.id.through(r.collectionGroups.groupId),
    }),
    collectionUsers: r.many.collectionUsers(),
    collectionGroups: r.many.collectionGroups(),
  },

  collectionUsers: {
    user: r.one.users({ from: r.collectionUsers.userId, to: r.users.id, optional: false }),
    collection: r.one.collections({
      from: r.collectionUsers.collectionId,
      to: r.collections.id,
      optional: false,
    }),
  },

  cipherCollections: {
    cipher: r.one.ciphers({ from: r.cipherCollections.cipherId, to: r.ciphers.id, optional: false }),
    collection: r.one.collections({
      from: r.cipherCollections.collectionId,
      to: r.collections.id,
      optional: false,
    }),
  },

  orgGroups: {
    organization: r.one.organizations({ from: r.orgGroups.orgId, to: r.organizations.id, optional: false }),
    members: r.many.organizationMemberships(),
    collections: r.many.collections(),
    groupMembers: r.many.orgGroupMembers(),
    collectionGroups: r.many.collectionGroups(),
  },

  orgGroupMembers: {
    group: r.one.orgGroups({ from: r.orgGroupMembers.groupId, to: r.orgGroups.id, optional: false }),
    membership: r.one.organizationMemberships({
      from: r.orgGroupMembers.membershipId,
      to: r.organizationMemberships.id,
      optional: false,
    }),
  },

  collectionGroups: {
    collection: r.one.collections({
      from: r.collectionGroups.collectionId,
      to: r.collections.id,
      optional: false,
    }),
    group: r.one.orgGroups({ from: r.collectionGroups.groupId, to: r.orgGroups.id, optional: false }),
  },

  orgPolicies: {
    organization: r.one.organizations({ from: r.orgPolicies.orgId, to: r.organizations.id, optional: false }),
  },

  organizationApiKeys: {
    organization: r.one.organizations({
      from: r.organizationApiKeys.orgId,
      to: r.organizations.id,
      optional: false,
    }),
  },

  organizationScimTokens: {
    organization: r.one.organizations({
      from: r.organizationScimTokens.orgId,
      to: r.organizations.id,
      optional: false,
    }),
  },

  ssoUsers: {
    user: r.one.users({ from: r.ssoUsers.userId, to: r.users.id, optional: false }),
  },

  smProjects: {
    organization: r.one.organizations({ from: r.smProjects.orgId, to: r.organizations.id, optional: false }),
    secrets: r.many.smSecrets({
      from: r.smProjects.id.through(r.smSecretProjects.projectId),
      to: r.smSecrets.id.through(r.smSecretProjects.secretId),
    }),
    serviceAccounts: r.many.smServiceAccounts({
      from: r.smProjects.id.through(r.smServiceAccountProjects.projectId),
      to: r.smServiceAccounts.id.through(r.smServiceAccountProjects.serviceAccountId),
    }),
    secretProjects: r.many.smSecretProjects(),
    serviceAccountProjects: r.many.smServiceAccountProjects(),
  },

  smSecrets: {
    organization: r.one.organizations({ from: r.smSecrets.orgId, to: r.organizations.id, optional: false }),
    projects: r.many.smProjects(),
    secretProjects: r.many.smSecretProjects(),
  },

  smSecretProjects: {
    secret: r.one.smSecrets({ from: r.smSecretProjects.secretId, to: r.smSecrets.id, optional: false }),
    project: r.one.smProjects({ from: r.smSecretProjects.projectId, to: r.smProjects.id, optional: false }),
  },

  smServiceAccounts: {
    organization: r.one.organizations({
      from: r.smServiceAccounts.orgId,
      to: r.organizations.id,
      optional: false,
    }),
    accessTokens: r.many.smAccessTokens(),
    projects: r.many.smProjects(),
    projectGrants: r.many.smServiceAccountProjects(),
  },

  smServiceAccountProjects: {
    serviceAccount: r.one.smServiceAccounts({
      from: r.smServiceAccountProjects.serviceAccountId,
      to: r.smServiceAccounts.id,
      optional: false,
    }),
    project: r.one.smProjects({ from: r.smServiceAccountProjects.projectId, to: r.smProjects.id, optional: false }),
  },

  smAccessTokens: {
    serviceAccount: r.one.smServiceAccounts({
      from: r.smAccessTokens.serviceAccountId,
      to: r.smServiceAccounts.id,
      optional: false,
    }),
  },

  emergencyAccess: {
    grantor: r.one.users({
      from: r.emergencyAccess.grantorId,
      to: r.users.id,
      optional: false,
      alias: 'emergency_grantor',
    }),
    grantee: r.one.users({ from: r.emergencyAccess.granteeId, to: r.users.id, alias: 'emergency_grantee' }),
  },
}));
