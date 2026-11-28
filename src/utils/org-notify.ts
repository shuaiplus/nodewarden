import type { Env } from '../types';
import { StorageService } from '../services/storage';
import { notifyUserVaultSync } from '../durable/notifications-hub';
import { readActingDeviceIdentifier } from './device';

// Fan out a revision bump + sync push to every confirmed member of an
// organization. Organization data lives in every member's sync payload, so any
// org change (cipher, collection, membership, permissions) invalidates every
// member's cached sync response.
export async function bumpOrganizationMembers(
  request: Request,
  env: Env,
  storage: StorageService,
  organizationId: string,
  exceptUserId?: string
): Promise<void> {
  const members = await storage.listConfirmedOrganizationUserIds(organizationId);
  const contextId = readActingDeviceIdentifier(request);
  for (const member of members) {
    if (exceptUserId && member.userId === exceptUserId) continue;
    const revisionDate = await storage.updateRevisionDate(member.userId);
    notifyUserVaultSync(env, member.userId, revisionDate, contextId);
  }
}
