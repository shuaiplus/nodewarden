import type { Env } from '../types';
import { isActiveMember } from './org-authz';
import { MembershipType } from './org-types';
import { getMembershipByUserAndOrg } from './storage-org-repo';

export type SmActor = { kind: 'admin' | 'user'; membershipId: string } | { kind: 'serviceAccount'; serviceAccountId: string };
export type SmAccess = 'none' | 'read' | 'write';
export interface GrantRows {
  projects: { id: string; write_access: number }[];
  secrets: { id: string; write_access: number }[];
  serviceAccounts: { id: string }[];
}
export interface SmGrants {
  readonly projects: ReadonlyMap<string, SmAccess>;
  readonly secrets: ReadonlyMap<string, SmAccess>;
  readonly serviceAccounts: ReadonlySet<string>;
}
export function maxAccess(...levels: SmAccess[]): SmAccess {
  return levels.includes('write') ? 'write' : levels.includes('read') ? 'read' : 'none';
}
export function grantsFromRows(rows: GrantRows): SmGrants {
  const merge = (items: GrantRows['projects']) => {
    const result = new Map<string, SmAccess>();
    for (const row of items) result.set(row.id, maxAccess(result.get(row.id) ?? 'none', row.write_access ? 'write' : 'read'));
    return result;
  };
  return { projects: merge(rows.projects), secrets: merge(rows.secrets), serviceAccounts: new Set(rows.serviceAccounts.map(row => row.id)) };
}
export function projectAccess(actor: SmActor, grants: SmGrants, id: string): SmAccess {
  return actor.kind === 'admin' ? 'write' : grants.projects.get(id) ?? 'none';
}
export async function resolveSmActor(env: Env, userId: string, orgId: string): Promise<SmActor | null> {
  const member = await getMembershipByUserAndOrg(env.DB, userId, orgId);
  if (!isActiveMember(member)) return null;
  return { kind: member.type <= MembershipType.Admin ? 'admin' : 'user', membershipId: member.id };
}

export function secretAccess(actor: SmActor, grants: SmGrants, secret: { id: string; projectIds: readonly string[] }): SmAccess {
  return actor.kind === 'admin' ? 'write' : maxAccess(grants.secrets.get(secret.id) ?? 'none', ...secret.projectIds.map(id => projectAccess(actor, grants, id)));
}
export function canCreateSecret(actor: SmActor, grants: SmGrants, projectId: string | undefined): boolean {
  return actor.kind === 'admin' || (!!projectId && projectAccess(actor, grants, projectId) === 'write');
}
export function canUpdateSecret(actor: SmActor, grants: SmGrants, secret: { id: string; projectIds: readonly string[] }, requested: readonly string[]): boolean {
  return secretAccess(actor, grants, secret) === 'write' && (actor.kind === 'admin' || secret.projectIds[0] === requested[0] || (!!requested[0] && projectAccess(actor, grants, requested[0]) === 'write'));
}

export function serviceAccountAccess(actor: SmActor, grants: SmGrants, id: string): SmAccess {
  return actor.kind === 'admin' || (actor.kind === 'user' && grants.serviceAccounts.has(id)) ? 'write' : 'none';
}
