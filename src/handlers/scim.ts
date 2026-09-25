import type { Env } from '../types';
import { StorageService } from '../services/storage';
import * as orgRepo from '../services/storage-org-repo';
import { MembershipStatus, MembershipType } from '../services/org-types';
import { generateUUID } from '../utils/uuid';
import { verifyScimBearer } from './organizations';
import { publishPlatformEvent } from '../services/queue-publisher';

function scimJson(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/scim+json' },
  });
}

function scimError(status: number, detail: string): Response {
  return scimJson({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    status,
    detail,
  }, status);
}

export async function handleScimRoute(request: Request, env: Env, path: string): Promise<Response | null> {
  const match = path.match(/^\/(?:scim\/)?v2\/([a-f0-9-]+)\/(Users|users|Groups|groups)(?:\/([^/]+))?$/i);
  if (!match) return null;
  const orgId = match[1];
  const resource = match[2].toLowerCase();
  const id = match[3] || null;
  const org = await orgRepo.getOrganization(env.DB, orgId);
  if (!org) return scimError(404, 'Organization not found');
  const authorized = await verifyScimBearer(env, orgId, request.headers.get('Authorization'));
  if (!authorized) return scimError(401, 'Invalid SCIM token');

  if (resource === 'users') return handleScimUsers(request, env, orgId, id);
  return handleScimGroups(request, env, orgId, id);
}

async function handleScimUsers(request: Request, env: Env, orgId: string, id: string | null): Promise<Response> {
  const storage = new StorageService(env.DB);
  if (request.method === 'GET' && !id) {
    const members = await orgRepo.listMembershipsByOrg(env.DB, orgId);
    const startIndex = Number(new URL(request.url).searchParams.get('startIndex') || 1);
    const count = Number(new URL(request.url).searchParams.get('count') || 100);
    const slice = members.slice(startIndex - 1, startIndex - 1 + count);
    const resources = [];
    for (const member of slice) {
      const user = member.userId ? await storage.getUserById(member.userId) : null;
      resources.push(scimUser(member.id, user?.email || member.email || '', user?.name || '', member.status !== MembershipStatus.Revoked && member.status > MembershipStatus.Revoked, member.externalId));
    }
    return scimJson({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: members.length,
      startIndex,
      itemsPerPage: count,
      Resources: resources,
    });
  }

  if (request.method === 'GET' && id) {
    const member = await orgRepo.getMembership(env.DB, id);
    if (!member || member.orgId !== orgId) return scimError(404, 'User not found');
    const user = member.userId ? await storage.getUserById(member.userId) : null;
    return scimJson(scimUser(member.id, user?.email || member.email || '', user?.name || '', member.status > MembershipStatus.Revoked, member.externalId));
  }

  if (request.method === 'POST') {
    const body = await request.json() as Record<string, unknown>;
    const email = extractEmail(body);
    if (!email) return scimError(400, 'userName is required');
    const existingUser = await storage.getUser(email);
    const now = new Date().toISOString();
    const member = {
      id: generateUUID(),
      userId: existingUser?.id || null,
      orgId,
      email,
      invitedByEmail: 'scim',
      accessAll: false,
      key: '',
      status: existingUser ? MembershipStatus.Accepted : MembershipStatus.Staged,
      type: MembershipType.User,
      permissions: null,
      resetPasswordKey: null,
      externalId: String(body.externalId || '') || null,
      createdAt: now,
      updatedAt: now,
    };
    await orgRepo.saveMembership(env.DB, member);
    await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
    await publishPlatformEvent(env, { type: 'directory.applied', orgId, resource: 'user', resourceId: member.id });
    return scimJson(scimUser(member.id, email, String((body.name as { formatted?: string } | undefined)?.formatted || ''), true, member.externalId), 201);
  }

  if ((request.method === 'PUT' || request.method === 'PATCH') && id) {
    const member = await orgRepo.getMembership(env.DB, id);
    if (!member || member.orgId !== orgId) return scimError(404, 'User not found');
    const body = await request.json() as Record<string, unknown>;
    const active = extractActive(body, member.status > MembershipStatus.Revoked);
    if (!active && member.status > MembershipStatus.Revoked) member.status = member.status - 128;
    if (active && member.status <= MembershipStatus.Revoked) member.status = member.status + 128;
    if (body.externalId) member.externalId = String(body.externalId);
    member.updatedAt = new Date().toISOString();
    await orgRepo.saveMembership(env.DB, member);
    await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
    const user = member.userId ? await storage.getUserById(member.userId) : null;
    return scimJson(scimUser(member.id, user?.email || member.email || '', user?.name || '', member.status > MembershipStatus.Revoked, member.externalId));
  }

  if (request.method === 'DELETE' && id) {
    const member = await orgRepo.getMembership(env.DB, id);
    if (!member || member.orgId !== orgId) return scimError(404, 'User not found');
    await orgRepo.deleteMembership(env.DB, id);
    await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
    return new Response(null, { status: 204 });
  }

  return scimError(405, 'Method not allowed');
}

async function handleScimGroups(request: Request, env: Env, orgId: string, id: string | null): Promise<Response> {
  if (request.method === 'GET' && !id) {
    const groups = await orgRepo.listGroupsByOrg(env.DB, orgId);
    return scimJson({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: groups.length,
      startIndex: 1,
      itemsPerPage: groups.length,
      Resources: groups.map((group) => scimGroup(group.id, group.name, group.externalId)),
    });
  }
  if (request.method === 'GET' && id) {
    const group = await orgRepo.getGroup(env.DB, id);
    if (!group || group.orgId !== orgId) return scimError(404, 'Group not found');
    return scimJson(scimGroup(group.id, group.name, group.externalId));
  }
  if (request.method === 'POST') {
    const body = await request.json() as Record<string, unknown>;
    const now = new Date().toISOString();
    const group = {
      id: generateUUID(),
      orgId,
      name: String(body.displayName || 'Group'),
      accessAll: false,
      externalId: String(body.externalId || '') || null,
      createdAt: now,
      updatedAt: now,
    };
    await orgRepo.saveGroup(env.DB, group);
    await publishPlatformEvent(env, { type: 'directory.applied', orgId, resource: 'group', resourceId: group.id });
    return scimJson(scimGroup(group.id, group.name, group.externalId), 201);
  }
  if ((request.method === 'PUT' || request.method === 'PATCH') && id) {
    const group = await orgRepo.getGroup(env.DB, id);
    if (!group || group.orgId !== orgId) return scimError(404, 'Group not found');
    const body = await request.json() as Record<string, unknown>;
    if (body.displayName) group.name = String(body.displayName);
    if (body.externalId) group.externalId = String(body.externalId);
    group.updatedAt = new Date().toISOString();
    await orgRepo.saveGroup(env.DB, group);
    return scimJson(scimGroup(group.id, group.name, group.externalId));
  }
  if (request.method === 'DELETE' && id) {
    const group = await orgRepo.getGroup(env.DB, id);
    if (!group || group.orgId !== orgId) return scimError(404, 'Group not found');
    await orgRepo.deleteGroup(env.DB, id);
    return new Response(null, { status: 204 });
  }
  return scimError(405, 'Method not allowed');
}

function scimUser(id: string, email: string, name: string, active: boolean, externalId: string | null) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
    id,
    externalId,
    userName: email,
    displayName: name || email,
    active,
    emails: [{ value: email, primary: true, type: 'work' }],
    meta: { resourceType: 'User' },
  };
}

function scimGroup(id: string, name: string, externalId: string | null) {
  return {
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
    id,
    externalId,
    displayName: name,
    meta: { resourceType: 'Group' },
  };
}

function extractEmail(body: Record<string, unknown>): string {
  if (body.userName) return String(body.userName).trim().toLowerCase();
  const emails = body.emails as Array<{ value?: string }> | undefined;
  return String(emails?.[0]?.value || '').trim().toLowerCase();
}

function extractActive(body: Record<string, unknown>, fallback: boolean): boolean {
  if (typeof body.active === 'boolean') return body.active;
  const operations = body.Operations as Array<{ path?: string; value?: unknown }> | undefined;
  const activeOp = operations?.find((operation) => String(operation.path || '').toLowerCase() === 'active');
  if (typeof activeOp?.value === 'boolean') return activeOp.value;
  return fallback;
}
