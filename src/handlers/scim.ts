import { z } from 'zod';
import type { Env } from '../types';
import * as orgRepo from '../services/storage-org-repo';
import { MembershipStatus, MembershipType } from '../services/org-types';
import { generateUUID } from '../utils/uuid';
import { mailOrganizationInvites, verifyScimBearer } from './organizations';
import { publishPlatformEvent } from '../services/queue-publisher';
import * as userRepo from '../services/storage-user-repo';

function scimJson(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/scim+json', ...headers },
  });
}

function scimError(status: number, detail: string, headers: Record<string, string> = {}): Response {
  return scimJson({
    schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
    status,
    detail,
  }, status, headers);
}

// IdPs send loosely typed PATCH values, so an active that is not a boolean is ignored rather than rejected.
const scimActive = z.boolean().optional().catch(undefined);

const ScimUserRequest = z.object({
  userName: z.string().nullish(),
  emails: z.array(z.object({ value: z.string().nullish() })).nullish(),
  externalId: z.string().nullish(),
  name: z.object({ formatted: z.string().nullish() }).nullish(),
  active: scimActive,
  Operations: z.array(z.object({ path: z.string().nullish(), value: scimActive })).nullish(),
}).transform(({ userName, emails, externalId, name, active, Operations }) => ({
  email: (userName || emails?.[0]?.value || '').trim().toLowerCase(),
  externalId: externalId || null,
  displayName: name?.formatted || '',
  // A replaced active wins over the first PATCH operation on the active path.
  active: active ?? Operations?.find((operation) => operation.path?.toLowerCase() === 'active')?.value,
}));

const ScimGroupRequest = z.object({ displayName: z.string().nullish(), externalId: z.string().nullish() });

// SCIM payloads answer in the SCIM error format rather than Bitwarden's.
async function readScimBody<S extends z.ZodType>(request: Request, schema: S): Promise<z.output<S> | Response> {
  const result = schema.safeParse(await request.json().catch(() => undefined));
  return result.success ? result.data : scimError(400, result.error.issues[0].message);
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

  if (resource === 'users') {
    if (request.method === 'GET' && !id) {
      const members = await orgRepo.listMembershipsByOrg(env.DB, orgId);
      const startIndex = Number(new URL(request.url).searchParams.get('startIndex') || 1);
      const count = Number(new URL(request.url).searchParams.get('count') || 100);
      const slice = members.slice(startIndex - 1, startIndex - 1 + count);
      const resources = [];
      for (const member of slice) {
        const user = member.userId ? await userRepo.getUserById(env.DB, member.userId) : null;
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
      const user = member.userId ? await userRepo.getUserById(env.DB, member.userId) : null;
      return scimJson(scimUser(member.id, user?.email || member.email || '', user?.name || '', member.status > MembershipStatus.Revoked, member.externalId));
    }

    if (request.method === 'POST') {
      const body = await readScimBody(request, ScimUserRequest);
      if (body instanceof Response) return body;
      const { email, externalId } = body;
      if (!email) return scimError(400, 'userName is required');
      // Upstream PostUserCommand: a known member or externalId is a conflict, so an IdP replay after a
      // lost 201 neither mails a second invite nor adds a duplicate row. Bound rows carry the account email.
      const members = await orgRepo.listMembershipsWithAccountsByOrg(env.DB, orgId);
      const conflict = members.some(({ item, account }) =>
        (account?.email ?? item.email)?.toLowerCase() === email || (externalId !== null && item.externalId === externalId));
      if (conflict) return scimError(409, 'User already exists.');
      const existingUser = await userRepo.getUser(env.DB, email);
      const now = new Date().toISOString();
      // Upstream PostUserCommand never binds the account: only the invitee's own accept may do that,
      // otherwise any org owner could mint a SCIM token and force an existing user into the org.
      const member = {
        id: generateUUID(),
        userId: null,
        orgId,
        email,
        invitedByEmail: 'scim',
        accessAll: false,
        key: '',
        status: existingUser ? MembershipStatus.Invited : MembershipStatus.Staged,
        type: MembershipType.User,
        permissions: null,
        resetPasswordKey: null,
        externalId,
        createdAt: now,
        updatedAt: now,
      };
      // Upstream PostUserCommand invites through the normal invite path, so the invitee gets the token
      // that accept requires. Staged rows have no account to accept with yet. The SCIM token belongs
      // to the org rather than a user, so the org's directory is the inviter that spends the budget.
      if (existingUser) {
        const mailed = await mailOrganizationInvites(request, env, orgId, `scim:${orgId}`, [member]);
        if (!mailed.ok) return scimError(mailed.status, mailed.message, mailed.headers);
      }
      await orgRepo.saveMembership(env.DB, member);
      await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
      await publishPlatformEvent(env, { type: 'directory.applied', orgId, resource: 'user', resourceId: member.id });
      return scimJson(scimUser(member.id, email, body.displayName, true, member.externalId), 201);
    }

    if ((request.method === 'PUT' || request.method === 'PATCH') && id) {
      const member = await orgRepo.getMembership(env.DB, id);
      if (!member || member.orgId !== orgId) return scimError(404, 'User not found');
      const body = await readScimBody(request, ScimUserRequest);
      if (body instanceof Response) return body;
      const active = body.active ?? member.status > MembershipStatus.Revoked;
      if (!active && member.status > MembershipStatus.Revoked) member.status = member.status - 128;
      if (active && member.status <= MembershipStatus.Revoked) member.status = member.status + 128;
      if (body.externalId) member.externalId = body.externalId;
      member.updatedAt = new Date().toISOString();
      await orgRepo.saveMembership(env.DB, member);
      await orgRepo.bumpOrgMemberRevisions(env.DB, orgId);
      const user = member.userId ? await userRepo.getUserById(env.DB, member.userId) : null;
      return scimJson(scimUser(member.id, user?.email || member.email || '', user?.name || '', member.status > MembershipStatus.Revoked, member.externalId));
    }

    if (request.method === 'DELETE' && id) {
      const member = await orgRepo.getMembership(env.DB, id);
      if (!member || member.orgId !== orgId) return scimError(404, 'User not found');
      await orgRepo.applyMembershipAction(env.DB, orgId, [id], 'remove');
      return new Response(null, { status: 204 });
    }

    return scimError(405, 'Method not allowed');
  }

  // The route pattern only admits Users and Groups, so anything else is Groups.
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
    const body = await readScimBody(request, ScimGroupRequest);
    if (body instanceof Response) return body;
    const now = new Date().toISOString();
    const group = {
      id: generateUUID(),
      orgId,
      name: body.displayName || 'Group',
      accessAll: false,
      externalId: body.externalId || null,
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
    const body = await readScimBody(request, ScimGroupRequest);
    if (body instanceof Response) return body;
    if (body.displayName) group.name = body.displayName;
    if (body.externalId) group.externalId = body.externalId;
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
