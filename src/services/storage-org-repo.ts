import type { Organization, OrganizationUser, OrganizationUserStatus, OrganizationUserType, Collection } from '../types';
import { ORG_USER_STATUS, ORG_USER_TYPE } from '../config/org';

function mapOrganizationRow(row: any): Organization {
  return {
    id: row.id,
    name: row.name,
    privateKey: row.private_key,
    billingEmail: row.billing_email ?? null,
    publicKey: row.public_key ?? null,
    creationDate: row.creation_date,
    revisionDate: row.revision_date,
  };
}

function mapOrganizationUserRow(row: any): OrganizationUser {
  return {
    id: row.id,
    organizationId: row.organization_id,
    userId: row.user_id ?? null,
    email: row.email,
    key: row.key ?? null,
    status: Number(row.status) as OrganizationUserStatus,
    type: Number(row.type) as OrganizationUserType,
    accessAll: !!row.access_all,
    creationDate: row.creation_date,
    revisionDate: row.revision_date,
  };
}

const ORGANIZATION_USER_COLUMNS =
  'id, organization_id, user_id, email, key, status, type, access_all, creation_date, revision_date';

export async function getOrganization(db: D1Database, id: string): Promise<Organization | null> {
  const row = await db
    .prepare('SELECT id, name, private_key, billing_email, public_key, creation_date, revision_date FROM organizations WHERE id = ?')
    .bind(id)
    .first<any>();
  return row ? mapOrganizationRow(row) : null;
}

export async function saveOrganization(db: D1Database, organization: Organization): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organizations(id, name, private_key, billing_email, public_key, creation_date, revision_date) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET name=excluded.name, private_key=excluded.private_key, billing_email=excluded.billing_email, public_key=excluded.public_key, revision_date=excluded.revision_date'
    )
    .bind(
      organization.id,
      organization.name,
      organization.privateKey,
      organization.billingEmail ?? null,
      organization.publicKey ?? null,
      organization.creationDate,
      organization.revisionDate
    )
    .run();
}

export async function deleteOrganization(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organizations WHERE id = ?').bind(id).run();
}

// Create an organization together with its first (owner) membership and the
// optional default collection in a single atomic D1 batch — a crash mid-flow
// can never leave an ownerless organization behind.
export async function createOrganizationWithOwner(
  db: D1Database,
  organization: Organization,
  organizationUser: OrganizationUser,
  defaultCollection?: Collection | null
): Promise<void> {
  const statements: D1PreparedStatement[] = [
    db
      .prepare(
        'INSERT INTO organizations(id, name, private_key, billing_email, public_key, creation_date, revision_date) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        organization.id,
        organization.name,
        organization.privateKey,
        organization.billingEmail ?? null,
        organization.publicKey ?? null,
        organization.creationDate,
        organization.revisionDate
      ),
    db
      .prepare(
        'INSERT INTO organization_users(id, organization_id, user_id, email, key, status, type, access_all, creation_date, revision_date) ' +
        'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      )
      .bind(
        organizationUser.id,
        organizationUser.organizationId,
        organizationUser.userId,
        organizationUser.email,
        organizationUser.key ?? null,
        Number(organizationUser.status),
        Number(organizationUser.type),
        organizationUser.accessAll ? 1 : 0,
        organizationUser.creationDate,
        organizationUser.revisionDate
      ),
  ];
  if (defaultCollection) {
    statements.push(
      db
        .prepare(
          'INSERT INTO collections(id, organization_id, name, external_id, creation_date, revision_date) ' +
          'VALUES(?, ?, ?, ?, ?, ?)'
        )
        .bind(
          defaultCollection.id,
          defaultCollection.organizationId,
          defaultCollection.name,
          defaultCollection.externalId ?? null,
          defaultCollection.creationDate,
          defaultCollection.revisionDate
        )
    );
  }
  await db.batch(statements);
}

// Delete an organization in a single statement that simultaneously proves the
// caller is a confirmed Owner of it — authorization and deletion cannot drift
// apart. Returns false when no such organization/owner combination exists.
export async function deleteOrganizationForOwner(
  db: D1Database,
  organizationId: string,
  ownerUserId: string
): Promise<boolean> {
  const result = await db
    .prepare(
      'DELETE FROM organizations WHERE id = ? AND EXISTS (' +
        'SELECT 1 FROM organization_users ou ' +
        'WHERE ou.organization_id = organizations.id AND ou.user_id = ? AND ou.type = ${ORG_USER_TYPE.OWNER} AND ou.status = ${ORG_USER_STATUS.CONFIRMED}' +
      ')'
    )
    .bind(organizationId, ownerUserId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function getOrganizationUser(db: D1Database, id: string): Promise<OrganizationUser | null> {
  const row = await db
    .prepare(`SELECT ${ORGANIZATION_USER_COLUMNS} FROM organization_users WHERE id = ?`)
    .bind(id)
    .first<any>();
  return row ? mapOrganizationUserRow(row) : null;
}

export async function getOrganizationUserByEmail(
  db: D1Database,
  organizationId: string,
  email: string
): Promise<OrganizationUser | null> {
  const row = await db
    .prepare(`SELECT ${ORGANIZATION_USER_COLUMNS} FROM organization_users WHERE organization_id = ? AND email = ?`)
    .bind(organizationId, email)
    .first<any>();
  return row ? mapOrganizationUserRow(row) : null;
}

export async function getOrganizationUserForUser(
  db: D1Database,
  organizationId: string,
  userId: string
): Promise<OrganizationUser | null> {
  const row = await db
    .prepare(`SELECT ${ORGANIZATION_USER_COLUMNS} FROM organization_users WHERE organization_id = ? AND user_id = ?`)
    .bind(organizationId, userId)
    .first<any>();
  return row ? mapOrganizationUserRow(row) : null;
}

export async function listOrganizationUsers(db: D1Database, organizationId: string): Promise<OrganizationUser[]> {
  const result = await db
    .prepare(`SELECT ${ORGANIZATION_USER_COLUMNS} FROM organization_users WHERE organization_id = ? ORDER BY creation_date ASC`)
    .bind(organizationId)
    .all<any>();
  return (result.results || []).map(mapOrganizationUserRow);
}

export async function saveOrganizationUser(db: D1Database, organizationUser: OrganizationUser): Promise<void> {
  await db
    .prepare(
      'INSERT INTO organization_users(id, organization_id, user_id, email, key, status, type, access_all, creation_date, revision_date) ' +
      'VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
      'ON CONFLICT(id) DO UPDATE SET ' +
      'user_id=excluded.user_id, email=excluded.email, key=excluded.key, status=excluded.status, type=excluded.type, access_all=excluded.access_all, revision_date=excluded.revision_date'
    )
    .bind(
      organizationUser.id,
      organizationUser.organizationId,
      organizationUser.userId,
      organizationUser.email,
      organizationUser.key ?? null,
      Number(organizationUser.status),
      Number(organizationUser.type),
      organizationUser.accessAll ? 1 : 0,
      organizationUser.creationDate,
      organizationUser.revisionDate
    )
    .run();
}

export async function deleteOrganizationUser(db: D1Database, id: string): Promise<void> {
  await db.prepare('DELETE FROM organization_users WHERE id = ?').bind(id).run();
}

// Delete a membership in one statement that refuses to remove the last
// confirmed Owner of the organization — the correlated count re-evaluates at
// execution time and D1 serializes writes, so two concurrent owners demoting
// or removing each other cannot both succeed (a check-then-act count would
// let both through and strand an ownerless org). Returns false when the row
// is missing or it is the last confirmed Owner.
export async function deleteOrganizationUserGuardingLastOwner(
  db: D1Database,
  organizationUserId: string
): Promise<boolean> {
  const result = await db
    .prepare(
      'DELETE FROM organization_users WHERE id = ? AND (type != 0 OR (' +
      'SELECT COUNT(*) FROM organization_users o2 ' +
      'WHERE o2.organization_id = organization_users.organization_id AND o2.type = ' + ORG_USER_TYPE.OWNER + ' AND o2.status = ' + ORG_USER_STATUS.CONFIRMED +
      ') > 1)'
    )
    .bind(organizationUserId)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function countOrganizationOwners(db: D1Database, organizationId: string): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM organization_users WHERE organization_id = ? AND type = ' + ORG_USER_TYPE.OWNER)
    .bind(organizationId)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function countConfirmedOrganizationOwners(
  db: D1Database,
  organizationId: string
): Promise<number> {
  const row = await db
    .prepare('SELECT COUNT(*) AS count FROM organization_users WHERE organization_id = ? AND type = ${ORG_USER_TYPE.OWNER} AND status = ${ORG_USER_STATUS.CONFIRMED}')
    .bind(organizationId)
    .first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function listConfirmedOrganizationUserIds(
  db: D1Database,
  organizationId: string
): Promise<Array<{ id: string; userId: string }>> {
  const result = await db
    .prepare(
      `SELECT id, user_id FROM organization_users WHERE organization_id = ? AND status = ${ORG_USER_STATUS.CONFIRMED} AND user_id IS NOT NULL`
    )
    .bind(organizationId)
    .all<{ id: string; user_id: string }>();
  return (result.results || []).map((row) => ({ id: row.id, userId: row.user_id }));
}

// Confirmed organization memberships for a user, joined with the organization
// row so profile/sync can build their responses without extra queries.
export interface UserOrganizationMembership {
  organization: Organization;
  organizationUser: OrganizationUser;
}

export async function listConfirmedOrganizationsForUser(
  db: D1Database,
  userId: string
): Promise<UserOrganizationMembership[]> {
  const result = await db
    .prepare(
      `SELECT o.id AS org_id, o.name AS org_name, o.private_key AS org_private_key, o.billing_email AS org_billing_email,
              o.public_key AS org_public_key, o.creation_date AS org_creation_date, o.revision_date AS org_revision_date,
              ou.id AS ou_id, ou.organization_id AS ou_organization_id, ou.user_id AS ou_user_id, ou.email AS ou_email,
              ou.key AS ou_key, ou.status AS ou_status, ou.type AS ou_type, ou.access_all AS ou_access_all,
              ou.creation_date AS ou_creation_date, ou.revision_date AS ou_revision_date
       FROM organization_users ou
       JOIN organizations o ON o.id = ou.organization_id
       WHERE ou.user_id = ? AND ou.status = ${ORG_USER_STATUS.CONFIRMED}
       ORDER BY ou.creation_date ASC`
    )
    .bind(userId)
    .all<any>();
  return (result.results || []).map((row) => ({
    organization: mapOrganizationRow({
      id: row.org_id,
      name: row.org_name,
      private_key: row.org_private_key,
      billing_email: row.org_billing_email,
      public_key: row.org_public_key,
      creation_date: row.org_creation_date,
      revision_date: row.org_revision_date,
    }),
    organizationUser: mapOrganizationUserRow({
      id: row.ou_id,
      organization_id: row.ou_organization_id,
      user_id: row.ou_user_id,
      email: row.ou_email,
      key: row.ou_key,
      status: row.ou_status,
      type: row.ou_type,
      access_all: row.ou_access_all,
      creation_date: row.ou_creation_date,
      revision_date: row.ou_revision_date,
    }),
  }));
}

// Link an organization user row to a registered account by email. Used when a
// user registers with an email that has pending organization invitations and
// when invitations are created for an email that is already registered.
export async function linkOrganizationUsersByEmail(db: D1Database, userId: string, email: string): Promise<void> {
  await db
    .prepare('UPDATE organization_users SET user_id = ?, revision_date = ? WHERE email = ? AND user_id IS NULL')
    .bind(userId, new Date().toISOString(), email)
    .run();
}

// All linked memberships for a user, any status (pending invitations included).
export async function listOrganizationsForUser(
  db: D1Database,
  userId: string
): Promise<UserOrganizationMembership[]> {
  const result = await db
    .prepare(
      `SELECT o.id AS org_id, o.name AS org_name, o.private_key AS org_private_key, o.billing_email AS org_billing_email,
              o.public_key AS org_public_key, o.creation_date AS org_creation_date, o.revision_date AS org_revision_date,
              ou.id AS ou_id, ou.organization_id AS ou_organization_id, ou.user_id AS ou_user_id, ou.email AS ou_email,
              ou.key AS ou_key, ou.status AS ou_status, ou.type AS ou_type, ou.access_all AS ou_access_all,
              ou.creation_date AS ou_creation_date, ou.revision_date AS ou_revision_date
       FROM organization_users ou
       JOIN organizations o ON o.id = ou.organization_id
       WHERE ou.user_id = ?
       ORDER BY ou.creation_date ASC`
    )
    .bind(userId)
    .all<any>();
  return (result.results || []).map((row) => ({
    organization: mapOrganizationRow({
      id: row.org_id,
      name: row.org_name,
      private_key: row.org_private_key,
      billing_email: row.org_billing_email,
      public_key: row.org_public_key,
      creation_date: row.org_creation_date,
      revision_date: row.org_revision_date,
    }),
    organizationUser: mapOrganizationUserRow({
      id: row.ou_id,
      organization_id: row.ou_organization_id,
      user_id: row.ou_user_id,
      email: row.ou_email,
      key: row.ou_key,
      status: row.ou_status,
      type: row.ou_type,
      access_all: row.ou_access_all,
      creation_date: row.ou_creation_date,
      revision_date: row.ou_revision_date,
    }),
  }));
}

// Status-preconditioned membership transition: a plain UPDATE with an
// expected-status guard. Returns false when the row is missing or its status
// changed concurrently (e.g. the membership was removed between the
// handler's read and this write), which makes delete-vs-write interleavings
// fail cleanly instead of resurrecting deleted rows via the upsert in
// saveOrganizationUser.
export async function transitionOrganizationUserStatus(
  db: D1Database,
  organizationUserId: string,
  expectedStatus: number,
  fields: {
    status?: number;
    key?: string | null;
    userId?: string | null;
    type?: number;
    accessAll?: boolean;
  },
  options: { guardLastOwner?: boolean } = {}
): Promise<boolean> {
  const sets: string[] = [];
  const values: unknown[] = [];
  if (fields.status !== undefined) {
    sets.push('status = ?');
    values.push(Number(fields.status));
  }
  if (fields.key !== undefined) {
    sets.push('key = ?');
    values.push(fields.key);
  }
  if (fields.userId !== undefined) {
    sets.push('user_id = ?');
    values.push(fields.userId);
  }
  if (fields.type !== undefined) {
    sets.push('type = ?');
    values.push(Number(fields.type));
  }
  if (fields.accessAll !== undefined) {
    sets.push('access_all = ?');
    values.push(fields.accessAll ? 1 : 0);
  }
  if (!sets.length) return false;
  sets.push('revision_date = ?');
  values.push(new Date().toISOString());
  // Optional last-owner guard (see deleteOrganizationUserGuardingLastOwner):
  // the write to an Owner row only commits while another confirmed Owner
  // exists, evaluated atomically with the UPDATE. Used by the member-update
  // path so a concurrent demote of the other owner cannot leave the org
  // ownerless even when both requests passed the handler's upfront count.
  const lastOwnerGuard = options.guardLastOwner
    ? ' AND (type != 0 OR (' +
      'SELECT COUNT(*) FROM organization_users o2 ' +
      'WHERE o2.organization_id = organization_users.organization_id AND o2.type = ' + ORG_USER_TYPE.OWNER + ' AND o2.status = ' + ORG_USER_STATUS.CONFIRMED +
      ') > 1)'
    : '';
  const result = await db
    .prepare(
      `UPDATE organization_users SET ${sets.join(', ')} WHERE id = ? AND status = ?${lastOwnerGuard}`
    )
    .bind(...values, organizationUserId, Number(expectedStatus))
    .run();
  return (result.meta.changes ?? 0) > 0;
}
