import assert from 'node:assert/strict';
import test from 'node:test';
import { createTestEnv, portalFetch, seedUser, signInToAdminPortal } from './support/env';
import { seedMember, seedMembership } from './support/sm';
import { MembershipStatus } from '../services/org-types';
const { createOwnedOrganization } = await import('../handlers/organizations');
import * as orgRepo from '../services/storage-org-repo';
import { getOrm } from '../db/client';
import { auditLogs, organizations, smSecrets, smProjects } from '../db/schema';
import { eq } from 'drizzle-orm';

const email = 'portal@x.io';
test('portal organization searches use literal names and either member email; details show counts only', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: email });
  const auth = await signInToAdminPortal(env, email);
  const owner = await seedUser(env);
  const org = await createOwnedOrganization(env, owner, { name: '<img src=x onerror=bad()> 50%', key: '4.dGVzdA==' });
  const other = await createOwnedOrganization(env, await seedUser(env), { name: 'other', key: '4.dGVzdA==' });
  await getOrm(env.DB)
    .update(organizations)
    .set({ privateKey: 'DO-NOT-RENDER-PRIVATE-KEY', publicKey: 'DO-NOT-RENDER-PUBLIC-KEY' })
    .where(eq(organizations.id, org.id));
  await seedMembership(env, org.id, { email: 'invitee@x.io', status: MembershipStatus.Invited });
  // A membership row without an email of its own is found through its account.
  const { user: accountOnly } = await seedMember(env, org.id, { email: null });
  for (const memberEmail of ['invitee@x.io', owner.email.toUpperCase(), accountOnly.email.toUpperCase()]) {
    const rows = await orgRepo.searchOrganizations(env.DB, { memberEmail, nameContains: '', offset: 0, limit: 25 });
    assert.deepEqual(
      rows.map((row) => row.id),
      [org.id],
    );
  }
  assert.deepEqual(
    (await orgRepo.searchOrganizations(env.DB, { memberEmail: '', nameContains: '%', offset: 0, limit: 25 })).map(
      (row) => row.id,
    ),
    [org.id],
  );
  await getOrm(env.DB).insert(smProjects).values({
    id: crypto.randomUUID(),
    orgId: org.id,
    name: 'ENCRYPTED-PROJECT-NAME',
    createdAt: org.createdAt,
    updatedAt: org.updatedAt,
  });
  await getOrm(env.DB)
    .insert(smSecrets)
    .values([
      {
        id: crypto.randomUUID(),
        orgId: org.id,
        key: 'ENCRYPTED-SECRET-KEY',
        value: 'ENCRYPTED-SECRET-VALUE',
        createdAt: org.createdAt,
        updatedAt: org.updatedAt,
      },
      {
        id: crypto.randomUUID(),
        orgId: org.id,
        key: 'ENCRYPTED-SECRET-KEY',
        value: 'ENCRYPTED-SECRET-VALUE',
        createdAt: org.createdAt,
        updatedAt: org.updatedAt,
        deletedAt: org.updatedAt,
      },
      {
        id: crypto.randomUUID(),
        orgId: other.id,
        key: 'OTHER-SECRET',
        value: 'OTHER-SECRET',
        createdAt: org.createdAt,
        updatedAt: org.updatedAt,
      },
    ]);
  const response = await portalFetch(env, { path: `/admin/organizations/view/${org.id}`, cookie: auth.cookie });
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /&lt;img src=x/);
  assert.match(body, /<dt>SM secrets<\/dt>\s*<dd>1<\/dd>/);
  assert.match(body, /<dt>SM projects<\/dt>\s*<dd>1<\/dd>/);
  assert.match(body, /<dt>Invited<\/dt>\s*<dd>1<\/dd>/);
  assert.match(body, /<dt>Has keys<\/dt>\s*<dd>Yes<\/dd>/);
  assert.doesNotMatch(body, /DO-NOT-RENDER|ENCRYPTED-|OTHER-SECRET/);
});

test('portal organization deletion validates confirmation and audits the atomic deletion', async () => {
  const env = await createTestEnv({ ADMIN_EMAILS: email });
  const auth = await signInToAdminPortal(env, email);
  const org = await createOwnedOrganization(env, await seedUser(env), { name: 'Delete me', key: '4.dGVzdA==' });
  const path = `/admin/organizations/delete/${org.id}`;
  assert.equal(
    (
      await portalFetch(env, {
        path,
        method: 'POST',
        cookie: auth.cookie,
        form: { csrf: auth.csrf, confirmation: 'wrong' },
      })
    ).status,
    400,
  );
  assert.equal(
    (await portalFetch(env, { path, method: 'POST', cookie: auth.cookie, form: { confirmation: org.name } })).status,
    403,
  );
  assert.equal(
    (
      await portalFetch(env, {
        path,
        method: 'POST',
        cookie: auth.cookie,
        form: { csrf: auth.csrf, confirmation: org.name },
      })
    ).status,
    303,
  );
  assert.equal(await orgRepo.getOrganization(env.DB, org.id), null);
  assert.ok(await getOrm(env.DB).$count(auditLogs, eq(auditLogs.action, 'admin.portal.org.delete')));
  assert.equal(
    (await portalFetch(env, { path: `/admin/organizations/view/${org.id}`, cookie: auth.cookie })).status,
    404,
  );
});
