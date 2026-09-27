import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { events } from '../db/schema';
import { authedFetch, createTestEnv, drainWaitUntil, seedUser } from './support/env';
import { seedMembership } from './support/sm';
import { hashPassword } from '../services/auth-password';
import { MembershipStatus } from '../services/org-types';
import * as userRepo from '../services/storage-user-repo';
const { createOwnedOrganization } = await import('../handlers/organizations');
const PASSWORD = 'event-test-password';
const KEY = '2.dGVzdA==|dGVzdA==|dGVzdA==';

test('real login, failed login, password and factor changes record immutable user/org events once', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, {
    masterPasswordHash: await hashPassword(PASSWORD),
    totpSecret: 'JBSWY3DPEHPK3PXP',
  });
  const org = await createOwnedOrganization(env, user, { name: 'User events', key: '4.dGVzdA==' });
  await getOrm(env.DB).delete(events);
  for (let i = 0; i < 2; i++)
    assert.equal(
      (
        await authedFetch(env, {
          method: 'DELETE',
          path: '/api/two-factor/authenticator',
          userId: user.id,
          body: { masterPasswordHash: PASSWORD },
        })
      ).status,
      204,
    );
  const login = (password: string) =>
    authedFetch(env, {
      method: 'POST',
      path: '/identity/connect/token',
      body: { grant_type: 'password', username: user.email, password },
      headers: { 'Device-Type': '9' },
    });
  assert.equal((await login('wrong-password')).status, 400);
  assert.equal((await login(PASSWORD)).status, 200);
  assert.equal(
    (
      await authedFetch(env, {
        method: 'POST',
        path: '/api/accounts/password',
        userId: user.id,
        body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: 'replacement-hash', key: KEY },
      })
    ).status,
    200,
  );
  await drainWaitUntil();
  const rows = await getOrm(env.DB)
    .select({ type: events.type, actingUserId: events.actingUserId, userId: events.userId })
    .from(events)
    .where(eq(events.organizationId, org.id))
    .orderBy(events.type);
  assert.deepEqual(
    rows.map((row) => row.type),
    [1000, 1001, 1003, 1005],
  );
  assert.ok(rows.every((row) => row.actingUserId === user.id && row.userId === user.id));
  const own = (await (await authedFetch(env, { path: '/api/events', userId: user.id })).json()) as {
    data: { organizationId: string | null; type: number }[];
  };
  assert.deepEqual(own.data.map((row) => row.type).sort(), [1000, 1001, 1003, 1005]);
  assert.ok(own.data.every((row) => row.organizationId === null));
});

test('client export events fan out only to confirmed organizations and factor failures use their own event type', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const acceptedOrg = await createOwnedOrganization(env, owner, { name: 'Accepted only', key: '4.dGVzdA==' });
  const user = await seedUser(env, {
    masterPasswordHash: await hashPassword(PASSWORD),
    totpSecret: 'JBSWY3DPEHPK3PXP',
  });
  const org = await createOwnedOrganization(env, user, { name: 'Confirmed', key: '4.dGVzdA==' });
  await seedMembership(env, acceptedOrg.id, { userId: user.id, email: user.email, status: MembershipStatus.Accepted });
  await getOrm(env.DB).delete(events);
  assert.equal(
    (
      await authedFetch(env, {
        method: 'POST',
        path: '/events/collect',
        userId: user.id,
        body: [{ type: 1007, date: new Date().toISOString(), organizationId: acceptedOrg.id }],
      })
    ).status,
    200,
  );
  assert.equal(
    (
      await authedFetch(env, {
        method: 'POST',
        path: '/identity/connect/token',
        body: {
          grant_type: 'password',
          username: user.email,
          password: PASSWORD,
          twoFactorProvider: '0',
          twoFactorToken: 'wrong',
        },
      })
    ).status,
    400,
  );
  await drainWaitUntil();
  const rows = await getOrm(env.DB).select({ organizationId: events.organizationId, type: events.type }).from(events);
  assert.equal(rows.length, 4);
  assert.equal(rows.filter((row) => row.organizationId === org.id).length, 2);
  assert.equal(rows.filter((row) => row.organizationId === null).length, 2);
  assert.ok(rows.every((row) => row.type === 1006 || row.type === 1007));
  assert.ok(!rows.some((row) => row.organizationId === acceptedOrg.id));
  assert.equal((await userRepo.getUserById(env.DB, user.id))!.totpSecret, user.totpSecret);
});

test('a backdated client export keeps its date only on the personal row', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const org = await createOwnedOrganization(env, user, { name: 'Export review', key: '4.dGVzdA==' });
  await getOrm(env.DB).delete(events);
  const backdated = '2001-01-01T00:00:00.000Z';
  const before = new Date().toISOString();
  assert.equal(
    (
      await authedFetch(env, {
        method: 'POST',
        path: '/events/collect',
        userId: user.id,
        body: [{ type: 1007, date: backdated }],
      })
    ).status,
    200,
  );
  const rows = await getOrm(env.DB)
    .select({ organizationId: events.organizationId, date: events.date })
    .from(events)
    .where(eq(events.type, 1007));
  assert.equal(rows.find((row) => row.organizationId === null)?.date, backdated);
  const orgRow = rows.find((row) => row.organizationId === org.id);
  assert.ok(orgRow && orgRow.date >= before, 'the organization copy carries receipt time');
  const listed = (await (
    await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: user.id })
  ).json()) as { data: { type: number }[] };
  assert.ok(
    listed.data.some((event) => event.type === 1007),
    'the export appears in the default organization window',
  );
});
