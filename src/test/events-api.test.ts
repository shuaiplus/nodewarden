import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { getOrm } from '../db/client';
import { ciphers, events, users } from '../db/schema';
import { createTestEnv, authedFetch, seedUser, wrapStatements } from './support/env';
import { seedMember } from './support/sm';
import { EventType, recordEvents, pruneEvents } from '../services/events';
import { saveAuditLogSettings } from '../services/audit-events';
import { MembershipType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import type { Env, User } from '../types';
import { LIMITS } from '../config/limits';
import * as cipherRepo from '../services/storage-cipher-repo';
const { createOwnedOrganization } = await import('../handlers/organizations');
const ENC = '2.dGVzdA==|dGVzdA==|dGVzdA==';

async function setup() {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const org = await createOwnedOrganization(env, owner, { name: 'Event test', key: '4.dGVzdA==' });
  await getOrm(env.DB).delete(events);
  return { env, owner, org };
}
async function cipher(env: Env, owner: User, orgId: string | null) {
  const id = crypto.randomUUID();
  await cipherRepo.saveCipher(env.DB, {
    id,
    userId: owner.id,
    organizationId: orgId,
    type: 1,
    folderId: null,
    name: ENC,
    notes: null,
    favorite: false,
    data: '{}',
    key: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    deletedAt: null,
  });
  return id;
}
const count = (env: Env) => getOrm(env.DB).$count(events);
type EventRow = {
  type: number;
  date: string;
  actingUserId: string | null;
  userId: string | null;
  organizationId: string | null;
  cipherId: string | null;
  ipAddress: string | null;
  deviceType: number | null;
};
type EventPage = { data: EventRow[]; continuationToken: string | null; object: string };

test('event queries page equal timestamps without loss and validate dates and URL-safe cursors', async () => {
  const { env, owner, org } = await setup();
  const date = new Date().toISOString();
  const resources = Array.from({ length: 63 }, () => crypto.randomUUID());
  await recordEvents(
    env,
    new Request('https://vault.test', { headers: { 'CF-Connecting-IP': '203.0.113.77', 'Device-Type': '9' } }),
    { userId: owner.id },
    resources.map((resourceId) => ({
      type: EventType.CipherCreated,
      organizationId: org.id,
      resourceType: 'cipher',
      resourceId,
      date,
    })),
  );
  const path = `/api/organizations/${org.id}/events`;
  const first = await authedFetch(env, { path, userId: owner.id });
  assert.equal(first.status, 200);
  const page1 = (await first.json()) as EventPage;
  assert.equal(page1.object, 'list');
  assert.equal(page1.data.length, 50);
  assert.match(page1.continuationToken!, /^[A-Za-z0-9_-]+$/);
  assert.equal(page1.data[0].ipAddress, '203.0.113.77');
  assert.equal(page1.data[0].deviceType, 9);
  const page2 = (await (
    await authedFetch(env, { path: `${path}?continuationToken=${page1.continuationToken}`, userId: owner.id })
  ).json()) as EventPage;
  assert.equal(page2.data.length, 13);
  assert.equal(page2.continuationToken, null);
  assert.deepEqual(new Set([...page1.data, ...page2.data].map((event) => event.cipherId)), new Set(resources));
  for (const query of [
    'start=bad',
    'start=2020-01-01&end=2026-01-01',
    'continuationToken=bad!',
    'continuationToken=W10',
  ])
    assert.equal((await authedFetch(env, { path: `${path}?${query}`, userId: owner.id })).status, 400, query);
  const yesterday = new Date(Date.now() - 86_400_000).toISOString();
  const tomorrow = new Date(Date.now() + 86_400_000).toISOString();
  assert.equal(
    (
      (await (
        await authedFetch(env, { path: `${path}?start=${tomorrow}&end=${yesterday}`, userId: owner.id })
      ).json()) as EventPage
    ).data.length,
    50,
  );
});

test('continuation walks every page in date then id order when page boundaries fall between and within timestamps', async () => {
  const { env, owner, org } = await setup();
  const SHARED_PER_TIMESTAMP = 7;
  const base = Date.now() - 3_600_000;
  const resources = Array.from({ length: 130 }, () => crypto.randomUUID());
  await recordEvents(
    env,
    null,
    { userId: owner.id },
    resources.map((resourceId, index) => ({
      type: EventType.CipherCreated,
      organizationId: org.id,
      resourceType: 'cipher',
      resourceId,
      date: new Date(base - Math.floor(index / SHARED_PER_TIMESTAMP) * 60_000).toISOString(),
    })),
  );
  const path = `/api/organizations/${org.id}/events`;
  const pages: EventPage[] = [];
  for (let token: string | null = ''; token !== null;) {
    const page = (await (
      await authedFetch(env, { path: token ? `${path}?continuationToken=${token}` : path, userId: owner.id })
    ).json()) as EventPage;
    pages.push(page);
    token = page.continuationToken;
  }
  assert.deepEqual(
    pages.map((page) => page.data.length),
    [50, 50, 30],
  );
  const walked = pages.flatMap((page) => page.data);
  assert.deepEqual(
    walked.map((event) => event.cipherId).sort(),
    [...resources].sort(),
    'no event is skipped or repeated',
  );
  assert.ok(
    walked.every((event, index) => index === 0 || walked[index - 1].date >= event.date),
    'pages continue in descending date order',
  );
});

test('event scope is immutable across moves/deletion; membership filters use the actor and permissions remain tenant-bound', async () => {
  const { env, owner, org } = await setup();
  const otherOwner = await seedUser(env);
  const other = await createOwnedOrganization(env, otherOwner, { name: 'Other', key: '4.dGVzdA==' });
  const { user: actor, memberId: actorMembership } = await seedMember(env, org.id, {
    type: MembershipType.Custom,
    permissions: { accessEventLogs: true },
  });
  const { user: ordinary } = await seedMember(env, org.id, {
    type: MembershipType.Custom,
    permissions: { accessEventLogs: false },
  });
  const id = await cipher(env, owner, org.id);
  await getOrm(env.DB).delete(events);
  await recordEvents(env, null, { userId: actor.id }, [
    { type: 1100, organizationId: org.id, resourceType: 'cipher', resourceId: id },
  ]);
  await recordEvents(env, null, { userId: owner.id }, [
    {
      type: 1500,
      organizationId: org.id,
      resourceType: 'organizationUser',
      resourceId: actorMembership,
      userId: actor.id,
    },
  ]);
  const memberEvents = (await (
    await authedFetch(env, { path: `/api/organizations/${org.id}/users/${actorMembership}/events`, userId: owner.id })
  ).json()) as EventPage;
  assert.deepEqual(
    memberEvents.data.map((event) => event.type),
    [1100],
  );
  assert.equal(
    (await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: actor.id })).status,
    200,
    'event permission is independent of vault-item read permission',
  );
  assert.equal(
    (await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: ordinary.id })).status,
    404,
  );
  assert.equal(
    (await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: otherOwner.id })).status,
    404,
  );
  await getOrm(env.DB).update(ciphers).set({ organizationId: other.id }).where(eq(ciphers.id, id));
  assert.equal((await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: actor.id })).status, 404);
  const moved = (await (
    await authedFetch(env, { path: `/api/ciphers/${id}/events`, userId: otherOwner.id })
  ).json()) as EventPage;
  assert.equal(moved.data.length, 0, 'new owner does not inherit previous organization history');
  await getOrm(env.DB).delete(ciphers).where(eq(ciphers.id, id));
  await getOrm(env.DB).delete(users).where(eq(users.id, actor.id));
  const history = (await (
    await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: owner.id })
  ).json()) as EventPage;
  assert.equal(history.data.find((event) => event.type === 1100)?.actingUserId, actor.id);
  assert.equal(history.data.find((event) => event.type === 1100)?.cipherId, id);
  await orgRepo.deleteOrganization(env.DB, org.id);
  assert.equal(await count(env), 0, 'organization deletion removes its event scope');
});

test('collector records authorized client actions, derives actor/scope and hides unknown versus foreign IDs', async () => {
  const { env, owner, org } = await setup();
  const otherOwner = await seedUser(env);
  const other = await createOwnedOrganization(env, otherOwner, { name: 'Other', key: '4.dGVzdA==' });
  const id = await cipher(env, owner, org.id);
  const foreign = await cipher(env, otherOwner, other.id);
  const personal = await cipher(env, owner, null);
  await getOrm(env.DB).delete(events);
  const date = new Date().toISOString();
  const post = (body: unknown, userId = owner.id) =>
    authedFetch(env, {
      method: 'POST',
      path: '/events/collect',
      userId,
      body,
      headers: { 'CF-Connecting-IP': '203.0.113.77', 'Device-Type': '9' },
    });
  assert.equal(
    (
      await post([
        {
          type: 1107,
          cipherId: id,
          date,
          actingUserId: otherOwner.id,
          ipAddress: 'FAKE',
          name: 'PLAINTEXT MUST NOT STORE',
        },
      ])
    ).status,
    200,
  );
  const row = await getOrm(env.DB).select().from(events).get();
  assert.equal(row?.organizationId, org.id);
  assert.equal(row?.actingUserId, owner.id);
  assert.equal(row?.ipAddress, '203.0.113.77');
  assert.ok(!JSON.stringify(row).includes('PLAINTEXT'));
  for (const entry of [
    { type: 1100, cipherId: id },
    { type: 1107, cipherId: foreign },
    { type: 1107, cipherId: crypto.randomUUID() },
    { type: 1107, cipherId: personal },
    { type: 1107, cipherId: id, organizationId: other.id },
  ]) {
    const response = await post([{ ...entry, date }]);
    assert.equal(response.status, 200);
    assert.equal(await response.text(), '');
  }
  assert.equal(await count(env), 1);
  const { user: reader } = await seedMember(env, org.id, {
    type: MembershipType.Custom,
    permissions: { accessEventLogs: true },
  });
  assert.equal((await post([{ type: 1107, cipherId: id, date }], reader.id)).status, 200);
  assert.equal(await count(env), 1, 'log readers cannot claim actions on inaccessible ciphers');
  assert.equal((await post(Array.from({ length: 100 }, () => ({ type: 1111, cipherId: id, date })))).status, 200);
  assert.equal(await count(env), 101);
  assert.equal(
    (await post(Array.from({ length: 250 }, () => ({ type: 1111, cipherId: id, date })))).status,
    200,
    'a whole mobile backlog is accepted',
  );
  assert.equal(await count(env), 351);
  const overCap = Array.from({ length: 100 * LIMITS.rateLimit.apiRequestsPerMinute + 1 }, () => ({
    type: 1107,
    cipherId: id,
    date,
  }));
  for (const body of [[], overCap, [{ type: 1107, cipherId: id, date: 'bad' }]])
    assert.equal((await post(body)).status, 400);
  assert.equal(await count(env), 351);
});

test('collector accepts PascalCase uploads and records organization client events only for members', async () => {
  const { env, owner, org } = await setup();
  const id = await cipher(env, owner, org.id);
  const ownerMembership = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, org.id))!;
  const outsider = await seedUser(env);
  await getOrm(env.DB).delete(events);
  const date = new Date().toISOString();
  const post = (body: unknown, userId = owner.id) =>
    authedFetch(env, { method: 'POST', path: '/events/collect', userId, body });
  assert.equal((await post([{ Type: EventType.CipherClientViewed, CipherId: id, Date: date }])).status, 200);
  const ORGANIZATION_CLIENT_EXPORTED_VAULT = 1602;
  const MEMBER_CLIENT_EVENTS = [1522, 1618, 1619];
  assert.equal(
    (
      await post(
        [ORGANIZATION_CLIENT_EXPORTED_VAULT, ...MEMBER_CLIENT_EVENTS].map((type) => ({
          type,
          organizationId: org.id,
          date,
        })),
      )
    ).status,
    200,
  );
  assert.equal(
    (
      await post(
        [ORGANIZATION_CLIENT_EXPORTED_VAULT, ...MEMBER_CLIENT_EVENTS].map((type) => ({
          type,
          organizationId: org.id,
          date,
        })),
        outsider.id,
      )
    ).status,
    200,
  );
  const rows = await getOrm(env.DB)
    .select({
      type: events.type,
      organizationId: events.organizationId,
      actingUserId: events.actingUserId,
      userId: events.userId,
      resourceType: events.resourceType,
      resourceId: events.resourceId,
    })
    .from(events)
    .orderBy(events.type);
  const row = (type: number, userId: string | null, resourceType: string | null, resourceId: string | null) => ({
    type,
    organizationId: org.id,
    actingUserId: owner.id,
    userId,
    resourceType,
    resourceId,
  });
  assert.deepEqual(
    rows,
    [
      row(EventType.CipherClientViewed, null, 'cipher', id),
      row(MEMBER_CLIENT_EVENTS[0], owner.id, 'organizationUser', ownerMembership.id),
      row(ORGANIZATION_CLIENT_EXPORTED_VAULT, null, null, null),
      row(MEMBER_CLIENT_EVENTS[1], owner.id, 'organizationUser', ownerMembership.id),
      row(MEMBER_CLIENT_EVENTS[2], owner.id, 'organizationUser', ownerMembership.id),
    ],
    'a non-member upload for the organization stores nothing',
  );
});

test('uploads spend a per-minute budget of 100-row batches, counting export copies, apart from vault calls', async (t) => {
  // Freeze the clock so both uploads always fall in the same rate-limit window.
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() });
  const { env, owner, org } = await setup();
  const id = await cipher(env, owner, org.id);
  await getOrm(env.DB).delete(events);
  const date = new Date().toISOString();
  const post = (body: unknown, userId = owner.id) =>
    authedFetch(env, { method: 'POST', path: '/events/collect', userId, body });
  const minuteOfBatches = 100 * LIMITS.rateLimit.apiRequestsPerMinute;
  assert.equal(
    (await post(Array.from({ length: minuteOfBatches }, () => ({ type: 1111, cipherId: id, date })))).status,
    200,
  );
  assert.equal(await count(env), minuteOfBatches);
  const limited = await post([{ type: 1107, cipherId: id, date }]);
  assert.equal(limited.status, 429, 'a client keeps its queue and retries after the window');
  assert.ok(Number(limited.headers.get('Retry-After')) > 0);
  assert.equal(await count(env), minuteOfBatches);
  assert.equal(
    (await authedFetch(env, { path: '/api/accounts/profile', userId: owner.id })).status,
    200,
    'vault calls keep their own budget',
  );

  const exporter = await seedUser(env);
  for (const name of ['First', 'Second']) await createOwnedOrganization(env, exporter, { name, key: '4.dGVzdA==' });
  const exportsOverOneMinute = Math.floor(minuteOfBatches / 3) + 1;
  assert.equal(
    (
      await post(
        Array.from({ length: exportsOverOneMinute }, () => ({ type: 1007, date })),
        exporter.id,
      )
    ).status,
    400,
    'two organization copies per export count toward the budget',
  );
});

test('event cleanup reuses audit retention and deletes at most 1000 rows using receipt time', async () => {
  const { env, owner, org } = await setup();
  await recordEvents(
    env,
    null,
    { userId: owner.id },
    Array.from({ length: 1005 }, () => ({ type: 1600, organizationId: org.id, date: '2099-01-01T00:00:00.000Z' })),
  );
  await getOrm(env.DB).update(events).set({ recordedAt: '2000-01-01T00:00:00.000Z' });
  await pruneEvents(env);
  assert.equal(await count(env), 5);
  await pruneEvents(env);
  assert.equal(await count(env), 0);
});

test('a row-cap audit setting never lets one account flood out another organization history', async () => {
  const { env, owner, org } = await setup();
  const daysAgo = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  await recordEvents(
    env,
    null,
    { userId: owner.id },
    Array.from({ length: 5 }, () => ({ type: 1600, organizationId: org.id })),
  );
  await getOrm(env.DB)
    .update(events)
    .set({ recordedAt: daysAgo(10) });
  const outsider = await seedUser(env);
  await recordEvents(
    env,
    null,
    { userId: outsider.id },
    Array.from({ length: 1005 }, () => ({
      type: EventType.UserClientExportedVault,
      organizationId: null,
      userId: outsider.id,
    })),
  );
  await saveAuditLogSettings(env.DB, { retentionDays: null, maxEntries: 1000 });
  await pruneEvents(env);
  assert.equal(await count(env), 1010, 'recent rows are kept whatever their volume');
  await getOrm(env.DB)
    .update(events)
    .set({ recordedAt: daysAgo(91) })
    .where(eq(events.organizationId, org.id));
  await pruneEvents(env);
  assert.equal(await count(env), 1005, 'row-cap mode still expires events at the default retention age');
  await saveAuditLogSettings(env.DB, { retentionDays: null, maxEntries: null });
  await getOrm(env.DB)
    .update(events)
    .set({ recordedAt: daysAgo(4000) });
  await pruneEvents(env);
  assert.equal(await count(env), 1005, 'disabled retention keeps every event');
});

test('committed server changes survive event-store failure, while client uploads remain retryable', async (t) => {
  t.mock.method(console, 'error', () => {});
  const { env, owner, org } = await setup();
  const id = await cipher(env, owner, org.id);
  wrapStatements(env, (query, statement) => {
    if (/insert into "events"/i.test(query)) throw new Error('Event storage unavailable');
    return statement;
  });
  const password = await authedFetch(env, {
    method: 'POST',
    path: '/api/accounts/password',
    userId: owner.id,
    body: { masterPasswordHash: owner.masterPasswordHash, newMasterPasswordHash: 'replacement-password', key: ENC },
  });
  assert.equal(password.status, 200);
  const deleted = await authedFetch(env, { method: 'DELETE', path: `/api/ciphers/${id}`, userId: owner.id });
  assert.equal(deleted.status, 200);
  assert.ok((await cipherRepo.getCipher(env.DB, id))?.deletedAt);
  const collected = await authedFetch(env, {
    method: 'POST',
    path: '/events/collect',
    userId: owner.id,
    body: [{ type: 1007, date: new Date().toISOString() }],
  });
  assert.equal(collected.status, 500);
  assert.equal(await count(env), 0);
});
