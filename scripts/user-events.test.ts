import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, createTestEnv, drainWaitUntil, seedUser } from './support/env';
import { seedMembership } from './support/sm';
import { hashPassword } from '../src/services/auth-password';
import { MembershipStatus } from '../src/services/org-types';
import * as userRepo from '../src/services/storage-user-repo';
const { createOwnedOrganization } = await import('../src/handlers/organizations');
const PASSWORD = 'event-test-password';
const KEY = '2.dGVzdA==|dGVzdA==|dGVzdA==';

test('real login, failed login, password and factor changes record immutable user/org events once', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: 'JBSWY3DPEHPK3PXP' });
  const org = await createOwnedOrganization(env, user, { name: 'User events', key: '4.dGVzdA==' });
  await env.DB.prepare('DELETE FROM events').run();
  for (let i = 0; i < 2; i++) assert.equal((await authedFetch(env, { method: 'DELETE', path: '/api/two-factor/authenticator', userId: user.id, body: { masterPasswordHash: PASSWORD } })).status, 204);
  const login = (password: string) => authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password }, headers: { 'Device-Type': '9' } });
  assert.equal((await login('wrong-password')).status, 400);
  assert.equal((await login(PASSWORD)).status, 200);
  assert.equal((await authedFetch(env, { method: 'POST', path: '/api/accounts/password', userId: user.id, body: { masterPasswordHash: PASSWORD, newMasterPasswordHash: 'replacement-hash', key: KEY } })).status, 200);
  await drainWaitUntil();
  const rows = await env.DB.prepare('SELECT type,acting_user_id,user_id FROM events WHERE organization_id=? ORDER BY type').bind(org.id).all<{ type: number; acting_user_id: string; user_id: string }>();
  assert.deepEqual(rows.results.map(row => row.type), [1000, 1001, 1003, 1005]);
  assert.ok(rows.results.every(row => row.acting_user_id === user.id && row.user_id === user.id));
  const own = await (await authedFetch(env, { path: '/api/events', userId: user.id })).json() as { data: { organizationId: string | null; type: number }[] };
  assert.deepEqual(own.data.map(row => row.type).sort(), [1000, 1001, 1003, 1005]);
  assert.ok(own.data.every(row => row.organizationId === null));
});

test('client export events fan out only to confirmed organizations and factor failures use their own event type', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const acceptedOrg = await createOwnedOrganization(env, owner, { name: 'Accepted only', key: '4.dGVzdA==' });
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: 'JBSWY3DPEHPK3PXP' });
  const org = await createOwnedOrganization(env, user, { name: 'Confirmed', key: '4.dGVzdA==' });
  await seedMembership(env, acceptedOrg.id, { userId: user.id, email: user.email, status: MembershipStatus.Accepted });
  await env.DB.prepare('DELETE FROM events').run();
  assert.equal((await authedFetch(env, { method: 'POST', path: '/events/collect', userId: user.id, body: [{ type: 1007, date: new Date().toISOString(), organizationId: acceptedOrg.id }] })).status, 200);
  assert.equal((await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password: PASSWORD, twoFactorProvider: '0', twoFactorToken: 'wrong' } })).status, 400);
  await drainWaitUntil();
  const rows = await env.DB.prepare('SELECT organization_id,type FROM events').all<{ organization_id: string | null; type: number }>();
  assert.equal(rows.results.length, 4);
  assert.equal(rows.results.filter(row => row.organization_id === org.id).length, 2);
  assert.equal(rows.results.filter(row => row.organization_id === null).length, 2);
  assert.ok(rows.results.every(row => row.type === 1006 || row.type === 1007));
  assert.ok(!rows.results.some(row => row.organization_id === acceptedOrg.id));
  assert.equal((await userRepo.getUserById(env.DB, user.id))!.totpSecret, user.totpSecret);
});

test('a backdated client export keeps its date only on the personal row', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const org = await createOwnedOrganization(env, user, { name: 'Export review', key: '4.dGVzdA==' });
  await env.DB.prepare('DELETE FROM events').run();
  const backdated = '2001-01-01T00:00:00.000Z';
  const before = new Date().toISOString();
  assert.equal((await authedFetch(env, { method: 'POST', path: '/events/collect', userId: user.id, body: [{ type: 1007, date: backdated }] })).status, 200);
  const rows = await env.DB.prepare('SELECT organization_id,date FROM events WHERE type = 1007').all<{ organization_id: string | null; date: string }>();
  assert.equal(rows.results.find(row => row.organization_id === null)?.date, backdated);
  const orgRow = rows.results.find(row => row.organization_id === org.id);
  assert.ok(orgRow && orgRow.date >= before, 'the organization copy carries receipt time');
  const listed = await (await authedFetch(env, { path: `/api/organizations/${org.id}/events`, userId: user.id })).json() as { data: { type: number }[] };
  assert.ok(listed.data.some(event => event.type === 1007), 'the export appears in the default organization window');
});
