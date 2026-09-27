import assert from 'node:assert/strict';
import test from 'node:test';

import { sha256Base64Url } from '../utils/account-passkeys';
import { createDeleteRecoverToken, signHs256Jwt } from '../utils/jwt';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, seedUser } from './support/env';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

const { createOwnedOrganization } = await import('../handlers/organizations');
const requestPath = '/api/accounts/delete-recover';
const tokenPath = '/api/accounts/delete-recover-token';

async function setup() {
  const mail = captureEmail();
  const env = await createTestEnv(mail.overrides);
  const active = await seedUser(env, { email: `active@${MAILABLE_DOMAIN}` });
  const banned = await seedUser(env, { email: `banned@${MAILABLE_DOMAIN}`, status: 'banned' });
  return { env, mail, active, banned };
}

test('deletion recovery conceals account existence and status and puts all token parameters in the configured fragment', async () => {
  const f = await setup();
  for (const email of [f.active.email, f.banned.email, `unknown@${MAILABLE_DOMAIN}`]) {
    const response = await authedFetch(f.env, { method: 'POST', path: requestPath, body: { email }, headers: { 'X-Forwarded-Host': 'evil.test' } });
    assert.equal(response.status, 200);
    assert.equal(await response.json(), '');
  }
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 1);
  assert.equal(f.mail.sent[0].to, f.active.email);
  const link = new URL(String(f.mail.sent[0].text).match(/https:\/\/\S+/)![0]);
  assert.equal(link.origin, 'https://web.example.test');
  assert.equal(link.search, '');
  assert.ok(link.hash.startsWith('#/verify-recover-delete?'));
  const params = new URLSearchParams(link.hash.split('?')[1]);
  assert.equal(params.get('userId'), f.active.id);
  assert.equal(params.get('email'), f.active.email);
  assert.ok(params.get('token'));
  assert.ok(!String(f.mail.sent[0].subject).includes(params.get('token')!));
  // A delivered link remains usable during a mail outage, and account deletion consumes it.
  delete f.env.EMAIL;
  const body = { userId: f.active.id, token: params.get('token') };
  const deleted = await authedFetch(f.env, { method: 'POST', path: tokenPath, body });
  assert.equal(deleted.status, 200);
  assert.equal(await deleted.text(), '');
  assert.equal(await userRepo.getUserById(f.env.DB, f.active.id), null);
  const replay = await authedFetch(f.env, { method: 'POST', path: tokenPath, body });
  assert.equal(replay.status, 400);
  assert.equal((await replay.json() as { error: string }).error, 'Invalid token.');
  await drainWaitUntil();
});

test('mail-disabled or origin-missing recovery gives the same 503 for every address', async () => {
  for (const missing of ['mail', 'origin']) {
    const f = await setup();
    if (missing === 'mail') delete f.env.EMAIL;
    else delete f.env.WEB_VAULT_ORIGINS;
    for (const email of [f.active.email, f.banned.email, `unknown@${MAILABLE_DOMAIN}`]) {
      const response = await authedFetch(f.env, { method: 'POST', path: requestPath, body: { email } });
      assert.equal(response.status, 503);
    }
    await drainWaitUntil();
    assert.equal(f.mail.sent.length, 0);
  }
});

test('unknown, banned, expired, foreign and revoked deletion tokens have identical failures', async () => {
  const f = await setup();
  const claim = { iss: 'nodewarden|delete_recover', sub: f.active.id, sst: await sha256Base64Url(f.active.securityStamp), exp: Math.floor(Date.now() / 1000) + 60 };
  const beforeChange = await createDeleteRecoverToken(f.env, f.active);
  let failure: unknown;
  for (const body of [
    { userId: 'missing', token: beforeChange },
    { userId: f.banned.id, token: await createDeleteRecoverToken(f.env, f.banned) },
    { userId: f.active.id, token: await createDeleteRecoverToken(f.env, f.banned) },
    { userId: f.active.id, token: await signHs256Jwt({ ...claim, exp: Math.floor(Date.now() / 1000) - 1 }, f.env.JWT_SECRET) },
    { userId: f.active.id, token: await signHs256Jwt({ ...claim, iss: 'nodewarden' }, f.env.JWT_SECRET) },
    { userId: f.active.id, token: await signHs256Jwt({ ...claim, exp: undefined }, f.env.JWT_SECRET) },
    { userId: f.active.id, token: 'garbage' },
  ]) {
    const response = await authedFetch(f.env, { method: 'POST', path: tokenPath, body });
    assert.equal(response.status, 400);
    const payload = await response.json();
    failure ??= payload;
    assert.deepEqual(payload, failure);
  }
  await f.env.DB.prepare('UPDATE users SET security_stamp=? WHERE id=?').bind(crypto.randomUUID(), f.active.id).run();
  const revoked = await authedFetch(f.env, { method: 'POST', path: tokenPath, body: { userId: f.active.id, token: beforeChange } });
  assert.deepEqual(await revoked.json(), failure);
});

test('sole Owners and the last administrator remain protected, and the sixth request is rate-limited', async () => {
  const f = await setup();
  await createOwnedOrganization(f.env, f.active, { name: 'Sole Owner', key: '4.dGVzdA==' });
  const owner = await authedFetch(f.env, { method: 'POST', path: tokenPath, body: { userId: f.active.id, token: await createDeleteRecoverToken(f.env, f.active) } });
  assert.equal(owner.status, 400);
  assert.match(await owner.text(), /sole owner/);
  const admin = await seedUser(f.env, { role: 'admin' });
  const lastAdmin = await authedFetch(f.env, { method: 'POST', path: tokenPath, body: { userId: admin.id, token: await createDeleteRecoverToken(f.env, admin) } });
  assert.equal(lastAdmin.status, 400);
  assert.match(await lastAdmin.text(), /last instance administrator/);
  for (let index = 0; index < 6; index++) {
    const response = await authedFetch(f.env, { method: 'POST', path: requestPath, body: { email: `unknown@${MAILABLE_DOMAIN}` } });
    assert.equal(response.status, index < 5 ? 200 : 429);
    if (index === 5) assert.ok(response.headers.get('Retry-After'));
  }
  await drainWaitUntil();
});

test('a mid-flight security-stamp change prevents self or recovery deletion without touching account data', async () => {
  for (const recover of [false, true]) {
    const f = await setup();
    await sessionRepo.saveRefreshToken(f.env.DB, 'existing-session', f.active.id);
    const token = await createDeleteRecoverToken(f.env, f.active);
    const batch = f.env.DB.batch.bind(f.env.DB);
    const newStamp = crypto.randomUUID();
    f.env.DB.batch = async statements => {
      await f.env.DB.prepare('UPDATE users SET security_stamp=? WHERE id=?').bind(newStamp, f.active.id).run();
      return batch(statements);
    };
    const response = await authedFetch(f.env, {
      method: recover ? 'POST' : 'DELETE', path: recover ? tokenPath : '/api/accounts', userId: recover ? undefined : f.active.id,
      body: recover ? { userId: f.active.id, token } : { masterPasswordHash: f.active.masterPasswordHash },
    });
    assert.equal(response.status, recover ? 400 : 404);
    assert.equal((await userRepo.getUserById(f.env.DB, f.active.id))?.securityStamp, newStamp);
    assert.ok(await sessionRepo.getRefreshTokenRecord(f.env.DB, 'existing-session'));
    assert.equal(await f.env.DB.prepare('SELECT COUNT(*) AS n FROM audit_logs').first('n'), 0);
  }
});
