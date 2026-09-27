import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { eq, lt } from 'drizzle-orm';
import { TOTP } from 'otpauth';
import { getOrm } from '../db/client';
import { devices, session, trustedTwoFactorDeviceTokens, users, verification } from '../db/schema';
import { SINGLE_ROW, jsonSet } from '../db/sql';
import { consumeSsoContinuation, saveSsoContinuation } from '../services/sso-continuation';
import type { User } from '../types';
import { verifyJWT } from '../utils/jwt';
import { authedFetch, captureEmail, createTestEnv, seedUser, TEST_ORIGIN, MAILABLE_DOMAIN } from './support/env';
import * as deviceRepo from '../services/storage-device-repo';
import * as userRepo from '../services/storage-user-repo';

const TOTP_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const VERIFIER = 'verified-pkce-context-'.repeat(3);
const CODE = 'single-use-idp-authorization-code';
const DEVICE = 'sso-device';
const RECOVERY = 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567';
const PATH = '/identity/connect/token';

const totp = () => new TOTP({ secret: TOTP_SECRET }).generate();

async function setup(t: TestContext, userOverrides: Partial<User> = {}) {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, SSO_ENABLED: '1', SSO_ONLY: '1', SSO_AUTHORITY: `https://${crypto.randomUUID()}.idp.example.test`, SSO_CLIENT_ID: 'nodewarden' });
  const user = await seedUser(env, { totpSecret: TOTP_SECRET, totpRecoveryCode: RECOVERY, ...userOverrides });
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'continuation-test' })).toString('base64url');
  const claims = Buffer.from(JSON.stringify({ iss: env.SSO_AUTHORITY, aud: env.SSO_CLIENT_ID, sub: `provider-${user.id}`, email: user.email, email_verified: true, exp: Math.floor(Date.now() / 1000) + 600 })).toString('base64url');
  const unsigned = `${header}.${claims}`;
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(unsigned));
  const idToken = `${unsigned}.${Buffer.from(signature).toString('base64url')}`;
  const jwk = { ...await crypto.subtle.exportKey('jwk', pair.publicKey), kid: 'continuation-test' };
  let exchanges = 0;
  t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url.endsWith('/.well-known/openid-configuration')) return Response.json({ token_endpoint: `${env.SSO_AUTHORITY}/token`, jwks_uri: `${env.SSO_AUTHORITY}/jwks` });
    if (request.url === `${env.SSO_AUTHORITY}/jwks`) return Response.json({ keys: [jwk] });
    assert.equal(request.url, `${env.SSO_AUTHORITY}/token`);
    exchanges++;
    if (exchanges > 1) return Response.json({ error: 'invalid_grant' }, { status: 400 });
    const body = await request.formData();
    assert.equal(body.get('code'), CODE);
    assert.equal(body.get('code_verifier'), VERIFIER);
    assert.equal(body.get('client_id'), env.SSO_CLIENT_ID);
    assert.equal(body.get('redirect_uri'), `${TEST_ORIGIN}/identity/oidc-signin`);
    return Response.json({ id_token: idToken, access_token: 'never-store-this-idp-access-token' });
  });
  const login = (overrides: Record<string, string> = {}, headers?: HeadersInit, path = PATH) => authedFetch(env, {
    method: 'POST', path, headers,
    body: new URLSearchParams({ grant_type: 'authorization_code', code: CODE, code_verifier: VERIFIER, redirect_uri: `${TEST_ORIGIN}/sso-connector.html`, client_id: 'web', scope: 'api offline_access', deviceIdentifier: DEVICE, deviceType: '9', ...overrides }),
  });
  const challenge = async () => {
    const response = await login();
    assert.equal(response.status, 400);
    assert.deepEqual((await response.json() as any).TwoFactorProviders, ['0']);
  };
  const state = async () => getOrm(env.DB).select({ id: verification.id, value: verification.value, expiresAt: verification.expiresAt })
    .from(verification).where(eq(verification.identifier, 'sso-continuation')).get();
  const counts = async () => {
    const orm = getOrm(env.DB);
    return orm.select({ sessions: orm.$count(session), remembered: orm.$count(trustedTwoFactorDeviceTokens), devices: orm.$count(devices) }).from(SINGLE_ROW).get();
  };
  return { env, user, mail, login, challenge, state, counts, exchanges: () => exchanges, idToken };
}

test('SSO exchanges its PKCE code once across challenge, invalid/context retries, successful TOTP and replay', async t => {
  const f = await setup(t);
  await f.challenge();
  const before = (await f.state())!;
  const value = JSON.parse(before.value);
  assert.ok(value.expiresAt > Date.now() && value.expiresAt <= Date.now() + 300_000);
  assert.ok(before.expiresAt > value.expiresAt);
  for (const sensitive of [CODE, VERIFIER, f.idToken, 'never-store-this-idp-access-token', f.user.masterPasswordHash, f.user.key]) assert.equal(before.value.includes(sensitive), false);
  assert.equal((await f.login({ twoFactorProvider: '0', twoFactorToken: 'wrong' })).status, 400);
  for (const changed of [{ client_id: 'desktop' }, { deviceIdentifier: 'other-device' }, { deviceType: '8' }, { code_verifier: 'wrong-verifier' }, { redirect_uri: 'https://other.test/callback' }, { scope: 'other' }]) {
    assert.equal((await f.login({ ...changed, twoFactorProvider: '0', twoFactorToken: totp() })).status, 400);
  }
  assert.equal((await f.login({}, undefined, 'https://other-vault.test/identity/connect/token')).status, 400);
  assert.deepEqual(await f.state(), before);
  assert.equal(f.exchanges(), 1);
  const accepted = await f.login({ deviceIdentifier: '', device_identifier: DEVICE, deviceType: '', device_type: '9', twoFactorProvider: '0', twoFactorToken: totp(), twoFactorRemember: '1' });
  assert.equal(accepted.status, 200);
  const tokens = await accepted.json() as any;
  assert.equal((await verifyJWT(tokens.access_token, f.env.JWT_SECRET))?.sub, f.user.id);
  assert.ok(tokens.refresh_token && tokens.TwoFactorToken);
  const state = await f.counts();
  assert.deepEqual(state, { sessions: 1, remembered: 1, devices: 1 });
  assert.equal((await f.login({ twoFactorProvider: '5', twoFactorToken: tokens.TwoFactorToken })).status, 400);
  assert.deepEqual(await f.counts(), state);
  assert.equal(f.exchanges(), 1);
});

test('expired SSO proof survives Better Auth cleanup as a tombstone and never re-exchanges', async t => {
  const f = await setup(t);
  await f.challenge();
  await getOrm(f.env.DB).update(verification).set({ value: jsonSet(verification.value, '$.expiresAt', Date.now() - 1) })
    .where(eq(verification.identifier, 'sso-continuation'));
  // The installed Better Auth internal adapter performs this global expiry cleanup.
  await getOrm(f.env.DB).delete(verification).where(lt(verification.expiresAt, Date.now()));
  assert.ok(await f.state());
  assert.equal((await f.login({ twoFactorProvider: '0', twoFactorToken: totp() })).status, 400);
  assert.equal(f.exchanges(), 1);
  assert.deepEqual(await f.counts(), { sessions: 0, remembered: 0, devices: 0 });
});

test('disabled, stamp-changed and email-reassigned accounts cannot resume verified SSO', async t => {
  const f = await setup(t);
  await f.challenge();
  const factors = { twoFactorProvider: '0', twoFactorToken: totp() };
  await getOrm(f.env.DB).update(users).set({ status: 'banned' }).where(eq(users.id, f.user.id));
  assert.equal((await f.login(factors)).status, 400);
  await getOrm(f.env.DB).update(users).set({ status: 'active', securityStamp: 'changed' }).where(eq(users.id, f.user.id));
  assert.equal((await f.login(factors)).status, 400);
  await getOrm(f.env.DB).update(users).set({ securityStamp: f.user.securityStamp, email: 'changed@example.test' }).where(eq(users.id, f.user.id));
  await seedUser(f.env, { email: f.user.email });
  assert.equal((await f.login(factors)).status, 400);
  assert.equal(f.exchanges(), 1);
  assert.deepEqual(await f.counts(), { sessions: 0, remembered: 0, devices: 0 });
});

test('only one concurrent SSO completion can create sessions with a reusable remember factor', async t => {
  const f = await setup(t);
  await f.challenge();
  await deviceRepo.saveTrustedTwoFactorDeviceToken(f.env.DB, 'existing-remember-token', f.user.id, DEVICE, Date.now() + 60_000);
  const responses = await Promise.all(Array.from({ length: 2 }, () => f.login({ twoFactorProvider: '5', twoFactorToken: 'existing-remember-token' })));
  assert.deepEqual(responses.map(response => response.status).sort(), [200, 400]);
  assert.deepEqual(await f.counts(), { sessions: 1, remembered: 1, devices: 1 });
  assert.equal(f.exchanges(), 1);
});

test('recovery-factor rotation and continuation claim commit together, and a losing claim changes neither', async t => {
  const f = await setup(t);
  await f.challenge();
  const originalBatch = f.env.DB.batch.bind(f.env.DB);
  let injectConflict = true;
  t.mock.method(f.env.DB, 'batch', async (statements: D1PreparedStatement[]) => {
    if (injectConflict && (statements[0] as any).query?.startsWith('update "verification" set "value"')) {
      injectConflict = false;
      await getOrm(f.env.DB).update(verification).set({ value: jsonSet(verification.value, '$.consumed', 1) }).where(eq(verification.identifier, 'sso-continuation'));
    }
    return originalBatch(statements);
  });
  const factors = { twoFactorProvider: '8', twoFactorToken: RECOVERY };
  assert.equal((await f.login(factors)).status, 400);
  const stored = await userRepo.getUserById(f.env.DB, f.user.id);
  assert.equal(stored!.securityStamp, f.user.securityStamp);
  assert.equal(stored!.totpSecret, TOTP_SECRET);
  assert.equal(stored!.totpRecoveryCode, RECOVERY);
  assert.deepEqual(await f.counts(), { sessions: 0, remembered: 0, devices: 0 });
  // Restore the fixture to the original unconsumed state to exercise the winning path.
  await getOrm(f.env.DB).update(verification).set({ value: jsonSet(verification.value, '$.consumed', 0) }).where(eq(verification.identifier, 'sso-continuation'));
  const response = await f.login(factors);
  assert.equal(response.status, 200);
  const finalUser = (await userRepo.getUserById(f.env.DB, f.user.id))!;
  assert.notEqual(finalUser.securityStamp, f.user.securityStamp);
  assert.equal(finalUser.totpSecret, null);
  assert.equal((await verifyJWT((await response.json() as any).access_token, f.env.JWT_SECRET))?.sstamp, finalUser.securityStamp);
  assert.equal((await f.login(factors)).status, 400);
  assert.equal(f.exchanges(), 1);
});

test('the final SSO claim checks fresh account state before creating remembered devices or sessions', async t => {
  const f = await setup(t);
  await f.challenge();
  const originalBatch = f.env.DB.batch.bind(f.env.DB);
  let changed = false;
  t.mock.method(f.env.DB, 'batch', async (statements: D1PreparedStatement[]) => {
    if (!changed && (statements[0] as any).query?.startsWith('update "verification" set "value"')) {
      changed = true;
      await getOrm(f.env.DB).update(users).set({ securityStamp: 'changed-before-claim' }).where(eq(users.id, f.user.id));
    }
    return originalBatch(statements);
  });
  assert.equal((await f.login({ twoFactorProvider: '0', twoFactorToken: totp(), twoFactorRemember: '1' })).status, 400);
  assert.deepEqual(await f.counts(), { sessions: 0, remembered: 0, devices: 0 });
  assert.equal(f.exchanges(), 1);
});

test('SSO email two-factor completes the same single-use authorization-code request', async t => {
  const f = await setup(t, { totpSecret: null, twoFactorEmail: `sso-factor@${MAILABLE_DOMAIN}` });
  const challenge = await f.login().then(response => response.json() as Promise<{ SsoEmail2faSessionToken: string }>);
  const sent = await authedFetch(f.env, { method: 'POST', path: '/api/two-factor/send-email-login', body: { email: f.user.email, ssoEmail2FaSessionToken: challenge.SsoEmail2faSessionToken } });
  assert.equal(sent.status, 200);
  assert.equal(f.mail.sent.length, 1);
  const code = String(f.mail.sent[0].text).match(/\b\d{6}\b/)![0];
  const accepted = await f.login({ twoFactorProvider: '1', twoFactorToken: code });
  assert.equal(accepted.status, 200);
  assert.equal(f.exchanges(), 1);
  assert.equal((await f.login({ twoFactorProvider: '1', twoFactorToken: code })).status, 400);
});

test('verified SSO is exempt from new-device verification on an old opted-in account', async t => {
  const f = await setup(t, { totpSecret: null, verifyDevices: true, createdAt: new Date(Date.now() - 2 * 86400_000).toISOString() });
  f.env.ENABLE_NEW_DEVICE_VERIFICATION = 'true';
  f.env.DISABLE_EMAIL_NEW_DEVICE = 'true';
  await deviceRepo.upsertDevice(f.env.DB, f.user.id, 'known-device', 'Known', 9);
  assert.equal((await f.login()).status, 200);
});

// The claim re-checks the stored proof inside its UPDATE. Each refused claim below meets every other
// condition, and the account row always matches the user passed in.
test('an SSO continuation claim refuses another binding, account, stamp or email and an expired proof', async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orm = getOrm(env.DB);
  const issue = async (id: string) => (await saveSsoContinuation(env, { id, binding: 'issued-binding' }, owner))!;
  const updateOwner = (values: { securityStamp?: string; email?: string }) => orm.update(users).set(values).where(eq(users.id, owner.id));
  const continuation = await issue('sso-continuation:claim');
  assert.equal(await consumeSsoContinuation(env, { ...continuation, binding: 'other-binding' }, owner), false);
  await updateOwner({ securityStamp: 'rotated-stamp' });
  assert.equal(await consumeSsoContinuation(env, continuation, { ...owner, securityStamp: 'rotated-stamp' }), false);
  await updateOwner({ securityStamp: owner.securityStamp, email: 'renamed@example.test' });
  assert.equal(await consumeSsoContinuation(env, continuation, { ...owner, email: 'renamed@example.test' }), false);
  const heir = await seedUser(env, { email: owner.email, securityStamp: owner.securityStamp });
  assert.equal(await consumeSsoContinuation(env, continuation, heir), false);
  await orm.delete(users).where(eq(users.id, heir.id));
  await updateOwner({ email: owner.email });
  assert.equal(await consumeSsoContinuation(env, continuation, owner), true);

  const expired = await issue('sso-continuation:expired');
  await orm.update(verification).set({ value: jsonSet(verification.value, '$.expiresAt', Date.now() - 1) }).where(eq(verification.id, expired.id));
  assert.equal(await consumeSsoContinuation(env, expired, owner), false);
});
