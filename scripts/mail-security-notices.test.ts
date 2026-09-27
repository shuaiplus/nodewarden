import assert from 'node:assert/strict';
import test from 'node:test';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, failingEmail, MAILABLE_DOMAIN, seedUser } from './support/env';
import { hashPassword } from '../src/services/auth-password';
import { readMailConfig } from '../src/services/mail';
const password = 'client-password-hash';
const old = '2020-01-01T00:00:00.000Z';

test('new device mail is delivered once, respects age/flag and never blocks a login', async (t) => {
  t.mock.method(console, 'error', () => {});
  t.mock.method(console, 'warn', () => {});
  for (const flag of [undefined, 'true', '1', 'yes']) {
    const capture = captureEmail();
    const env = await createTestEnv({ ...capture.overrides, DISABLE_EMAIL_NEW_DEVICE: flag });
    const user = await seedUser(env, { email: `security@${MAILABLE_DOMAIN}`, createdAt: old, masterPasswordHash: await hashPassword(password) });
    const login = (device: string) => authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password, deviceIdentifier: device, deviceType: '9' } });
    assert.equal((await login('first')).status, 200);
    await drainWaitUntil();
    assert.equal(capture.sent.length, flag === undefined ? 1 : 0);
    assert.equal((await login('first')).status, 200);
    await drainWaitUntil();
    assert.equal(capture.sent.length, flag === undefined ? 1 : 0);
    env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
    assert.equal((await login('second')).status, 200);
    await drainWaitUntil();
    if (flag === 'yes') assert.equal(readMailConfig(env).kind, 'misconfigured', 'invalid delivery configuration must be reported');
  }
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  for (const overrides of [{ email: `young@${MAILABLE_DOMAIN}` }, { email: 'reserved@example.test', createdAt: old }]) {
    const user = await seedUser(env, { ...overrides, masterPasswordHash: await hashPassword(password) });
    assert.equal((await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password, deviceIdentifier: crypto.randomUUID() } })).status, 200);
  }
  await drainWaitUntil();
  assert.equal(capture.sent.length, 0);
});

test('API-key grants notify a new device', async () => {
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const apiKey = 'a'.repeat(30);
  const user = await seedUser(env, { email: `api@${MAILABLE_DOMAIN}`, createdAt: old, apiKey });
  const response = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'client_credentials', client_id: `user.${user.id}`, client_secret: apiKey, scope: 'api', deviceIdentifier: 'api-device' } });
  assert.equal(response.status, 200);
  await drainWaitUntil();
  assert.equal(capture.sent.length, 1);
  assert.match(capture.sent[0].subject, /New device/);
});

test('failed two-factor notices deduplicate per account, skip Remember and identify recovery failures', async (t) => {
  t.mock.method(console, 'warn', () => {});
  const capture = captureEmail();
  const env = await createTestEnv(capture.overrides);
  const attempt = async (suffix: string, provider: string, repeats = 1) => {
    const user = await seedUser(env, { email: `${suffix}@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(password), totpSecret: 'JBSWY3DPEHPK3PXP', totpRecoveryCode: 'recovery-code' });
    for (let i = 0; i < repeats; i++) {
      const response = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: user.email, password, twoFactorProvider: provider, twoFactorToken: 'invalid', deviceIdentifier: 'known' } });
      assert.equal(response.status, 400);
      await drainWaitUntil();
    }
  };
  await attempt('totp', '0', 2);
  assert.equal(capture.sent.length, 1);
  await attempt('remember', '5');
  assert.equal(capture.sent.length, 1);
  await attempt('recovery', '8');
  assert.equal(capture.sent.length, 2);
  assert.match(capture.sent[1].text, /Recovery code/);
  assert.match(capture.sent[0].text, /203\[dot\]0\[dot\]113\[dot\]10/);
  env.EMAIL = failingEmail('E_RECIPIENT_SUPPRESSED');
  await attempt('failure', '0');
});

test('both recovery paths send a security notice and delivery failure never rolls back recovery', async (t) => {
  t.mock.method(console, 'warn', () => {});
  for (const login of [false, true]) {
    const capture = captureEmail();
    const env = await createTestEnv(capture.overrides);
    const user = await seedUser(env, { email: `recover@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(password), totpSecret: 'JBSWY3DPEHPK3PXP', totpRecoveryCode: 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567' });
    const attempt = (code: string) => authedFetch(env, { method: 'POST', path: login ? '/identity/connect/token' : '/identity/accounts/recover-2fa', body: login ? { grant_type: 'password', username: user.email, password, twoFactorProvider: '8', twoFactorToken: code } : { email: user.email, masterPasswordHash: password, recoveryCode: code } });
    assert.equal((await attempt('WRONG')).status, 400);
    await drainWaitUntil();
    assert.equal(capture.sent.length, 1);
    assert.match(capture.sent[0].subject, /Unsuccessful/);
    assert.equal((await attempt(user.totpRecoveryCode!)).status, 200);
    await drainWaitUntil();
    assert.equal(capture.sent.length, 2);
    assert.match(capture.sent[1].subject, /was recovered/);
  }
  const env = await createTestEnv({ ...captureEmail().overrides, EMAIL: failingEmail('E_RECIPIENT_SUPPRESSED') });
  const user = await seedUser(env, { email: `failure@${MAILABLE_DOMAIN}`, masterPasswordHash: await hashPassword(password), totpSecret: 'JBSWY3DPEHPK3PXP', totpRecoveryCode: 'ABCD EFGH IJKL MNOP QRST UVWX YZ23 4567' });
  assert.equal((await authedFetch(env, { method: 'POST', path: '/identity/accounts/recover-2fa', body: { email: user.email, masterPasswordHash: password, recoveryCode: user.totpRecoveryCode } })).status, 200);
  await drainWaitUntil();
});

import { cose, isoCBOR } from '@simplewebauthn/server/helpers';
import { createPrivateKey, sign } from 'node:crypto';
import { TEST_ORIGIN } from './support/env';
import * as passkeyRepo from '../src/services/storage-account-passkey-repo';
import * as deviceRepo from '../src/services/storage-device-repo';

test('a verified passkey grant notifies its new device', async () => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ENABLE_NEW_DEVICE_VERIFICATION: 'true' });
  const user = await seedUser(env, { email: `passkey@${MAILABLE_DOMAIN}`, verifyDevices: true, createdAt: new Date(Date.now() - 2 * 86400_000).toISOString() });
  await deviceRepo.upsertDevice(env.DB, user.id, 'known-device', 'Known', 9);
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', keys.privateKey);
  type CborValue = Parameters<typeof isoCBOR.encode>[0];
  const publicKey = isoCBOR.encode(new Map<number, CborValue>([
    [cose.COSEKEYS.kty, cose.COSEKTY.EC2], [cose.COSEKEYS.alg, cose.COSEALG.ES256], [cose.COSEKEYS.crv, cose.COSECRV.P256],
    [cose.COSEKEYS.x, Buffer.from(jwk.x!, 'base64url')], [cose.COSEKEYS.y, Buffer.from(jwk.y!, 'base64url')],
  ]));
  const credentialId = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString('base64url');
  await passkeyRepo.saveAccountPasskeyCredential(env.DB, { id: crypto.randomUUID(), userId: user.id, purpose: 'login', name: 'Test key', publicKey: Buffer.from(publicKey).toString('base64url'), credentialId, counter: 0, type: 'public-key', aaGuid: null, transports: ['usb'], encryptedUserKey: null, encryptedPublicKey: null, encryptedPrivateKey: null, supportsPrf: false, createdAt: old, updatedAt: old });
  const optionsResponse = await authedFetch(env, { path: '/identity/accounts/webauthn/assertion-options' });
  assert.equal(optionsResponse.status, 200);
  const { options, token } = await optionsResponse.json() as { options: { challenge: string; rpId: string }; token: string };
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: TEST_ORIGIN }));
  const authenticatorData = Buffer.concat([new Uint8Array(await crypto.subtle.digest('SHA-256', Buffer.from(options.rpId))), Buffer.from([5, 0, 0, 0, 1])]);
  const signed = Buffer.concat([authenticatorData, new Uint8Array(await crypto.subtle.digest('SHA-256', clientData))]);
  const deviceResponse = { id: credentialId, rawId: credentialId, type: 'public-key', clientExtensionResults: {}, response: { clientDataJSON: clientData.toString('base64url'), authenticatorData: authenticatorData.toString('base64url'), signature: sign('sha256', signed, createPrivateKey({ key: jwk, format: 'jwk' })).toString('base64url'), userHandle: Buffer.from(user.id).toString('base64url') } };
  const response = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'webauthn', token, deviceResponse: JSON.stringify(deviceResponse), deviceIdentifier: 'new-passkey-device' } });
  assert.equal(response.status, 200, await response.clone().text());
  await drainWaitUntil();
  assert.equal(capture.sent.length, 1);
  assert.match(capture.sent[0].subject, /New device/);
});
