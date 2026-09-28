import assert from 'node:assert/strict';
import test from 'node:test';
import { eq } from 'drizzle-orm';
import { TOTP } from 'otpauth';
import { unzipSync, zipSync } from 'fflate';

import { getOrm } from '../db/client';
import { ensureStorageSchema } from '../db/migrate';
import { authRequests, config, devices, users } from '../db/schema';
import { hashPassword } from '../services/auth-password';
import { buildBackupArchive } from '../services/backup-archive';
import { importBackupArchiveBytes } from '../services/backup-import';
import { readMailConfig } from '../services/mail';
import type { Env, User } from '../types';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, seedUser } from './support/env';
import * as deviceRepo from '../services/storage-device-repo';
import * as userRepo from '../services/storage-user-repo';

const PASSWORD = 'client-master-password-hash';
const OLD = new Date(Date.now() - 2 * 86400_000).toISOString();
const REQUIRED = {
  error: 'device_error',
  error_description: 'New device verification required',
  ErrorModel: { Message: 'new device verification required', Object: 'error' },
};
const INVALID = {
  error: 'device_error',
  error_description: 'Invalid New Device OTP',
  ErrorModel: { Message: 'invalid new device otp', Object: 'error' },
};

async function setup(overrides: Partial<User> = {}, envOverrides: Partial<Env> = {}) {
  const mail = captureEmail();
  const env = await createTestEnv({
    ...mail.overrides,
    ENABLE_NEW_DEVICE_VERIFICATION: 'true',
    DISABLE_EMAIL_NEW_DEVICE: 'true',
    ...envOverrides,
  });
  const user = await seedUser(env, {
    email: `ndv@${MAILABLE_DOMAIN}`,
    masterPasswordHash: await hashPassword(PASSWORD),
    createdAt: OLD,
    verifyDevices: true,
    emailVerified: false,
    ...overrides,
  });
  await deviceRepo.upsertDevice(env.DB, user.id, 'known-device', 'Known device', 9);
  const login = (extra: Record<string, string> = {}) =>
    authedFetch(env, {
      method: 'POST',
      path: '/identity/connect/token',
      body: {
        grant_type: 'password',
        username: user.email,
        password: PASSWORD,
        deviceIdentifier: 'new-device',
        deviceType: '9',
        ...extra,
      },
    });
  const code = () =>
    String(mail.sent.filter((message) => String(message.subject).includes('sign-in code')).at(-1)?.text).match(
      /\b\d{6}\b/,
    )![0];
  return { env, user, login, mail, code };
}

test('new-device OTP uses exact errors, sends in the background, verifies email and rejects same-device replay', async () => {
  const f = await setup();
  const required = await f.login({ sso: '1', deviceIdentifier: '' });
  assert.equal(required.status, 400);
  assert.deepEqual(await required.json(), REQUIRED);
  assert.equal(await deviceRepo.isKnownDevice(f.env.DB, f.user.id, 'new-device'), false);
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 1);
  assert.equal(f.mail.sent[0].to, f.user.email);
  assert.match(String(f.mail.sent[0].text), /Consider enabling two-step login/);
  const wrong = await f.login({ newDeviceOtp: f.code() === '000000' ? '111111' : '000000' });
  assert.deepEqual(await wrong.json(), INVALID);
  assert.equal(await deviceRepo.isKnownDevice(f.env.DB, f.user.id, 'new-device'), false);
  assert.equal((await f.login({ newDeviceOtp: f.code() })).status, 200);
  assert.equal(await deviceRepo.isKnownDevice(f.env.DB, f.user.id, 'new-device'), true);
  assert.equal((await userRepo.getUserById(f.env.DB, f.user.id))?.emailVerified, true);
  const replay = await f.login({ newDeviceOtp: f.code() });
  assert.deepEqual(await replay.json(), INVALID);
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 1);
});

test('known devices, young accounts, empty device history, opt-out, flag-off and mail-off bypass the challenge', async () => {
  for (const kind of ['known', 'young', 'no-devices', 'opt-out', 'flag-off', 'mail-off']) {
    const f = await setup(
      kind === 'young' ? { createdAt: new Date().toISOString() } : kind === 'opt-out' ? { verifyDevices: false } : {},
    );
    if (kind === 'no-devices') await getOrm(f.env.DB).delete(devices).where(eq(devices.userId, f.user.id));
    if (kind === 'flag-off') f.env.ENABLE_NEW_DEVICE_VERIFICATION = '0';
    if (kind === 'mail-off') delete f.env.EMAIL;
    const response = await f.login(kind === 'known' ? { deviceIdentifier: 'known-device' } : {});
    assert.equal(response.status, 200, kind);
    await drainWaitUntil();
    assert.equal(f.mail.sent.length, 0, kind);
  }
  const f = await setup();
  await getOrm(f.env.DB).delete(devices).where(eq(devices.userId, f.user.id));
  assert.deepEqual(await (await f.login({ newDeviceOtp: '123456' })).json(), INVALID);
});

test('TOTP, approved device requests and personal API keys do not need new-device email verification', async () => {
  const totpSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const f = await setup({ totpSecret });
  const token = new TOTP({ secret: totpSecret }).generate();
  assert.equal((await f.login({ twoFactorProvider: '0', twoFactorToken: token })).status, 200);
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 0);
  const device = await setup({ apiKey: 'personal-api-key' });
  const id = crypto.randomUUID();
  await getOrm(device.env.DB).insert(authRequests).values({
    id,
    userId: device.user.id,
    type: 0,
    requestDeviceIdentifier: 'approved-device',
    requestDeviceType: 9,
    accessCode: 'access-code',
    publicKey: 'public-key',
    key: '2.key|key|key',
    approved: 1,
    creationDate: new Date().toISOString(),
    responseDate: new Date().toISOString(),
  });
  assert.equal((await device.login({ password: 'access-code', authRequest: id })).status, 200);
  const apiKey = await device.login({
    grant_type: 'client_credentials',
    client_id: `user.${device.user.id}`,
    client_secret: 'personal-api-key',
    scope: 'api',
    deviceIdentifier: 'api-device',
  });
  assert.equal(apiKey.status, 200);
  await drainWaitUntil();
  assert.equal(device.mail.sent.length, 0);
});

test('the attempt budget refuses the sixth try without using the password lockout', async () => {
  const f = await setup();
  await f.login();
  await drainWaitUntil();
  const code = f.code();
  for (let attempt = 0; attempt < 5; attempt++) {
    assert.deepEqual(await (await f.login({ newDeviceOtp: code === '000000' ? '111111' : '000000' })).json(), INVALID);
  }
  assert.deepEqual(await (await f.login({ newDeviceOtp: code })).json(), INVALID);
  // Further OTP failures remain device errors, rather than entering the ten-failure password lockout.
  for (let attempt = 0; attempt < 5; attempt++)
    assert.deepEqual(await (await f.login({ newDeviceOtp: code })).json(), INVALID);
});

test('resend conceals credentials and the active account preference requires the master password', async () => {
  const f = await setup();
  const resend = (email: string, password: string) =>
    authedFetch(f.env, {
      method: 'POST',
      path: '/api/accounts/resend-new-device-otp',
      body: { email, masterPasswordHash: password },
    });
  for (const [email, password] of [
    ['missing@x.io', PASSWORD],
    [f.user.email, 'wrong'],
  ]) {
    const response = await resend(email, password);
    assert.equal(response.status, 200);
    assert.equal(await response.json(), '');
  }
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 0);
  assert.equal((await resend(f.user.email, PASSWORD)).status, 200);
  await drainWaitUntil();
  assert.equal(f.mail.sent.length, 1);
  const set = (masterPasswordHash: string, verifyDevices: unknown) =>
    authedFetch(f.env, {
      method: 'POST',
      path: '/api/accounts/verify-devices',
      userId: f.user.id,
      body: { masterPasswordHash, verifyDevices },
    });
  assert.equal((await set('wrong', false)).status, 400);
  assert.equal((await set(PASSWORD, 'false')).status, 400);
  const disabled = await set(PASSWORD, false);
  assert.equal(disabled.status, 200);
  assert.equal(await disabled.text(), '');
  assert.equal((await f.login()).status, 200);
  const profile = await authedFetch(f.env, { path: '/api/accounts/profile', userId: f.user.id });
  assert.equal(((await profile.json()) as { verifyDevices: boolean }).verifyDevices, false);
  const legacy = await authedFetch(f.env, {
    path: '/api/two-factor/get-device-verification-settings',
    userId: f.user.id,
  });
  assert.deepEqual(await legacy.json(), {
    isDeviceVerificationSectionEnabled: false,
    unknownDeviceVerificationEnabled: false,
    object: 'deviceVerificationSettings',
  });
  delete f.env.EMAIL;
  assert.equal((await resend(f.user.email, PASSWORD)).status, 501);
  await drainWaitUntil();
});

test('an invalid optional NDV flag logs and disables only NDV while Email two-factor still sends', async (t) => {
  const f = await setup({ twoFactorEmail: `factor@${MAILABLE_DOMAIN}` }, { ENABLE_NEW_DEVICE_VERIFICATION: 'yes' });
  const errors = t.mock.method(console, 'error', () => {});
  const config = readMailConfig(f.env);
  assert.equal(config.kind, 'enabled');
  assert.equal(config.kind === 'enabled' && config.newDeviceVerification, false);
  assert.ok(
    errors.mock.calls.some((call) => JSON.stringify(call.arguments).includes('ENABLE_NEW_DEVICE_VERIFICATION')),
  );
  const sent = await authedFetch(f.env, {
    method: 'POST',
    path: '/api/two-factor/send-email-login',
    body: { email: f.user.email, masterPasswordHash: PASSWORD },
  });
  assert.equal(sent.status, 200);
  assert.equal(f.mail.sent.length, 1);
});

test('registration opts in and baseline replay or legacy backup restore never overwrites a later opt-out', async () => {
  const env = await createTestEnv();
  const registered = await authedFetch(env, {
    method: 'POST',
    path: '/identity/accounts/register/finish',
    body: {
      email: 'first@x.io',
      masterPasswordHash: PASSWORD,
      key: '2.key|key|key',
      encryptedPrivateKey: '2.private|private|private',
      publicKey: 'public',
    },
  });
  assert.equal(registered.status, 200);
  const user = (await userRepo.getUser(env.DB, 'first@x.io'))!;
  assert.equal(user.verifyDevices, true);
  await getOrm(env.DB).update(users).set({ verifyDevices: 0 }).where(eq(users.id, user.id));
  await ensureStorageSchema(env.DB);
  assert.equal((await userRepo.getUserById(env.DB, user.id))?.verifyDevices, false);
  const archive = await buildBackupArchive(env, new Date(), { includeAttachments: false });
  const files = unzipSync(archive.bytes);
  const db = JSON.parse(new TextDecoder().decode(files['db.json']));
  db.config = db.config.filter((row: { key: string }) => row.key !== 'migration.verify-devices-on');
  delete db.users[0].verify_devices;
  files['db.json'] = Buffer.from(JSON.stringify(db));
  const restored = await createTestEnv();
  await importBackupArchiveBytes(zipSync(files), restored, user.id, false);
  await ensureStorageSchema(restored.DB);
  assert.equal((await userRepo.getUserById(restored.DB, user.id))?.verifyDevices, false);
  assert.equal(
    (
      await getOrm(restored.DB)
        .select({ value: config.value })
        .from(config)
        .where(eq(config.key, 'migration.verify-devices-on'))
        .get()
    )?.value,
    '1',
  );
  await drainWaitUntil();
});
