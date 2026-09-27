import assert from 'node:assert/strict';
import test from 'node:test';

import * as emergencyRepo from '../services/storage-emergency-repo';
import { EmergencyAccessStatus, EmergencyAccessType } from '../services/storage-emergency-repo';
import { AuthService } from '../services/auth';
import type { Env, User } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import * as userRepo from '../services/storage-user-repo';

// Web 2026.9 (clients e8bc60e5ba) finishes an emergency takeover with only the nested
// authenticationData/unlockData body. The grantee sees success either way, so a server that
// ignores the nested shape silently locks the grantor out: the only proof is the grantor's login.
const NEW_MASTER_PASSWORD_HASH = 'bmV3LW1hc3Rlci1wYXNzd29yZC1oYXNo';
const NEW_WRAPPED_USER_KEY = '2.bmV3LWl2|bmV3LWNpcGhlcg==|bmV3LW1hYw==';
const GRANTEE_WRAPPED_GRANTOR_KEY = '4.Z3JhbnRvci11c2VyLWtleQ==';
const CURRENT_MASTER_PASSWORD_HASH = 'Y3VycmVudC1tYXN0ZXItcGFzc3dvcmQtaGFzaA==';

interface Takeover {
  env: Env;
  grantor: User;
  grantee: User;
  takeoverPath: string;
  passwordPath: string;
}

async function approvedTakeover(): Promise<Takeover> {
  const env = await createTestEnv();
  const grantor = await seedUser(env);
  const grantee = await seedUser(env);
  const now = new Date().toISOString();
  const record: emergencyRepo.EmergencyAccessRecord = {
    id: crypto.randomUUID(),
    grantorId: grantor.id,
    granteeId: grantee.id,
    email: null,
    keyEncrypted: GRANTEE_WRAPPED_GRANTOR_KEY,
    type: EmergencyAccessType.Takeover,
    status: EmergencyAccessStatus.RecoveryApproved,
    waitTimeDays: 0,
    recoveryInitiatedAt: now,
    lastNotificationAt: now,
    createdAt: now,
    updatedAt: now,
  };
  await emergencyRepo.saveEmergencyAccess(env.DB, record);
  return {
    env,
    grantor,
    grantee,
    takeoverPath: `/api/emergency-access/${record.id}/takeover`,
    passwordPath: `/api/emergency-access/${record.id}/password`,
  };
}

// Mirrors EmergencyAccessService.takeover() and the web change-password flow: both halves carry
// the account's KDF and salt.
function nestedPasswordBody(user: User) {
  const salt = user.email.toLowerCase();
  const kdf = { kdfType: user.kdfType, iterations: user.kdfIterations };
  return {
    authenticationData: { salt, kdf, masterPasswordAuthenticationHash: NEW_MASTER_PASSWORD_HASH },
    unlockData: { salt, kdf, masterKeyWrappedUserKey: NEW_WRAPPED_USER_KEY },
  };
}

function passwordLogin(env: Env, email: string, masterPasswordHash: string): Promise<Response> {
  return authedFetch(env, {
    method: 'POST',
    path: '/identity/connect/token',
    body: new URLSearchParams({
      grant_type: 'password',
      username: email,
      password: masterPasswordHash,
      scope: 'api offline_access',
      client_id: 'web',
      deviceIdentifier: crypto.randomUUID(),
      deviceName: 'firefox',
      deviceType: '10',
    }),
  });
}

test('the web 2026.9 nested takeover body lets the grantor log in with the new password', async () => {
  const { env, grantor, grantee, takeoverPath, passwordPath } = await approvedTakeover();

  const takeover = await authedFetch(env, { method: 'POST', path: takeoverPath, userId: grantee.id });
  assert.equal(takeover.status, 200);
  assert.equal((await takeover.json() as { salt: string }).salt, grantor.email.toLowerCase());

  const password = await authedFetch(env, { method: 'POST', path: passwordPath, body: nestedPasswordBody(grantor), userId: grantee.id });
  assert.equal(password.status, 200);

  const login = await passwordLogin(env, grantor.email, NEW_MASTER_PASSWORD_HASH);
  assert.equal(login.status, 200);
  assert.equal((await login.json() as { Key: string }).Key, NEW_WRAPPED_USER_KEY);
  const stored = await userRepo.getUserById(env.DB, grantor.id);
  const credentialPassword = await env.DB.prepare("SELECT password FROM account WHERE user_id = ? AND provider_id = 'credential'")
    .bind(grantor.id)
    .first('password');
  assert.equal(credentialPassword, stored?.masterPasswordHash);
});

test('the legacy newMasterPasswordHash and key takeover body still works', async () => {
  const { env, grantor, grantee, passwordPath } = await approvedTakeover();
  const body = { newMasterPasswordHash: NEW_MASTER_PASSWORD_HASH, key: NEW_WRAPPED_USER_KEY };

  const takeover = await authedFetch(env, { method: 'POST', path: passwordPath, body, userId: grantee.id });
  assert.equal(takeover.status, 200);

  const login = await passwordLogin(env, grantor.email, NEW_MASTER_PASSWORD_HASH);
  assert.equal(login.status, 200);
  assert.equal((await login.json() as { Key: string }).Key, NEW_WRAPPED_USER_KEY);
});

test('an incomplete, mismatched or unauthorized takeover is rejected and leaves the grantor untouched', async () => {
  const { env, grantor, grantee, passwordPath } = await approvedTakeover();
  const intruder = await seedUser(env);
  const nested = nestedPasswordBody(grantor);
  const weakerKdf = { kdfType: grantor.kdfType, iterations: grantor.kdfIterations - 1 };
  const rejected = [
    { body: null, userId: grantee.id },
    { body: {}, userId: grantee.id },
    { body: { newMasterPasswordHash: NEW_MASTER_PASSWORD_HASH }, userId: grantee.id },
    { body: { authenticationData: nested.authenticationData }, userId: grantee.id },
    { body: { ...nested, unlockData: { ...nested.unlockData, masterKeyWrappedUserKey: '' } }, userId: grantee.id },
    { body: { ...nested, unlockData: { ...nested.unlockData, salt: 'someone-else@example.test' } }, userId: grantee.id },
    { body: { ...nested, unlockData: { ...nested.unlockData, masterKeyWrappedUserKey: 'not-an-enc-string' } }, userId: grantee.id },
    // Both halves agree but weaken the grantor's KDF: the client would derive a different key.
    {
      body: {
        authenticationData: { ...nested.authenticationData, kdf: weakerKdf },
        unlockData: { ...nested.unlockData, kdf: weakerKdf },
      },
      userId: grantee.id,
    },
    { body: nested, userId: intruder.id },
    { body: nested, userId: grantor.id },
  ];

  for (const { body, userId } of rejected) {
    const response = await authedFetch(env, { method: 'POST', path: passwordPath, body, userId });
    assert.equal(response.status, 400, JSON.stringify({ body, userId }));
  }

  const stored = await userRepo.getUserById(env.DB, grantor.id);
  assert.equal(stored?.masterPasswordHash, grantor.masterPasswordHash);
  assert.equal(stored?.key, grantor.key);
  assert.equal(stored?.securityStamp, grantor.securityStamp);
});

// The account password change shares the nested parse with the takeover, so it must keep working.
test('the account password change still accepts the nested body', async () => {
  const env = await createTestEnv();
  const masterPasswordHash = await new AuthService(env).hashPasswordServer(CURRENT_MASTER_PASSWORD_HASH);
  const user = await seedUser(env, { masterPasswordHash });
  const body = { masterPasswordHash: CURRENT_MASTER_PASSWORD_HASH, ...nestedPasswordBody(user) };

  const change = await authedFetch(env, { method: 'POST', path: '/api/accounts/password', body, userId: user.id });
  assert.equal(change.status, 200);

  const login = await passwordLogin(env, user.email, NEW_MASTER_PASSWORD_HASH);
  assert.equal(login.status, 200);
  assert.equal((await login.json() as { Key: string }).Key, NEW_WRAPPED_USER_KEY);
});
