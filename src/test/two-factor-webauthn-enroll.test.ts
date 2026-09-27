import assert from 'node:assert/strict';
import test from 'node:test';

import { cose, isoCBOR } from '@simplewebauthn/server/helpers';
import { eq } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { webauthnCredentials } from '../db/schema';
import { AuthService } from '../services/auth';
import type { Env, User } from '../types';
import {
  authedFetch,
  createTestEnv,
  interceptStatement,
  seedUser,
  portalFetch,
  signInToAdminPortal,
} from './support/env';
import * as passkeyRepo from '../services/storage-account-passkey-repo';
import * as userRepo from '../services/storage-user-repo';

// Official web enrolls a two-step-login key by PUTting the deviceResponse built in
// putTwoFactorWebAuthn (clients web-v2026.9.0 default-two-factor-api.service.ts): base64url ids
// and a PascalCase AttestationObject next to a camelCase clientDataJson. Server v2026.9.1 binds
// it case-insensitively, so the enrollment must verify and return 200.
const CLIENT_MASTER_PASSWORD_HASH = 'Y2xpZW50LW1hc3Rlci1wYXNzd29yZC1oYXNo';
const INVALID_REGISTRATION = 'Invalid passkey registration response';
const CREDENTIAL_ID_BYTES = 16;
// Authenticator data layout: https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data
const FLAG_USER_PRESENT = 1 << 0;
const FLAG_ATTESTED_CREDENTIAL_DATA = 1 << 6;
const SIGN_COUNT_BYTES = 4;
const AAGUID_BYTES = 16;
const CREDENTIAL_ID_LENGTH_BYTES = 2;

interface Enrollment {
  env: Env;
  user: User;
  userVerificationToken: string;
  deviceResponse: {
    id: string;
    rawId: string;
    type: string;
    extensions: Record<string, never>;
    response: { AttestationObject: string; clientDataJson: string; transports: string[] };
  };
}

type CborValue = Parameters<typeof isoCBOR.encode>[0];
const base64Url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

// A software authenticator's 'none' attestation for the challenge the Worker just issued.
async function officialEnrollment(
  context?: Pick<Enrollment, 'env' | 'user' | 'userVerificationToken'>,
): Promise<Enrollment> {
  const env = context?.env ?? (await createTestEnv());
  const user =
    context?.user ??
    (await seedUser(env, {
      masterPasswordHash: await new AuthService(env).hashPasswordServer(CLIENT_MASTER_PASSWORD_HASH),
    }));
  const userVerificationToken =
    context?.userVerificationToken ??
    (await authedFetch(env, {
      method: 'POST',
      path: '/api/two-factor/get-webauthn',
      userId: user.id,
      body: { masterPasswordHash: CLIENT_MASTER_PASSWORD_HASH },
    }).then(async (response) => {
      assert.equal(response.status, 200);
      const body = (await response.json()) as {
        WebAuthn: { Enabled: boolean; Keys: unknown[] };
        UserVerificationToken: string;
      };
      assert.equal(body.WebAuthn.Enabled, false);
      assert.deepEqual(body.WebAuthn.Keys, []);
      assert.ok(body.UserVerificationToken);
      return body.UserVerificationToken;
    }));
  const options = await authedFetch(env, {
    method: 'POST',
    path: '/api/two-factor/get-webauthn-challenge',
    body: { userVerificationToken },
    userId: user.id,
  }).then(async (response) => {
    assert.equal(response.status, 200);
    const body = (await response.json()) as {
      Options: { challenge: string; rp: { id: string }; excludeCredentials: unknown[] };
    };
    assert.ok(Array.isArray(body.Options.excludeCredentials));
    return body.Options;
  });

  const { publicKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const { x, y } = await crypto.subtle.exportKey('jwk', publicKey);
  const coseKey = isoCBOR.encode(
    new Map<number, CborValue>([
      [cose.COSEKEYS.kty, cose.COSEKTY.EC2],
      [cose.COSEKEYS.alg, cose.COSEALG.ES256],
      [cose.COSEKEYS.crv, cose.COSECRV.P256],
      [cose.COSEKEYS.x, Buffer.from(x!, 'base64url')],
      [cose.COSEKEYS.y, Buffer.from(y!, 'base64url')],
    ]),
  );
  const credentialId = crypto.getRandomValues(new Uint8Array(CREDENTIAL_ID_BYTES));
  const credentialIdLength = new Uint8Array(CREDENTIAL_ID_LENGTH_BYTES);
  new DataView(credentialIdLength.buffer).setUint16(0, credentialId.length);
  const authData = Buffer.concat([
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(options.rp.id))),
    Uint8Array.of(FLAG_USER_PRESENT | FLAG_ATTESTED_CREDENTIAL_DATA),
    new Uint8Array(SIGN_COUNT_BYTES),
    new Uint8Array(AAGUID_BYTES),
    credentialIdLength,
    credentialId,
    coseKey,
  ]);
  const attestationObject = isoCBOR.encode(
    new Map<string, CborValue>([
      ['fmt', 'none'],
      ['attStmt', new Map()],
      ['authData', authData],
    ]),
  );
  // The Worker serves itself as the RP, so the vault origin is the RP ID over https.
  const clientData = { type: 'webauthn.create', challenge: options.challenge, origin: `https://${options.rp.id}` };

  return {
    env,
    user,
    userVerificationToken,
    deviceResponse: {
      id: base64Url(credentialId),
      rawId: base64Url(credentialId),
      type: 'public-key',
      extensions: {},
      response: {
        AttestationObject: base64Url(attestationObject),
        clientDataJson: base64Url(new TextEncoder().encode(JSON.stringify(clientData))),
        transports: ['usb'],
      },
    },
  };
}

function putWebAuthn({ env, user, userVerificationToken }: Enrollment, deviceResponse: unknown): Promise<Response> {
  return authedFetch(env, {
    method: 'PUT',
    path: '/api/two-factor/webauthn',
    body: { id: 1, name: 'Security key', userVerificationToken, deviceResponse },
    userId: user.id,
  });
}

test('official web enrolls a WebAuthn two-step-login key with a PascalCase AttestationObject', async () => {
  const enrollment = await officialEnrollment();
  const response = await putWebAuthn(enrollment, enrollment.deviceResponse);
  assert.equal(response.status, 200);
  const body = (await response.json()) as { WebAuthn: { Enabled: boolean; Keys: { Name: string }[] } };
  assert.equal(body.WebAuthn.Enabled, true);
  assert.deepEqual(
    body.WebAuthn.Keys.map(({ Name }) => Name),
    ['Security key'],
  );

  // The dialog keeps the original token through enrollment and deletion.
  const second = await officialEnrollment(enrollment);
  assert.equal((await putWebAuthn(second, second.deviceResponse)).status, 200);
  const removed = await authedFetch(enrollment.env, {
    method: 'DELETE',
    path: '/api/two-factor/webauthn',
    userId: enrollment.user.id,
    body: { id: 1, userVerificationToken: enrollment.userVerificationToken },
  });
  assert.equal(removed.status, 200);
  assert.equal(((await removed.json()) as { WebAuthn: { Keys: unknown[] } }).WebAuthn.Keys.length, 1);
  const lastKey = await authedFetch(enrollment.env, {
    method: 'DELETE',
    path: '/api/two-factor/webauthn',
    userId: enrollment.user.id,
    body: { id: 1, userVerificationToken: enrollment.userVerificationToken },
  });
  assert.equal(lastKey.status, 400);

  const { env, user, userVerificationToken } = enrollment;
  await getOrm(env.DB).insert(webauthnCredentials).values({
    id: 'login-key',
    userId: user.id,
    purpose: 'login',
    name: 'Login key',
    publicKey: 'cHVibGlj',
    credentialId: 'login-credential',
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  });
  const disabled = await authedFetch(env, {
    method: 'DELETE',
    path: '/api/two-factor/webauthn/all',
    userId: user.id,
    body: { userVerificationToken },
  });
  assert.equal(disabled.status, 204);
  assert.equal(await disabled.text(), '');
  const remaining = await getOrm(env.DB)
    .select({ id: webauthnCredentials.id, purpose: webauthnCredentials.purpose })
    .from(webauthnCredentials)
    .where(eq(webauthnCredentials.userId, user.id));
  assert.deepEqual(remaining, [{ id: 'login-key', purpose: 'login' }]);
});

test('a WebAuthn enrollment without an attestation object in either casing is rejected', async () => {
  const enrollment = await officialEnrollment();
  const { AttestationObject: _omitted, ...withoutAttestation } = enrollment.deviceResponse.response;
  const response = await putWebAuthn(enrollment, { ...enrollment.deviceResponse, response: withoutAttestation });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, INVALID_REGISTRATION);
});

for (const action of ['reset', 'delete'] as const) {
  test(`pending WebAuthn enrollment cannot write after account ${action}`, async () => {
    const enrollment = await officialEnrollment();
    const { env, user } = enrollment;
    env.ADMIN_EMAILS = 'admin@x.io';
    await userRepo.saveUser(env.DB, { ...user, totpSecret: 'JBSWY3DPEHPK3PXP' }, ['totpSecret']);
    const portal = await signInToAdminPortal(env, 'admin@x.io');
    let interrupted = false;
    interceptStatement(env, /insert into "webauthn_credentials"/i, async () => {
      interrupted = true;
      const response =
        action === 'reset'
          ? await portalFetch(env, {
              method: 'POST',
              path: `/admin/users/${user.id}/remove-2fa`,
              cookie: portal.cookie,
              form: { csrf: portal.csrf, confirmation: user.email },
            })
          : await authedFetch(env, {
              method: 'DELETE',
              path: '/api/accounts',
              userId: user.id,
              body: { masterPasswordHash: CLIENT_MASTER_PASSWORD_HASH },
            });
      assert.equal(response.status, action === 'reset' ? 303 : 200);
    });
    const result = await putWebAuthn(enrollment, enrollment.deviceResponse);
    assert.equal(result.status, 400);
    assert.equal(interrupted, true);
    assert.equal(await passkeyRepo.countAccountPasskeyCredentialsByUserId(env.DB, user.id, 'twoFactor'), 0);
    const current = await userRepo.getUserById(env.DB, user.id);
    if (action === 'delete') assert.equal(current, null);
    else {
      assert.equal(current!.totpSecret, null);
      assert.equal(current!.totpRecoveryCode, null);
    }
  });
}
