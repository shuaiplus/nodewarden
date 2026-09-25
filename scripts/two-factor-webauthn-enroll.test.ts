import assert from 'node:assert/strict';
import test from 'node:test';

import { cose, isoCBOR } from '@simplewebauthn/server/helpers';

import { AuthService } from '../src/services/auth';
import type { Env, User } from '../src/types';
import { authedFetch, createTestEnv, seedUser } from './support/env';

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
async function officialEnrollment(): Promise<Enrollment> {
  const env = await createTestEnv();
  const user = await seedUser(env, { masterPasswordHash: await new AuthService(env).hashPasswordServer(CLIENT_MASTER_PASSWORD_HASH) });
  const options = await authedFetch(env, {
    method: 'POST',
    path: '/api/two-factor/get-webauthn-challenge',
    body: { masterPasswordHash: CLIENT_MASTER_PASSWORD_HASH },
    userId: user.id,
  }).then((response) => response.json() as Promise<{ challenge: string; rp: { id: string } }>);

  const { publicKey } = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const { x, y } = await crypto.subtle.exportKey('jwk', publicKey);
  const coseKey = isoCBOR.encode(new Map<number, CborValue>([
    [cose.COSEKEYS.kty, cose.COSEKTY.EC2],
    [cose.COSEKEYS.alg, cose.COSEALG.ES256],
    [cose.COSEKEYS.crv, cose.COSECRV.P256],
    [cose.COSEKEYS.x, Buffer.from(x!, 'base64url')],
    [cose.COSEKEYS.y, Buffer.from(y!, 'base64url')],
  ]));
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
  const attestationObject = isoCBOR.encode(new Map<string, CborValue>([
    ['fmt', 'none'],
    ['attStmt', new Map()],
    ['authData', authData],
  ]));
  // The Worker serves itself as the RP, so the vault origin is the RP ID over https.
  const clientData = { type: 'webauthn.create', challenge: options.challenge, origin: `https://${options.rp.id}` };

  return {
    env,
    user,
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

function putWebAuthn({ env, user }: Enrollment, deviceResponse: unknown): Promise<Response> {
  return authedFetch(env, {
    method: 'PUT',
    path: '/api/two-factor/webauthn',
    body: { id: 1, name: 'Security key', masterPasswordHash: CLIENT_MASTER_PASSWORD_HASH, deviceResponse },
    userId: user.id,
  });
}

test('official web enrolls a WebAuthn two-step-login key with a PascalCase AttestationObject', async () => {
  const enrollment = await officialEnrollment();
  const response = await putWebAuthn(enrollment, enrollment.deviceResponse);
  assert.equal(response.status, 200);
  const body = await response.json() as { Enabled: boolean; Keys: { Name: string }[] };
  assert.equal(body.Enabled, true);
  assert.deepEqual(body.Keys.map(({ Name }) => Name), ['Security key']);
});

test('a WebAuthn enrollment without an attestation object in either casing is rejected', async () => {
  const enrollment = await officialEnrollment();
  const { AttestationObject: _omitted, ...withoutAttestation } = enrollment.deviceResponse.response;
  const response = await putWebAuthn(enrollment, { ...enrollment.deviceResponse, response: withoutAttestation });
  assert.equal(response.status, 400);
  assert.equal(((await response.json()) as { error: string }).error, INVALID_REGISTRATION);
});
