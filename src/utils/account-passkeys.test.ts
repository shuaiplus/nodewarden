import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  normalizeAuthenticationResponse, normalizeRegistrationResponse, normalizeTransports, userHandleToUserId, userIdToWebAuthnUserId,
} from './account-passkeys';
import { normalizeJsonKeys } from './response';

// Mirrors the deviceResponse built by putTwoFactorWebAuthn in the official web vault
// (clients web-v2026.9.0 default-two-factor-api.service.ts): base64url values and a
// PascalCase AttestationObject next to a camelCase clientDataJson. Route bodies pass through
// normalizeJsonKeys before reaching the parser, so the test does too.
const officialTwoFactorDeviceResponse = {
  id: 'Y3JlZGVudGlhbC1pZA',
  rawId: 'Y3JlZGVudGlhbC1pZA',
  type: 'public-key',
  extensions: {},
  response: {
    AttestationObject: 'YXR0ZXN0YXRpb24tb2JqZWN0',
    clientDataJson: 'Y2xpZW50LWRhdGEtanNvbg',
    transports: ['usb', 'nfc'],
  },
};

test('accepts the official web 2FA WebAuthn body with PascalCase AttestationObject', () => {
  const normalized = normalizeRegistrationResponse(normalizeJsonKeys(officialTwoFactorDeviceResponse));
  const { AttestationObject, clientDataJson, transports } = officialTwoFactorDeviceResponse.response;
  assert.ok(normalized);
  assert.equal(normalized.response.attestationObject, AttestationObject);
  assert.equal(normalized.response.clientDataJSON, clientDataJson);
  assert.deepEqual(normalized.response.transports, transports);
});

test('rejects a registration body without an attestation object in either casing', () => {
  const { clientDataJson, transports } = officialTwoFactorDeviceResponse.response;
  assert.equal(
    normalizeRegistrationResponse(normalizeJsonKeys({ ...officialTwoFactorDeviceResponse, response: { clientDataJson, transports } })),
    null
  );
});

test('reads padded base64 assertions as base64url, requires client data and keeps only WebAuthn transports', () => {
  const assertion = { id: 'a+b/c==', rawId: 'a+b/c==', response: { authenticatorData: 'ZGF0YQ==', signature: 's+g/', userHandle: '' } };
  assert.equal(normalizeAuthenticationResponse(assertion), null);
  assert.deepEqual(normalizeAuthenticationResponse({ ...assertion, response: { ...assertion.response, clientDataJSON: 'Y2Q=' } }), {
    id: 'a-b_c',
    rawId: 'a-b_c',
    type: 'public-key',
    clientExtensionResults: {},
    response: { authenticatorData: 'ZGF0YQ', signature: 's-g_', userHandle: undefined, clientDataJSON: 'Y2Q' },
  });
  assert.deepEqual(normalizeTransports(['usb', 'carrier-pigeon', 'hybrid']), ['usb', 'hybrid']);
  assert.equal(normalizeTransports('usb'), null);
});

test('GUID user ids round-trip through the .NET Guid byte layout; other ids stay text', () => {
  const userId = '00112233-4455-6677-8899-aabbccddeeff';
  const handle = userIdToWebAuthnUserId(userId.toUpperCase());
  // .NET writes the first three groups little-endian.
  assert.equal(handle.toHex(), '33221100554477668899aabbccddeeff');
  assert.equal(userHandleToUserId(handle.toBase64({ alphabet: 'base64url', omitPadding: true })), userId);
  const legacy = userIdToWebAuthnUserId('legacy-user');
  assert.equal(userHandleToUserId(legacy.toBase64({ alphabet: 'base64url', omitPadding: true })), 'legacy-user');
  assert.equal(userHandleToUserId(undefined), null);
});
