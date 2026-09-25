import assert from 'node:assert/strict';
import { test } from 'node:test';

import { normalizeRegistrationResponse } from './account-passkeys';

// Mirrors the deviceResponse built by putTwoFactorWebAuthn in the official web vault
// (clients web-v2026.9.0 default-two-factor-api.service.ts): base64url values and a
// PascalCase AttestationObject next to a camelCase clientDataJson.
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
  const normalized = normalizeRegistrationResponse(officialTwoFactorDeviceResponse);
  const { AttestationObject, clientDataJson, transports } = officialTwoFactorDeviceResponse.response;
  assert.ok(normalized);
  assert.equal(normalized.response.attestationObject, AttestationObject);
  assert.equal(normalized.response.clientDataJSON, clientDataJson);
  assert.deepEqual(normalized.response.transports, transports);
});

test('rejects a registration body without an attestation object in either casing', () => {
  const { clientDataJson, transports } = officialTwoFactorDeviceResponse.response;
  assert.equal(
    normalizeRegistrationResponse({ ...officialTwoFactorDeviceResponse, response: { clientDataJson, transports } }),
    null
  );
});
