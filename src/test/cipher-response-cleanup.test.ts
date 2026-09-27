import assert from 'node:assert/strict';
import test from 'node:test';

import type { Cipher } from '../types';
import * as cipherRepo from '../services/storage-cipher-repo';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const ENC = '2.dGVzdA==|dGVzdA==|dGVzdA==';
const NOW = '2026-01-02T03:04:05.000Z';
const FIDO2_REQUIRED = {
  credentialId: ENC,
  keyType: ENC,
  keyAlgorithm: ENC,
  keyCurve: ENC,
  keyValue: ENC,
  rpId: ENC,
  counter: ENC,
  discoverable: ENC,
};

// Ciphers are stored as the client sent them, so the response path is what drops or defaults
// malformed nested entries. The expected JSON is compared as text to pin key order as well.
test('cipher responses drop malformed stored entries and default the rest', async (context) => {
  context.mock.timers.enable({ apis: ['Date'], now: Date.parse(NOW) });
  const env = await createTestEnv();
  const user = await seedUser(env);
  const stored = {
    id: crypto.randomUUID(),
    userId: user.id,
    type: 1,
    folderId: null,
    name: ENC,
    notes: null,
    favorite: false,
    reprompt: 0,
    key: null,
    createdAt: NOW,
    updatedAt: NOW,
    archivedAt: null,
    deletedAt: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    login: {
      username: ` ${ENC} `,
      password: 'plaintext',
      totp: null,
      uris: [
        null,
        'https://example.test',
        { uri: ENC, match: 0 },
        { uri: 'plaintext', uriChecksum: ENC },
        { uri: 'plaintext', match: null },
        { match: 3 },
        { extra: 'kept', uri: ENC, uriChecksum: ENC },
      ],
      fido2Credentials: [
        null,
        { ...FIDO2_REQUIRED, credentialId: 'plaintext' },
        { extra: 'kept', ...FIDO2_REQUIRED, keyValue: ` ${ENC} `, userName: 'plaintext', rpName: ENC },
        FIDO2_REQUIRED,
      ],
    },
    fields: [
      null,
      'text',
      { extra: 'kept', name: ENC, value: 'plaintext', type: '1' },
      { type: 'hidden', linkedId: 5 },
    ],
    passwordHistory: [
      null,
      { password: 'plaintext', lastUsedDate: NOW },
      { lastUsedDate: '2025-05-06T07:08:09Z', extra: 'kept', password: ` ${ENC} ` },
      { password: ENC, lastUsedDate: 'garbage' },
      { password: 5 },
    ],
  };
  await cipherRepo.saveCipher(env.DB, stored as unknown as Cipher);

  const response = await authedFetch(env, { path: `/api/ciphers/${stored.id}`, userId: user.id });
  assert.equal(response.status, 200);
  const body = (await response.json()) as Record<string, unknown>;
  assert.equal(
    JSON.stringify(body.login),
    JSON.stringify({
      username: ENC,
      password: null,
      totp: null,
      uris: [
        { uri: ENC, match: 0, uriChecksum: null },
        { uri: null, uriChecksum: ENC },
        { match: 3 },
        { extra: 'kept', uri: ENC, uriChecksum: ENC },
      ],
      fido2Credentials: [{ extra: 'kept', ...FIDO2_REQUIRED, userName: null, rpName: ENC }, FIDO2_REQUIRED],
    }),
  );
  assert.equal(
    JSON.stringify(body.fields),
    JSON.stringify([
      { extra: 'kept', name: ENC, value: null, type: 1, linkedId: null },
      { type: 0, linkedId: 5, name: null, value: null },
    ]),
  );
  assert.equal(
    JSON.stringify(body.passwordHistory),
    JSON.stringify([
      { lastUsedDate: '2025-05-06T07:08:09.000Z', extra: 'kept', password: ENC },
      { password: ENC, lastUsedDate: NOW },
    ]),
  );
});
