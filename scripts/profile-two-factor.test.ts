import assert from 'node:assert/strict';
import test from 'node:test';

import type { User } from '../src/types';
import { buildProfileResponse } from '../src/utils/profile-response';

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-1',
    email: 'user@example.test',
    name: 'Test User',
    masterPasswordHash: '',
    masterPasswordHint: null,
    key: '',
    privateKey: null,
    publicKey: null,
    kdfType: 0,
    kdfIterations: 600000,
    securityStamp: 'stamp',
    role: 'user',
    status: 'active',
    totpSecret: null,
    totpRecoveryCode: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    ...overrides,
  } as User;
}

test('profile reports two-factor disabled when no provider is set up', () => {
  assert.equal(buildProfileResponse(makeUser()).twoFactorEnabled, false);
});

test('profile reports two-factor enabled for an authenticator secret', () => {
  assert.equal(buildProfileResponse(makeUser({ totpSecret: 'JBSWY3DPEHPK3PXP' })).twoFactorEnabled, true);
});

test('profile reports two-factor enabled when only a two-factor passkey is registered', () => {
  const profile = buildProfileResponse(makeUser(), undefined, { hasTwoFactorPasskey: true });

  assert.equal(profile.twoFactorEnabled, true);
  assert.equal(profile.yubikeyEnabled, false);
});

test('profile ignores a missing or false two-factor passkey flag', () => {
  assert.equal(buildProfileResponse(makeUser(), undefined, {}).twoFactorEnabled, false);
  assert.equal(buildProfileResponse(makeUser(), undefined, { hasTwoFactorPasskey: false }).twoFactorEnabled, false);
});
