import assert from 'node:assert/strict';
import test from 'node:test';

import { createTestEnv } from '../test/support/env';
import { getConfigValue, setConfigValue } from './storage-config-repo';
import { YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, initializeYubicoCredentialsOnce } from './yubico-config';

const NOW = 1_800_000_000_000;

// The OTP is malformed, so a request that takes the claim gives up without calling Yubico and releases it.
test('a Yubico bootstrap claim holds through its expiry instant and is cleared only once it has passed', async (t) => {
  const env = await createTestEnv();
  t.mock.method(Date, 'now', () => NOW);
  for (const [expiresAt, cleared] of [
    [NOW, false],
    [NOW - 1, true],
  ] as const) {
    const claim = `${expiresAt}:other-request`;
    await setConfigValue(env.DB, YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, claim);
    assert.equal(await initializeYubicoCredentialsOnce(env.DB, 'owner@example.test', 'not-a-yubikey-otp'), null);
    assert.equal(await getConfigValue(env.DB, YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY), cleared ? null : claim);
  }
});
