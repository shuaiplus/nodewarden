import assert from 'node:assert/strict';
import test from 'node:test';

import { createTestEnv, seedUser } from '../test/support/env';
import type { AccountPasskeyCredential } from '../types';
import { saveAccountPasskeyCredential } from './storage-account-passkey-repo';

test('a stamp-guarded passkey saves only at the current stamp, and a two-factor one only beside a recovery code', async () => {
  const env = await createTestEnv();
  for (const [totpRecoveryCode, twoFactorSaved] of [
    [null, false],
    ['', false],
    ['ABCD EFGH IJKL MNOP', true],
  ] as const) {
    const user = await seedUser(env, { totpRecoveryCode });
    const save = (purpose: AccountPasskeyCredential['purpose'], securityStamp: string) =>
      saveAccountPasskeyCredential(
        env.DB,
        {
          id: crypto.randomUUID(),
          userId: user.id,
          purpose,
          name: purpose,
          publicKey: 'cHVibGlj',
          credentialId: crypto.randomUUID(),
          counter: 0,
          type: 'public-key',
          aaGuid: null,
          transports: null,
          encryptedUserKey: null,
          encryptedPublicKey: null,
          encryptedPrivateKey: null,
          supportsPrf: false,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        },
        securityStamp,
      );
    assert.equal(await save('twoFactor', user.securityStamp), twoFactorSaved, `recovery code ${totpRecoveryCode}`);
    assert.equal(await save('login', user.securityStamp), true);
    for (const purpose of ['twoFactor', 'login'] as const)
      assert.equal(await save(purpose, 'rotated-stamp'), false, purpose);
  }
});
