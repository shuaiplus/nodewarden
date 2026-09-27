import assert from 'node:assert/strict';
import test from 'node:test';
import { createHmac } from 'node:crypto';
import { upsertTwoFactorSecret } from '../src/services/auth-accounts';
import { hashPassword } from '../src/services/auth-password';
import { authedFetch, createTestEnv, interceptStatement, seedUser, portalFetch, signInToAdminPortal } from './support/env';
import * as userRepo from '../src/services/storage-user-repo';

const PASSWORD = 'enrollment-client-hash';
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
function totp(): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac('sha1', '12345678901234567890').update(counter).digest();
  return String((digest.readUInt32BE(digest[digest.length - 1] & 15) & 0x7fffffff) % 1_000_000).padStart(6, '0');
}

for (const path of ['/api/accounts/totp', '/api/two-factor/authenticator']) {
  for (const action of ['reset', 'delete'] as const) {
    test(`pending ${path} enrollment cannot restore its mirror after account ${action}`, async () => {
      const env = await createTestEnv({ ADMIN_EMAILS: 'admin@x.io' });
      const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD), totpSecret: SECRET, totpRecoveryCode: 'OLD-RECOVERY' });
      await upsertTwoFactorSecret(env.DB, user.id, SECRET, user.totpRecoveryCode!);
      const settings = await authedFetch(env, { method: 'POST', path: '/api/two-factor/get-authenticator', userId: user.id, body: { masterPasswordHash: PASSWORD } });
      const { UserVerificationToken: userVerificationToken } = await settings.json() as { UserVerificationToken: string };
      const portal = await signInToAdminPortal(env, 'admin@x.io');
      let interrupted = false;
      // The account row already carries the new secret; the reset or deletion lands before its mirror write.
      interceptStatement(env, /insert into "two_factor"/i, async () => {
        interrupted = true;
        const response = action === 'reset'
          ? await portalFetch(env, { method: 'POST', path: `/admin/users/${user.id}/remove-2fa`, cookie: portal.cookie, form: { csrf: portal.csrf, confirmation: user.email } })
          : await authedFetch(env, { method: 'DELETE', path: '/api/accounts', userId: user.id, body: { masterPasswordHash: PASSWORD } });
        assert.equal(response.status, action === 'reset' ? 303 : 200);
      });
      const response = await authedFetch(env, {
        method: 'PUT', path, userId: user.id,
        body: path === '/api/accounts/totp' ? { enabled: true, secret: SECRET, token: totp(), masterPasswordHash: PASSWORD }
          : { key: SECRET, token: totp(), userVerificationToken },
      });
      assert.equal(response.status, 400, await response.clone().text());
      assert.equal(interrupted, true);
      assert.equal(await env.DB.prepare('SELECT secret FROM two_factor WHERE user_id=?').bind(user.id).first(), null);
      const current = await userRepo.getUserById(env.DB, user.id);
      if (action === 'delete') assert.equal(current, null);
      else { assert.equal(current!.totpSecret, null); assert.equal(current!.totpRecoveryCode, null); }
    });
  }
}

test('a delayed TOTP mirror cannot overwrite a replacement made under the same stamp', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env, { totpSecret: SECRET, totpRecoveryCode: 'RECOVERY' });
  assert.equal(await upsertTwoFactorSecret(env.DB, user.id, SECRET, 'RECOVERY', user.securityStamp), true);
  const nextSecret = 'JBSWY3DPEHPK3PXP';
  await userRepo.saveUser(env.DB, { ...user, totpSecret: nextSecret }, ['totpSecret']);
  assert.equal(await upsertTwoFactorSecret(env.DB, user.id, nextSecret, 'RECOVERY', user.securityStamp), true);
  assert.equal(await upsertTwoFactorSecret(env.DB, user.id, SECRET, 'RECOVERY', user.securityStamp), false);
  assert.equal(await env.DB.prepare('SELECT secret FROM two_factor WHERE user_id=?').bind(user.id).first('secret'), nextSecret);
});
