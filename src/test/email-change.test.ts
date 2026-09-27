import assert from 'node:assert/strict';
import test from 'node:test';
import { pbkdf2Sync } from 'node:crypto';

import { AuthService } from '../services/auth';
import { upsertCredentialAccount } from '../services/auth-accounts';
import { hashPassword, verifyPassword } from '../services/auth-password';
import type { Env, User } from '../types';
import { authedFetch, captureEmail, createTestEnv, drainWaitUntil, MAILABLE_DOMAIN, seedUser } from './support/env';
import * as revisionRepo from '../services/storage-revision-repo';
import * as sessionRepo from '../services/storage-session-repo';
import * as userRepo from '../services/storage-user-repo';

const OLD_EMAIL = `old@${MAILABLE_DOMAIN}`;
const NEW_EMAIL = `new@${MAILABLE_DOMAIN}`;
const OLD_HASH = 'old-client-derived-hash';
const NEW_HASH = 'new-client-derived-hash';
const NEW_KEY = '2.bmV3|bmV3|bmV3';

async function setup(overrides: Partial<User> = {}, envOverrides: Partial<Env> = {}) {
  const mail = captureEmail();
  const env = await createTestEnv({ ...mail.overrides, ...envOverrides });
  const user = await seedUser(env, { email: OLD_EMAIL, masterPasswordHash: await hashPassword(OLD_HASH), ...overrides });
  await upsertCredentialAccount(env.DB, user.id, user.masterPasswordHash);
  const requestCode = (email = NEW_EMAIL, hash = OLD_HASH) => authedFetch(env, {
    method: 'POST', path: '/api/accounts/email-token', userId: user.id, body: { masterPasswordHash: hash, newEmail: email },
  });
  const code = () => String(mail.sent.filter(message => String(message.subject).includes('verification code')).at(-1)?.text).match(/\b\d{6}\b/)![0];
  const change = (extra: Record<string, unknown> = {}) => authedFetch(env, {
    method: 'POST', path: '/api/accounts/email', userId: user.id,
    body: { masterPasswordHash: OLD_HASH, newEmail: NEW_EMAIL, newMasterPasswordHash: NEW_HASH, key: NEW_KEY, token: code(), ...extra },
  });
  return { env, user, mail, requestCode, code, change };
}

async function assertOriginal(f: Awaited<ReturnType<typeof setup>>) {
  const user = (await userRepo.getUserById(f.env.DB, f.user.id))!;
  assert.equal(user.email, f.user.email);
  assert.equal(user.masterPasswordHash, f.user.masterPasswordHash);
  assert.equal(user.key, f.user.key);
  assert.equal(user.securityStamp, f.user.securityStamp);
  assert.equal(await f.env.DB.prepare("SELECT password FROM account WHERE user_id=? AND provider_id='credential'").bind(user.id).first('password'), f.user.masterPasswordHash);
}

test('email-token verifies the old password, conceals taken addresses, and uses one shared subject budget', async () => {
  const f = await setup();
  const existing = await seedUser(f.env, { email: `taken@${MAILABLE_DOMAIN}` });
  const wrong = await f.requestCode(NEW_EMAIL, 'wrong');
  assert.equal(wrong.status, 400);
  assert.deepEqual((await wrong.json() as { validationErrors: unknown }).validationErrors, { MasterPasswordHash: ['Invalid password.'] });
  assert.equal(f.mail.sent.length, 0);
  const taken = await f.requestCode(existing.email);
  assert.equal(taken.status, 200);
  assert.equal(await taken.text(), '');
  assert.equal(f.mail.sent.length, 1);
  assert.equal(f.mail.sent[0].to, OLD_EMAIL);
  assert.match(String(f.mail.sent[0].text), /already used/);
  assert.equal(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM verification WHERE identifier LIKE 'otp:email-change:%'").first('n'), 0);
  for (let index = 0; index < 4; index++) {
    const free = await f.requestCode(`free${index}@${MAILABLE_DOMAIN}`);
    assert.equal(free.status, 200);
    assert.equal(await free.text(), '');
  }
  assert.equal((await f.requestCode(existing.email)).status, 429);
  assert.equal((await f.requestCode(NEW_EMAIL)).status, 429);
  assert.equal(f.mail.sent.length, 5);
  assert.ok(f.mail.sent.slice(1).every(message => !/\b\d{6}\b/.test(String(message.subject))));
});

test('malformed key/KDF changes do not burn the code, which is bound to the normalized new address', async () => {
  const f = await setup();
  assert.equal((await f.requestCode(NEW_EMAIL.toUpperCase())).status, 200);
  assert.equal(f.mail.sent[0].to, NEW_EMAIL);
  assert.match(String(f.mail.sent[0].text), /confirm your new email/);
  for (const extra of [{ key: 'bad' }, { kdf: 1 }, { kdfIterations: '600000' }, { kdfMemory: 64 }]) {
    assert.equal((await f.change(extra)).status, 400);
    assert.equal(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM verification WHERE identifier LIKE 'otp:email-change:%'").first('n'), 1);
  }
  const wrongAddress = await f.change({ newEmail: `other@${MAILABLE_DOMAIN}` });
  assert.equal(wrongAddress.status, 400);
  assert.equal((await wrongAddress.json() as { error: string }).error, 'Invalid token.');
  assert.equal((await f.change({ newEmail: ` ${NEW_EMAIL.toUpperCase()} ` })).status, 200);
  assert.equal((await userRepo.getUserById(f.env.DB, f.user.id))?.email, NEW_EMAIL);
  await drainWaitUntil();
});

test('legacy old-email password proof becomes a new-email hash/key and revokes old sessions without changing the factor address', async () => {
  const legacy = '$s$' + pbkdf2Sync(OLD_HASH, OLD_EMAIL, 100000, 32, 'sha256').toString('base64');
  const f = await setup({ masterPasswordHash: legacy, emailVerified: false });
  // Restored users may have no Better Auth credential row; the same batch must create it.
  await f.env.DB.prepare('DELETE FROM account WHERE user_id=?').bind(f.user.id).run();
  await sessionRepo.saveRefreshToken(f.env.DB, 'old-refresh', f.user.id);
  const oldJwt = await new AuthService(f.env).generateAccessToken(f.user);
  assert.equal((await f.requestCode()).status, 200);
  const changed = await f.change();
  assert.equal(changed.status, 200);
  assert.equal(await changed.text(), '');
  const updated = (await userRepo.getUserById(f.env.DB, f.user.id))!;
  assert.equal(updated.email, NEW_EMAIL);
  assert.equal(updated.emailVerified, true);
  assert.equal(updated.key, NEW_KEY);
  assert.ok(updated.masterPasswordHash.startsWith('$s2$'));
  assert.notEqual(updated.securityStamp, f.user.securityStamp);
  assert.equal(await verifyPassword(NEW_HASH, updated.masterPasswordHash, NEW_EMAIL), true);
  assert.equal(await f.env.DB.prepare("SELECT password FROM account WHERE user_id=? AND provider_id='credential'").bind(f.user.id).first('password'), updated.masterPasswordHash);
  assert.equal(await sessionRepo.getRefreshTokenRecord(f.env.DB, 'old-refresh'), null);
  assert.equal((await authedFetch(f.env, { path: '/api/accounts/profile', headers: { Authorization: `Bearer ${oldJwt}` } })).status, 401);
  for (const [username, password, status] of [[OLD_EMAIL, OLD_HASH, 400], [NEW_EMAIL, NEW_HASH, 200]] as const) {
    const login = await authedFetch(f.env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username, password } });
    assert.equal(login.status, status);
  }
  const prelogin = await authedFetch(f.env, { method: 'POST', path: '/identity/accounts/prelogin', body: { email: NEW_EMAIL } });
  assert.equal((await prelogin.json() as { Salt: string }).Salt, NEW_EMAIL);
  const betterAuth = await authedFetch(f.env, { method: 'POST', path: '/api/auth/sign-in/email', body: { email: NEW_EMAIL, password: NEW_HASH } });
  assert.equal(betterAuth.status, 200);
  await drainWaitUntil();
  const notice = f.mail.sent.filter(message => String(message.subject).includes('email address changed'));
  assert.equal(notice.length, 1);
  assert.equal(notice[0].to, OLD_EMAIL);
  assert.match(String(notice[0].text), /Time \(UTC\).*IP address/);
  assert.equal(await f.env.DB.prepare("SELECT COUNT(*) AS n FROM audit_logs WHERE action='user.email.change'").first('n'), 1);

  const separate = await setup({ twoFactorEmail: `factor@${MAILABLE_DOMAIN}`, apiKey: 'same-api-key', privateKey: 'same-private-key', publicKey: 'same-public-key' });
  await separate.requestCode();
  assert.equal((await separate.change()).status, 200);
  const preserved = (await userRepo.getUserById(separate.env.DB, separate.user.id))!;
  for (const field of ['twoFactorEmail', 'apiKey', 'privateKey', 'publicKey', 'kdfType', 'kdfIterations'] as const) assert.equal(preserved[field], separate.user[field]);
  await drainWaitUntil();
});

test('email-change codes expire with a changed stamp and enforce a five-attempt budget', async () => {
  const f = await setup();
  await f.requestCode();
  const changedPassword = await authedFetch(f.env, { method: 'POST', path: '/api/accounts/password', userId: f.user.id, body: { masterPasswordHash: OLD_HASH, newMasterPasswordHash: 'interim-hash', key: f.user.key } });
  assert.equal(changedPassword.status, 200);
  const stale = await f.change({ masterPasswordHash: 'interim-hash' });
  assert.equal(stale.status, 400);
  assert.equal((await stale.json() as { error: string }).error, 'Invalid token.');
  const attempts = await setup();
  await attempts.requestCode();
  const wrong = attempts.code() === '000000' ? '111111' : '000000';
  for (let index = 0; index < 5; index++) assert.equal((await attempts.change({ token: wrong })).status, 400);
  assert.equal((await attempts.change()).status, 400);
  await assertOriginal(attempts);
});

test('duplicate-email and audit failures roll back the entire account mutation; a lost stamp writes no dependent rows', async () => {
  for (const kind of ['duplicate', 'audit', 'stamp']) {
    const f = await setup();
    await f.requestCode();
    await sessionRepo.saveRefreshToken(f.env.DB, 'existing-session', f.user.id);
    const revision = await revisionRepo.getRevisionDate(f.env.DB, f.user.id);
    if (kind === 'audit') await f.env.DB.prepare("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_logs BEGIN SELECT RAISE(ABORT,'forced email audit failure'); END").run();
    const batch = f.env.DB.batch.bind(f.env.DB);
    f.env.DB.batch = async statements => {
      if (kind === 'duplicate') await seedUser(f.env, { email: NEW_EMAIL });
      if (kind === 'stamp') await f.env.DB.prepare('UPDATE users SET security_stamp=? WHERE id=?').bind('newer-stamp', f.user.id).run();
      return batch(statements);
    };
    const response = await f.change();
    assert.equal(response.status, kind === 'audit' ? 500 : 400, kind);
    if (kind === 'duplicate') assert.equal((await response.json() as { error: string }).error, 'Email already in use.');
    if (kind === 'stamp') {
      const user = (await userRepo.getUserById(f.env.DB, f.user.id))!;
      assert.equal(user.securityStamp, 'newer-stamp');
      assert.equal(user.email, OLD_EMAIL);
      assert.equal(user.masterPasswordHash, f.user.masterPasswordHash);
    } else await assertOriginal(f);
    assert.ok(await sessionRepo.getRefreshTokenRecord(f.env.DB, 'existing-session'));
    assert.equal(await revisionRepo.getRevisionDate(f.env.DB, f.user.id), revision);
    assert.equal(await f.env.DB.prepare('SELECT COUNT(*) AS n FROM audit_logs').first('n'), 0);
    await drainWaitUntil();
    assert.equal(f.mail.sent.filter(message => String(message.subject).includes('email address changed')).length, 0);
  }
});

test('verified changes onto listed addresses promote, while the last listed administrator moving away keeps the no-lockout role', async () => {
  const promotion = await setup({}, { ADMIN_EMAILS: NEW_EMAIL });
  await promotion.requestCode();
  assert.equal((await promotion.change()).status, 200);
  assert.equal((await userRepo.getUserById(promotion.env.DB, promotion.user.id))?.role, 'admin');
  const retention = await setup({ role: 'admin' }, { ADMIN_EMAILS: OLD_EMAIL });
  await retention.requestCode();
  assert.equal((await retention.change()).status, 200);
  assert.equal((await userRepo.getUserById(retention.env.DB, retention.user.id))?.role, 'admin');
  await drainWaitUntil();
});

test('an old password-change mirror cannot overwrite a later atomic email change or delete its new session', async (t) => {
  const f = await setup();
  const prepare = f.env.DB.prepare.bind(f.env.DB);
  let interrupted = false;
  let newRefresh = '';
  t.mock.method(f.env.DB, 'prepare', (query: string) => {
    const statement = prepare(query);
    if (query.startsWith('insert into "account" ')) {
      const bind = statement.bind.bind(statement);
      statement.bind = (...values) => {
        const bound = bind(...values);
        const run = bound.run.bind(bound);
        bound.run = async () => {
          if (!interrupted) {
            interrupted = true;
            assert.equal((await f.requestCode(NEW_EMAIL, 'interim-hash')).status, 200);
            assert.equal((await f.change({ masterPasswordHash: 'interim-hash' })).status, 200);
            const login = await authedFetch(f.env, { method: 'POST', path: '/identity/connect/token', body: { grant_type: 'password', username: NEW_EMAIL, password: NEW_HASH } });
            assert.equal(login.status, 200);
            newRefresh = (await login.json() as { refresh_token: string }).refresh_token;
          }
          return run();
        };
        return bound;
      };
    }
    return statement;
  });
  const delayed = await authedFetch(f.env, { method: 'POST', path: '/api/accounts/password', userId: f.user.id, body: { masterPasswordHash: OLD_HASH, newMasterPasswordHash: 'interim-hash', key: f.user.key } });
  assert.equal(interrupted, true);
  assert.equal(delayed.status, 400);
  const updated = (await userRepo.getUserById(f.env.DB, f.user.id))!;
  assert.equal(updated.email, NEW_EMAIL);
  assert.equal(await verifyPassword(NEW_HASH, updated.masterPasswordHash), true);
  assert.equal(await f.env.DB.prepare("SELECT password FROM account WHERE user_id=? AND provider_id='credential'").bind(f.user.id).first('password'), updated.masterPasswordHash);
  assert.ok(newRefresh);
  assert.ok(await sessionRepo.getRefreshTokenRecord(f.env.DB, newRefresh));
  await drainWaitUntil();
});
