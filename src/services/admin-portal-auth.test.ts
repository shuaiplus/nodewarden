import assert from 'node:assert/strict';
import test from 'node:test';
import { parseAdminDirectory, checkPortalRequest, adminReturnPath } from './admin-portal-auth';
import { sha256Base64Url } from '../utils/account-passkeys';

test('admin directory validates every entry and hashes stamps', async () => {
  assert.deepEqual(parseAdminDirectory({}), { kind: 'disabled' });
  assert.deepEqual(parseAdminDirectory({ ADMIN_EMAILS: ' , ' }), { kind: 'disabled' });
  assert.deepEqual(parseAdminDirectory({ ADMIN_EMAILS: ' A@x.io , b@y.io:s1 ' }), {
    kind: 'enabled',
    admins: new Map([
      ['a@x.io', await sha256Base64Url('a@x.io')],
      ['b@y.io', await sha256Base64Url('s1')],
    ]),
  });
  for (const entry of [
    'bad',
    'a@b',
    ':x',
    'a@b.io:',
    'a@b.io:a b',
    'a@b.io:a\u0001b',
    'a'.repeat(257) + '@b.io',
    'a@b.io,A@b.io',
  ]) {
    assert.equal(parseAdminDirectory({ ADMIN_EMAILS: entry }).kind, 'invalid', entry);
  }
});

test('portal navigation, origin and return paths are constrained', () => {
  const origin = 'https://vault.io';
  for (const input of [
    'https://evil.test',
    '//evil.test',
    '/\\evil.test',
    '/%09/evil.test',
    '/admin/../api/sync',
    '/api/sync',
    '/admin/login/logout',
  ])
    assert.equal(adminReturnPath(input, origin), '/admin');
  assert.equal(adminReturnPath('/admin/users?page=2', origin), '/admin/users?page=2');
  for (const headers of [
    { Origin: 'null' },
    { Origin: 'https://evil.io' },
    {},
    { Origin: origin, 'Sec-Fetch-Mode': 'cors', 'Sec-Fetch-Dest': 'empty' },
  ] as Record<string, string>[])
    assert.equal(checkPortalRequest(new Request(origin, { method: 'POST', headers })), false);
  assert.equal(
    checkPortalRequest(new Request(origin, { method: 'POST', headers: { 'Sec-Fetch-Site': 'same-origin' } })),
    true,
  );
});
