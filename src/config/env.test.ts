import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readEnvConfig } from './env';

test('env config keeps each variable degrading to its historical default', () => {
  const defaults = readEnvConfig({});
  assert.deepEqual(defaults.JWT_SECRET, { kind: 'missing' });
  assert.equal(defaults.SSO_SIGNUPS, true);
  assert.equal(defaults.SSO_SCOPES, 'openid profile email');
  assert.equal(defaults.R2_BUCKET, 'nodewarden-attachments');
  assert.deepEqual(readEnvConfig({ JWT_SECRET: ' short ' }).JWT_SECRET, { kind: 'too_short' });
  for (const [value, enabled] of [
    [' 1 ', true],
    ['true', false],
    ['0', false],
  ] as const) {
    assert.equal(readEnvConfig({ ALLOW_OPEN_REGISTRATION: value }).ALLOW_OPEN_REGISTRATION, enabled, value);
  }
  for (const [value, enabled] of [
    ['0', false],
    ['false', true],
    ['', true],
  ] as const) {
    assert.equal(readEnvConfig({ SSO_SIGNUPS: value }).SSO_SIGNUPS, enabled, value);
  }
  const listed = readEnvConfig({
    WEB_VAULT_ORIGINS: ' https://a.example/x, bad, https://a.example ',
    SSO_AUTHORITY: 'https://idp.example//',
  });
  assert.deepEqual(listed.WEB_VAULT_ORIGINS, ['https://a.example']);
  assert.equal(listed.SSO_AUTHORITY, 'https://idp.example');
});
