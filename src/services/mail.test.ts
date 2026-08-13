import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildRegisterVerifyUrl,
  getEmailSender,
  isReservedDocumentationEmail,
  registerVerifyVaultOrigin,
} from './mail';

test('treats RFC documentation addresses as non-deliverable', () => {
  assert.equal(isReservedDocumentationEmail('user@example.com'), true);
  assert.equal(isReservedDocumentationEmail('user@example.org'), true);
  assert.equal(isReservedDocumentationEmail('user@foo.test'), true);
  assert.equal(isReservedDocumentationEmail('user@stevefan1999.tech'), false);
});

test('builds the official-web finish-signup redirect URL', () => {
  const url = buildRegisterVerifyUrl(
    'https://nodewarden-official-web.pages.dev/',
    'Owner@Example.com',
    'tok.en'
  );
  assert.equal(
    url,
    'https://nodewarden-official-web.pages.dev/redirect-connector.html#finish-signup?token=tok.en&email=Owner%40Example.com&fromEmail=true'
  );
});

test('reads EMAIL_FROM from env', () => {
  assert.equal(getEmailSender({}), null);
  assert.deepEqual(
    getEmailSender({ EMAIL_FROM: 'noreply@stevefan1999.tech', EMAIL_FROM_NAME: 'NW' }),
    { email: 'noreply@stevefan1999.tech', name: 'NW' }
  );
});

test('prefers the official web origin for the verification link', () => {
  const env = { WEB_VAULT_ORIGINS: 'https://nodewarden-official-web.pages.dev' };
  const fromPages = registerVerifyVaultOrigin(
    new Request('https://nodewarden.stevefan1999.workers.dev/identity/accounts/register/send-verification-email', {
      headers: { Origin: 'https://nodewarden-official-web.pages.dev' },
    }),
    env
  );
  assert.equal(fromPages, 'https://nodewarden-official-web.pages.dev');

  const fromForwarded = registerVerifyVaultOrigin(
    new Request('https://nodewarden.stevefan1999.workers.dev/identity/accounts/register/send-verification-email', {
      headers: { 'X-Forwarded-Host': 'nodewarden-official-web.pages.dev', 'X-Forwarded-Proto': 'https' },
    }),
    env
  );
  assert.equal(fromForwarded, 'https://nodewarden-official-web.pages.dev');
});
