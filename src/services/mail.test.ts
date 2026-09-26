const binding = { async send() { return { messageId: 'test' }; } };
import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  buildRegisterVerifyUrl,
  readMailConfig,
  isReservedDocumentationEmail,
  configuredVaultOrigin,
  registerVerifyVaultOrigin,
  sanitizeForEmail,
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
  assert.deepEqual(readMailConfig({}), { kind: 'disabled' });
  assert.deepEqual(
    readMailConfig({ EMAIL: binding, EMAIL_FROM: 'noreply@stevefan1999.tech', EMAIL_FROM_NAME: 'NW' }),
    { kind: 'enabled', binding, from: { email: 'noreply@stevefan1999.tech', name: 'NW' } }
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

test('invite links use the caller Origin only when it is a configured web vault', () => {
  const env = { WEB_VAULT_ORIGINS: 'https://a.stevefan1999.tech,https://b.stevefan1999.tech' };
  const inviteRequest = (origin: string) => new Request('https://nodewarden.stevefan1999.workers.dev/api/organizations/o/users/invite', {
    headers: { Origin: origin, 'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'https' },
  });
  assert.equal(configuredVaultOrigin(inviteRequest('https://b.stevefan1999.tech'), env), 'https://b.stevefan1999.tech');
  assert.equal(configuredVaultOrigin(inviteRequest('https://evil.example'), env), 'https://a.stevefan1999.tech');
  assert.equal(configuredVaultOrigin(inviteRequest('https://b.stevefan1999.tech'), {}), null);
});

test('defuses addresses, domains and links in text that another user chose', () => {
  assert.equal(sanitizeForEmail('Acme Inc'), 'Acme Inc');
  assert.equal(
    sanitizeForEmail('Unlock at https://evil.example/x or mail help@evil.example.'),
    'Unlock at evil[dot]example/x or mail help[at]evil[dot]example.'
  );
  assert.equal(sanitizeForEmail('https:x:////evil.éxample'), 'evil[dot]éxample');
});

import { html, toSafeUrl } from '../utils/html';
import { sendMail, mailStatusCheck } from './mail';
import { renderMail } from './mail-templates';
import type { Env } from '../types';

test('shared HTML escapes nested content and links reject unsafe protocols', () => {
  assert.equal(html`<p>${'<>&"\''}${[html`<b>${'<x>'}</b>`]}</p>`.safeHtml, '<p>&lt;&gt;&amp;&quot;&#39;<b>&lt;x&gt;</b></p>');
  assert.throws(() => toSafeUrl(new URL('javascript:alert(1)')));
  assert.throws(() => toSafeUrl(new URL('http://external.io')));
  assert.equal(toSafeUrl(new URL('http://localhost:8787/admin')), 'http://localhost:8787/admin');
  const rendered = renderMail({ subject: 'one\r\ntwo'.repeat(30), paragraphs: ['<>&"\''], action: { label: '<click>', url: toSafeUrl(new URL('https://vault.io/?a=1&b=2')) } });
  assert.ok(rendered.subject.length <= 100);
  assert.doesNotMatch(rendered.subject, /[\r\n]/);
  assert.match(rendered.html, /href="https:\/\/vault.io\/\?a=1&amp;b=2"/);
  assert.match(rendered.text, /https:\/\/vault.io\/\?a=1&b=2/);
});

test('mail config and delivery failures do not expose addresses or exception text', async (t) => {
  t.mock.method(console, 'error', () => {});
  const warnings = t.mock.method(console, 'warn', () => {});
  assert.deepEqual(readMailConfig({ EMAIL: binding, EMAIL_FROM: 'bad' }), { kind: 'misconfigured' });
  assert.deepEqual(readMailConfig({ EMAIL: binding, EMAIL_FROM: 'a@x.io', EMAIL_FROM_NAME: 'bad\r\nname' }), { kind: 'misconfigured' });
  let sends = 0;
  const env = { EMAIL_FROM: 'a@x.io', EMAIL: { async send() { sends++; throw Object.assign(new Error('private@x.io'), { code: 'E_RECIPIENT_SUPPRESSED' }); } } } as Env;
  const model = { vaultOrigin: 'https://vault.io', email: 'private@x.io', token: 'secret-token' };
  for (const to of ['a@x.io, b@y.io', 'a@x.io\r\nbcc: b@y.io']) assert.equal((await sendMail(env, to, 'registerVerification', model)).kind, 'failed');
  assert.equal(sends, 0);
  const outcome = await sendMail(env, 'private@x.io', 'registerVerification', model);
  assert.equal(outcome.kind, 'failed');
  assert.deepEqual(mailStatusCheck(outcome), { ok: false, status: 502, message: 'Unable to send email', headers: {} });
  assert.doesNotMatch(JSON.stringify(warnings.mock.calls), /private@|secret-token/);
  assert.equal(sanitizeForEmail('x\r\ny\u202Ez\u2028 end'), 'x y z end');
});
