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
    { kind: 'enabled', binding, sendsPerHour: 100, newDeviceNotices: true, newDeviceVerification: false, from: { email: 'noreply@stevefan1999.tech', name: 'NW' } }
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
import { MAIL_TEMPLATES, renderMail, type MailContent, type TemplateName, type TemplateModel } from './mail-templates';
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
  const outcome = await sendMail(env, 'private@x.io', 'adminSignIn', { url: toSafeUrl(new URL('https://vault.io')) });
  assert.equal(outcome.kind, 'failed');
  assert.deepEqual(mailStatusCheck(outcome), { ok: false, status: 502, message: 'Unable to send email', headers: {} });
  assert.doesNotMatch(JSON.stringify(warnings.mock.calls), /private@|secret-token/);
  assert.equal(sanitizeForEmail('x\r\ny\u202Ez\u2028 end'), 'x y z end');
});

test('emergency and organization mail templates sanitize untrusted text and preserve encoded invitation parameters', () => {
  const unsafe = '<>&"\' @ https://bad.domain\r\n\u202E';
  const safe = sanitizeForEmail(unsafe);
  const content: MailContent[] = [
    MAIL_TEMPLATES.emergencyAccessInvite.render({ vaultOrigin: 'https://vault.io', id: 'id', grantorName: unsafe, grantorEmail: 'a@x.io', token: 'private-token' }),
    MAIL_TEMPLATES.organizationInvite.render({ vaultOrigin: 'https://vault.io', organizationId: 'o', organizationUserId: 'm', organizationName: unsafe, email: 'a+tag@x.io', token: 'private-token', hasExistingUser: false, inviterEmail: unsafe, expiresAt: '2030-01-01T00:00:00Z' }),
    ...[
      MAIL_TEMPLATES.emergencyAccessAccepted, MAIL_TEMPLATES.emergencyAccessConfirmed,
      MAIL_TEMPLATES.emergencyAccessRecoveryInitiated, MAIL_TEMPLATES.emergencyAccessApproved,
      MAIL_TEMPLATES.emergencyAccessRejected, MAIL_TEMPLATES.emergencyAccessTimedOut, MAIL_TEMPLATES.emergencyAccessReminder,
    ].map((template) => template.render({ name: unsafe, accessType: unsafe, daysLeft: 1 })),
    MAIL_TEMPLATES.organizationUserAccepted.render({ organizationName: unsafe, memberName: unsafe }),
    MAIL_TEMPLATES.organizationUserConfirmed.render({ organizationName: unsafe, vaultOrigin: 'https://vault.io' }),
    MAIL_TEMPLATES.welcome.render({ name: unsafe, vaultOrigin: 'https://vault.io' }),
  ];
  for (const item of content) {
    const rendered = renderMail(item);
    assert.ok(rendered.subject.length <= 100);
    assert.doesNotMatch(rendered.subject, /private-token|[\r\n\u202E]/);
    assert.ok(item.paragraphs.join(' ').includes(safe));
    assert.doesNotMatch(item.paragraphs.join(' '), /https:\/\/|@|[\r\n\u202E]/);
    assert.match(rendered.html, /&lt;&gt;&amp;&quot;&#39;/);
    if (item.action) {
      assert.equal(new URL(item.action.url).origin, 'https://vault.io');
      assert.match(rendered.html, /href="https:\/\/vault.io/);
    }
  }
  const inviteUrl = content[1].action!.url;
  const parameters = new URLSearchParams(inviteUrl.slice(inviteUrl.indexOf('?') + 1));
  assert.equal(parameters.get('organizationName'), unsafe);
  assert.equal(parameters.get('email'), 'a+tag@x.io');
  assert.equal(parameters.get('token'), 'private-token');
});

test('every mail template escapes and sanitizes untrusted text without tokens in subjects', () => {
  const hostile = '<>&"\'\r\n\u202E https://evil.io help@evil.io';
  const vaultOrigin = 'https://vault.io';
  const token = 'UNIQUE-SECRET-TOKEN';
  const models = {
    emailChangeAlreadyExists: {}, emailChanged: { utc: hostile, ip: hostile },
    verifyDelete: { url: toSafeUrl(new URL(`${vaultOrigin}/#/verify-recover-delete?token=${token}`)) },
    verificationCode: { code: '123456', reason: 'two-factor-setup' },
    signInCode: { code: '123456', reason: 'two-factor', ip: hostile, deviceTypeName: hostile, utc: hostile },
    passwordHint: { hint: hostile }, noPasswordHint: {},
    twoFactorRecovered: { time: hostile, ip: hostile },
    failedTwoFactor: { provider: 8, time: hostile, ip: hostile },
    newDeviceLogin: { device: hostile, time: hostile, ip: hostile },
    adminSignIn: { url: toSafeUrl(new URL(`${vaultOrigin}/admin/login/confirm?token=${token}`)) },
    registerVerification: { vaultOrigin, email: 'mail@x.io', token },
    organizationInvite: { vaultOrigin, organizationId: 'org', organizationUserId: 'member', organizationName: hostile, email: 'mail@x.io', token, hasExistingUser: false, inviterEmail: hostile, expiresAt: '2026-10-01T00:00:00.000Z' },
    emergencyAccessInvite: { vaultOrigin, id: 'id', grantorName: hostile, grantorEmail: 'mail@x.io', token },
    emergencyAccessAccepted: { name: hostile }, emergencyAccessConfirmed: { name: hostile },
    emergencyAccessRecoveryInitiated: { name: hostile, accessType: hostile, daysLeft: 7 },
    emergencyAccessApproved: { name: hostile }, emergencyAccessRejected: { name: hostile }, emergencyAccessTimedOut: { name: hostile }, emergencyAccessReminder: { name: hostile, daysLeft: 1 },
    organizationUserAccepted: { organizationName: hostile, memberName: hostile },
    organizationUserConfirmed: { organizationName: hostile, vaultOrigin }, welcome: { name: hostile, vaultOrigin },
  } satisfies { [N in TemplateName]: TemplateModel<N> };
  for (const name of Object.keys(models) as TemplateName[]) {
    const render = MAIL_TEMPLATES[name].render as (model: TemplateModel<TemplateName>) => import('./mail-templates').MailContent;
    const content = render(models[name]);
    const rendered = renderMail(content);
    assert.ok(rendered.subject.length <= 100, name);
    assert.ok(!rendered.subject.includes(token), name);
    assert.doesNotMatch(rendered.subject, /[\r\n\u202E]/, name);
    assert.doesNotMatch(content.paragraphs.join(''), /[\r\n\u202E]|https:\/\/evil.io|help@evil.io/, name);
    assert.doesNotMatch(rendered.html, /<>&"'/, name);
    content.paragraphs.forEach((paragraph) => assert.ok(rendered.text.includes(paragraph), name));
    if (content.action) { assert.equal(new URL(content.action.url).origin, vaultOrigin); assert.ok(rendered.text.includes(content.action.url), name); }
  }
});

test('administrator two-factor recovery notice omits IP and administrator identity', async () => {
  const { MAIL_TEMPLATES, renderMail } = await import('./mail-templates');
  const rendered = renderMail(MAIL_TEMPLATES.twoFactorRecovered.render({ by: 'administrator' }));
  assert.match(rendered.text, /An administrator removed two-step login/);
  assert.doesNotMatch(rendered.text, /IP address|recovery code|@/i);
  assert.doesNotMatch(rendered.html, /IP address|recovery code|@/i);
});

test('sign-in codes stay out of subjects and new-device notices suggest two-step login', async () => {
  const { MAIL_TEMPLATES, renderMail } = await import('./mail-templates');
  for (const reason of ['two-factor', 'new-device'] as const) {
    const rendered = renderMail(MAIL_TEMPLATES.signInCode.render({ code: '000123', reason, ip: '203.0.113.1', deviceTypeName: 'Browser', utc: '2026-09-27T00:00:00Z' }));
    assert.ok(rendered.text.includes('000123'));
    assert.ok(!rendered.subject.includes('000123'));
    assert.equal(rendered.text.includes('Consider enabling two-step login'), reason === 'new-device');
  }
});
