import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import {
  base64UrlFromBuffer,
  buildCallbackUrl,
  buildCredentialData,
  decodeBase64Utf8,
  normalizePublicKeyOptions,
  parseConnectorRequest,
  resolveMobileCallbackUri,
} from '../webapp/public/webauthn-mobile-connector.js';

function encodeBase64Utf8(value) {
  return Buffer.from(value, 'utf8').toString('base64');
}

function v2Search(payload, extra = '') {
  return `?data=${encodeURIComponent(encodeBase64Utf8(JSON.stringify(payload)))}&parent=bitwarden%3A__webauthn-callback&v=2${extra}`;
}

const assertionOptions = {
  challenge: 'AQID-v8',
  rpId: 'pass.lvguangfa.cn',
  timeout: 60000,
  userVerification: 'preferred',
  allowCredentials: [{ id: 'BAUGBwg', type: 'public-key', transports: ['internal'] }],
};

test('parses the current Bitwarden iOS V2 connector payload', () => {
  const request = parseConnectorRequest(v2Search({
    btnReturnText: 'Return to app',
    btnText: 'Authenticate',
    callbackUri: 'bitwarden://webauthn-callback',
    data: JSON.stringify(assertionOptions),
    headerText: 'Verify your identity',
  }), 'pass.lvguangfa.cn');

  assert.equal(request.callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(request.headerText, 'Verify your identity');
  assert.equal(request.buttonText, 'Authenticate');
  assert.equal(request.returnButtonText, 'Return to app');
  assert.deepEqual(JSON.parse(request.webauthnJson), assertionOptions);
});

test('uses callbackUri only as a mobile signal and rejects callback injection', () => {
  const request = parseConnectorRequest(v2Search({
    callbackUri: 'https://attacker.example/capture',
    data: JSON.stringify(assertionOptions),
  }), 'pass.lvguangfa.cn');

  assert.equal(request.callbackUri, 'bitwarden://webauthn-callback');
});

test('supports current Android custom-scheme and app-link callbacks', () => {
  const payload = { mobile: true, data: JSON.stringify(assertionOptions) };
  const custom = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=bitwarden'));
  const appLink = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=https'), 'vault.bitwarden.eu');
  const selfHostedAppLink = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=https'), 'pass.lvguangfa.cn');

  assert.equal(custom.callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(appLink.callbackUri, 'https://bitwarden.eu/webauthn-callback');
  assert.equal(selfHostedAppLink.callbackUri, 'https://bitwarden.com/webauthn-callback');
});

test('supports legacy mobile markers without allowing arbitrary parent redirects', () => {
  const request = parseConnectorRequest(
    `?data=${encodeURIComponent(encodeBase64Utf8(JSON.stringify(assertionOptions)))}&v=1&client=mobile&parent=${encodeURIComponent('https://attacker.example')}`,
  );
  assert.equal(request.callbackUri, 'bitwarden://webauthn-callback');
});

test('requires a recognized mobile flow', () => {
  assert.equal(resolveMobileCallbackUri({ payload: {}, hostname: 'pass.lvguangfa.cn' }), null);
  assert.throws(
    () => parseConnectorRequest(v2Search({ data: JSON.stringify(assertionOptions) }).replace('&parent=bitwarden%3A__webauthn-callback', '')),
    /return target/i,
  );
});

test('decodes UTF-8 Base64 and normalizes WebAuthn binary fields without mutating input', () => {
  assert.equal(decodeBase64Utf8(encodeBase64Utf8('验证身份')), '验证身份');
  const original = structuredClone(assertionOptions);
  const normalized = normalizePublicKeyOptions(JSON.stringify(original));

  assert.deepEqual(Array.from(normalized.challenge), [1, 2, 3, 250, 255]);
  assert.deepEqual(Array.from(normalized.allowCredentials[0].id), [4, 5, 6, 7, 8]);
  assert.equal(original.challenge, assertionOptions.challenge);
  assert.equal(original.allowCredentials[0].id, assertionOptions.allowCredentials[0].id);
});

test('serializes credentials in the exact shape consumed by Bitwarden mobile', () => {
  const serialized = JSON.parse(buildCredentialData({
    id: 'credential-id',
    rawId: Uint8Array.from([1, 2, 255]).buffer,
    type: 'public-key',
    getClientExtensionResults: () => ({ appid: false }),
    response: {
      authenticatorData: Uint8Array.from([3, 4]).buffer,
      clientDataJSON: Uint8Array.from([5, 6]).buffer,
      signature: Uint8Array.from([7, 8]).buffer,
    },
  }));

  assert.deepEqual(serialized, {
    id: 'credential-id',
    rawId: 'AQL_',
    type: 'public-key',
    extensions: { appid: false },
    response: {
      authenticatorData: 'AwQ',
      clientDataJson: 'BQY',
      signature: 'Bwg',
    },
  });
  assert.equal(base64UrlFromBuffer(Uint8Array.from([251, 255])), '-_8');
});

test('encodes result and error callbacks safely', () => {
  assert.equal(
    buildCallbackUrl('bitwarden://webauthn-callback', 'data', '{"id":"a+b"}'),
    'bitwarden://webauthn-callback?data=%7B%22id%22%3A%22a%2Bb%22%7D',
  );
  assert.equal(
    buildCallbackUrl('bitwarden://webauthn-callback?source=nodewarden', 'error', 'Not allowed'),
    'bitwarden://webauthn-callback?source=nodewarden&error=Not%20allowed',
  );
});

test('HTML provides the branded mobile UI and loads the connector module', async () => {
  const html = await readFile(new URL('../webapp/public/webauthn-mobile-connector.html', import.meta.url), 'utf8');
  assert.match(html, /id="webauthn-header"/);
  assert.match(html, /id="webauthn-button"/);
  assert.match(html, /src="\/nodewarden-logo\.svg"/);
  assert.match(html, /src="\/webauthn-mobile-connector\.js"/);
  assert.match(html, /prefers-color-scheme: dark/);
  assert.match(html, /default-src 'none'/);
});
