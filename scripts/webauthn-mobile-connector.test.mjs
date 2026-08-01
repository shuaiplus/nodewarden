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
  rpId: 'vault.example.com',
  timeout: 60000,
  userVerification: 'preferred',
  allowCredentials: [{ id: 'BAUGBwg', type: 'public-key', transports: ['internal'] }],
};

test('parses the current Bitwarden Android V2 connector payload', () => {
  const request = parseConnectorRequest(v2Search({
    btnReturnText: 'Return to app', btnText: 'Authenticate', data: JSON.stringify(assertionOptions),
    headerText: 'Verify your identity', mobile: true,
  }, '&client=mobile&deeplinkScheme=bitwarden'), 'vault.example.com');
  assert.equal(request.callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(request.headerText, 'Verify your identity');
  assert.equal(request.buttonText, 'Authenticate');
  assert.equal(request.returnButtonText, 'Return to app');
  assert.deepEqual(JSON.parse(request.webauthnJson), assertionOptions);
});

test('uses callbackUri only as a signal and never as the redirect target', () => {
  const trustedLooking = parseConnectorRequest(v2Search({
    callbackUri: 'https://bitwarden.eu/webauthn-callback', data: assertionOptions,
  }).replace('&parent=bitwarden%3A__webauthn-callback', ''));
  const attacker = parseConnectorRequest(v2Search({
    callbackUri: 'https://attacker.example/capture', data: assertionOptions,
  }).replace('&parent=bitwarden%3A__webauthn-callback', ''));
  assert.equal(trustedLooking.callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(attacker.callbackUri, 'bitwarden://webauthn-callback');
});

test('treats any non-HTTPS deeplinkScheme as the fixed Bitwarden custom scheme', () => {
  const request = parseConnectorRequest(v2Search({ mobile: true, data: assertionOptions }, '&deeplinkScheme=untrusted'));
  assert.equal(request.callbackUri, 'bitwarden://webauthn-callback');
});

test('supports Android custom-scheme and official HTTPS App Link callbacks', () => {
  const payload = { mobile: true, data: assertionOptions };
  const custom = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=bitwarden'));
  const eu = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=https'), 'vault.bitwarden.eu');
  const selfHosted = parseConnectorRequest(v2Search(payload, '&client=mobile&deeplinkScheme=https'), 'vault.example.com');
  assert.equal(custom.callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(eu.callbackUri, 'https://bitwarden.eu/webauthn-callback');
  assert.equal(selfHosted.callbackUri, 'https://bitwarden.com/webauthn-callback');
});

test('supports V1 mobile requests and requires a recognized mobile signal', () => {
  const encoded = encodeURIComponent(encodeBase64Utf8(JSON.stringify(assertionOptions)));
  assert.equal(parseConnectorRequest(`?data=${encoded}&v=1&client=mobile`).callbackUri, 'bitwarden://webauthn-callback');
  assert.equal(resolveMobileCallbackUri({ payload: {}, hostname: 'vault.example.com' }), null);
  assert.throws(() => parseConnectorRequest(`?data=${encoded}&v=1`), /return target/i);
});

test('decodes UTF-8 and normalizes WebAuthn binary fields without mutation', () => {
  assert.equal(decodeBase64Utf8(encodeBase64Utf8('验证身份')), '验证身份');
  const original = structuredClone(assertionOptions);
  const normalized = normalizePublicKeyOptions(original);
  assert.deepEqual(Array.from(normalized.challenge), [1, 2, 3, 250, 255]);
  assert.deepEqual(Array.from(normalized.allowCredentials[0].id), [4, 5, 6, 7, 8]);
  assert.deepEqual(original, assertionOptions);
});

test('serializes the exact assertion shape emitted by Bitwarden common-webauthn', () => {
  const serialized = JSON.parse(buildCredentialData({
    id: 'credential-id', rawId: Uint8Array.from([1, 2, 255]).buffer, type: 'public-key',
    getClientExtensionResults: () => ({ appid: false }),
    response: {
      authenticatorData: Uint8Array.from([3, 4]).buffer,
      clientDataJSON: Uint8Array.from([5, 6]).buffer,
      signature: Uint8Array.from([7, 8]).buffer,
      userHandle: Uint8Array.from([9, 10]).buffer,
    },
  }));
  assert.deepEqual(serialized, {
    id: 'credential-id',
    rawId: 'AQL_',
    type: 'public-key',
    extensions: { appid: false },
    response: { authenticatorData: 'AwQ', clientDataJson: 'BQY', signature: 'Bwg' },
  });
  assert.equal(base64UrlFromBuffer(Uint8Array.from([251, 255])), '-_8');
});

test('encodes success and error callbacks safely', () => {
  assert.equal(buildCallbackUrl('bitwarden://webauthn-callback', 'data', '{"id":"a+b"}'), 'bitwarden://webauthn-callback?data=%7B%22id%22%3A%22a%2Bb%22%7D');
  assert.equal(buildCallbackUrl('bitwarden://webauthn-callback?source=nodewarden', 'error', 'Not allowed'), 'bitwarden://webauthn-callback?source=nodewarden&error=Not%20allowed');
});

test('HTML matches the fallback connector visual structure', async () => {
  const html = await readFile(new URL('../webapp/public/webauthn-mobile-connector.html', import.meta.url), 'utf8');
  assert.match(html, /id="webauthn-header"/);
  assert.match(html, /id="webauthn-button"/);
  assert.match(html, /class="connector-card"/);
  assert.match(html, /class="brand"/);
  assert.match(html, /class="form"/);
  assert.match(html, /class="msg"/);
  assert.match(html, /src="\/nodewarden-logo\.svg"/);
  assert.match(html, /src="\/webauthn-mobile-connector\.js"/);
  assert.match(html, /default-src 'none'/);
});

test('runtime uses Bitwarden-compatible replacement navigation', async () => {
  const source = await readFile(new URL('../webapp/public/webauthn-mobile-connector.js', import.meta.url), 'utf8');
  assert.match(source, /window\.location\.replace\(uri\)/);
  assert.doesNotMatch(source, /location\.assign/);
  assert.doesNotMatch(source, /safeCallbackFromPayload/);
});

test('Service Worker keeps connector navigations out of the SPA shell', async () => {
  const config = await readFile(new URL('../webapp/vite.config.ts', import.meta.url), 'utf8');
  assert.match(config, /url\.pathname\.endsWith\('-connector\.html'\)/);
  assert.match(config, /connectorNavigation\(request\)/);
  assert.match(config, /WebAuthn connector is unavailable while offline/);
});
