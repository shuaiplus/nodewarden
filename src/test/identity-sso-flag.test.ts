import assert from 'node:assert/strict';
import test from 'node:test';

import { hashPassword } from '../services/auth-password';
import { PolicyType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { verifyJWT } from '../utils/jwt';
import { authedFetch, createTestEnv, seedUser, captureEmail, drainWaitUntil, MAILABLE_DOMAIN } from './support/env';
import * as userRepo from '../services/storage-user-repo';

const { createOwnedOrganization } = await import('../handlers/organizations');

const SSO_CONFIG = {
  SSO_ENABLED: '1',
  SSO_AUTHORITY: 'https://idp.example.test',
  SSO_CLIENT_ID: 'nodewarden',
};
const PASSWORD = 'client-derived-password-hash';
const TOKEN_PATH = '/identity/connect/token';

test('a client-sent sso flag cannot bypass an organization SSO policy', async () => {
  const env = await createTestEnv(SSO_CONFIG);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  const org = await createOwnedOrganization(env, user, { name: 'SSO org', key: '4.dGVzdA==' });
  await orgRepo.savePolicy(env.DB, {
    id: crypto.randomUUID(),
    orgId: org.id,
    type: PolicyType.RequireSso,
    enabled: true,
    data: {},
    updatedAt: new Date().toISOString(),
  });
  const credentials = { grant_type: 'password', username: user.email, password: PASSWORD };

  for (const body of [credentials, { ...credentials, sso: '1' }, new URLSearchParams({ ...credentials, sso: '1' })]) {
    const response = await authedFetch(env, { method: 'POST', path: TOKEN_PATH, body });
    assert.equal(response.status, 400);
    const result = (await response.json()) as Record<string, unknown>;
    assert.equal(result.error_description, 'SSO sign-in is required');
    assert.equal(result.access_token, undefined);
  }
});

test('a client-sent sso flag does not replace password verification', async () => {
  const env = await createTestEnv(SSO_CONFIG);
  const user = await seedUser(env, { masterPasswordHash: await hashPassword(PASSWORD) });
  for (const [password, expectedStatus] of [
    ['incorrect', 400],
    [PASSWORD, 200],
  ] as const) {
    const response = await authedFetch(env, {
      method: 'POST',
      path: TOKEN_PATH,
      body: new URLSearchParams({ grant_type: 'password', username: user.email, password, sso: '1' }),
    });
    assert.equal(response.status, expectedStatus);
  }
});

test('verified SSO signs in an SSO-only account with a server-hashed password and still requires 2FA', async (t) => {
  const capture = captureEmail();
  const env = await createTestEnv({ ...capture.overrides, ...SSO_CONFIG, SSO_ONLY: '1' });
  const user = await seedUser(env, {
    masterPasswordHash: await hashPassword(PASSWORD),
    email: `sso@${MAILABLE_DOMAIN}`,
    createdAt: '2020-01-01T00:00:00.000Z',
  });
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'test-idp' })).toString('base64url');
  const claims = Buffer.from(
    JSON.stringify({
      iss: SSO_CONFIG.SSO_AUTHORITY,
      aud: SSO_CONFIG.SSO_CLIENT_ID,
      sub: 'provider-user',
      email: user.email,
      email_verified: true,
      exp: Math.floor(Date.now() / 1000) + 300,
    }),
  ).toString('base64url');
  const signed = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keys.privateKey,
    new TextEncoder().encode(signed),
  );
  const idToken = `${signed}.${Buffer.from(signature).toString('base64url')}`;
  const jwk = { ...(await crypto.subtle.exportKey('jwk', keys.publicKey)), kid: 'test-idp' };
  t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    switch (request.url) {
      case `${SSO_CONFIG.SSO_AUTHORITY}/.well-known/openid-configuration`:
        return Response.json({
          token_endpoint: `${SSO_CONFIG.SSO_AUTHORITY}/token`,
          jwks_uri: `${SSO_CONFIG.SSO_AUTHORITY}/jwks`,
        });
      case `${SSO_CONFIG.SSO_AUTHORITY}/jwks`:
        return Response.json({ keys: [jwk] });
      case `${SSO_CONFIG.SSO_AUTHORITY}/token`:
        assert.equal(request.method, 'POST');
        return ['valid-code', 'valid-code-2fa'].includes(String((await request.formData()).get('code')))
          ? Response.json({ id_token: idToken })
          : new Response(null, { status: 400 });
      default:
        throw new Error(`Unexpected outbound fetch: ${request.url}`);
    }
  });

  const exchange = (code: string, factors: Record<string, string> = {}) =>
    authedFetch(env, {
      method: 'POST',
      path: TOKEN_PATH,
      body: new URLSearchParams({ grant_type: 'authorization_code', code, deviceIdentifier: 'sso-device', ...factors }),
    });
  const rejected = await exchange('invalid-code');
  assert.equal(rejected.status, 400);
  assert.equal(((await rejected.json()) as Record<string, unknown>).access_token, undefined);

  const accepted = await exchange('valid-code');
  assert.equal(accepted.status, 200);
  await drainWaitUntil();
  assert.equal(capture.sent.length, 1);
  assert.match(capture.sent[0].subject, /New device/);
  const result = (await accepted.json()) as { access_token: string };
  assert.equal((await verifyJWT(result.access_token, env.JWT_SECRET))?.sub, user.id);

  await userRepo.saveUser(env.DB, { ...user, totpSecret: 'JBSWY3DPEHPK3PXP' }, ['totpSecret']);
  const challenged = await exchange('valid-code-2fa');
  assert.equal(challenged.status, 400);
  const challenge = (await challenged.json()) as Record<string, unknown>;
  assert.deepEqual(challenge.TwoFactorProviders, ['0']);
  assert.equal(challenge.access_token, undefined);
  assert.equal((await exchange('valid-code-2fa', { twoFactorProvider: '0', twoFactorToken: 'invalid' })).status, 400);
  await drainWaitUntil();
  assert.equal(capture.sent.length, 2);
  assert.match(capture.sent[1].subject, /Unsuccessful/);
});

test('SSO rejects unsigned, HMAC, tampered, foreign-audience and expired id_tokens but tolerates clock skew and a missing kid', async (t) => {
  const env = await createTestEnv({ ...SSO_CONFIG, SSO_AUTHORITY: 'https://forged.idp.example.test', SSO_ONLY: '1' });
  const user = await seedUser(env, { email: `forged-sso@${MAILABLE_DOMAIN}` });
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = { ...(await crypto.subtle.exportKey('jwk', keys.publicKey)), kid: 'forged-idp' };
  const now = Math.floor(Date.now() / 1000);
  const encode = (part: object) => Buffer.from(JSON.stringify(part)).toString('base64url');
  const claims = (overrides: object = {}) =>
    encode({
      iss: env.SSO_AUTHORITY,
      aud: env.SSO_CLIENT_ID,
      sub: 'forged-user',
      email: user.email,
      email_verified: true,
      exp: now + 300,
      ...overrides,
    });
  const signEs256 = async (unsigned: string) =>
    `${unsigned}.${Buffer.from(
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(unsigned)),
    ).toString('base64url')}`;
  const es256Header = encode({ alg: 'ES256', kid: 'forged-idp' });
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(JSON.stringify(jwk)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const hmacUnsigned = `${encode({ alg: 'HS256', kid: 'forged-idp' })}.${claims()}`;
  const tokens: Record<string, string> = {
    unsigned: `${encode({ alg: 'none', kid: 'forged-idp' })}.${claims()}.`,
    hmac: `${hmacUnsigned}.${Buffer.from(await crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(hmacUnsigned))).toString('base64url')}`,
    tampered: `${(await signEs256(`${es256Header}.${claims()}`))
      .split('.')
      .with(1, claims({ sub: 'someone-else' }))
      .join('.')}`,
    audience: await signEs256(`${es256Header}.${claims({ aud: 'another-client' })}`),
    expired: await signEs256(`${es256Header}.${claims({ exp: now - 120 })}`),
    skewed: await signEs256(`${es256Header}.${claims({ exp: now - 30, iat: now + 30 })}`),
    // OIDC Core lets a provider with a single signing key omit kid.
    keyless: await signEs256(`${encode({ alg: 'ES256' })}.${claims()}`),
  };
  t.mock.method(globalThis, 'fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = new Request(input, init);
    if (request.url.endsWith('/.well-known/openid-configuration'))
      return Response.json({ token_endpoint: `${env.SSO_AUTHORITY}/token`, jwks_uri: `${env.SSO_AUTHORITY}/jwks` });
    if (request.url === `${env.SSO_AUTHORITY}/jwks`) return Response.json({ keys: [jwk] });
    return Response.json({ id_token: tokens[String((await request.formData()).get('code'))] });
  });
  const exchange = (code: string) =>
    authedFetch(env, {
      method: 'POST',
      path: TOKEN_PATH,
      body: new URLSearchParams({ grant_type: 'authorization_code', code, deviceIdentifier: 'forged-sso-device' }),
    });
  for (const code of ['unsigned', 'hmac', 'tampered', 'audience', 'expired']) {
    const response = await exchange(code);
    assert.equal(response.status, 400, code);
    assert.equal(((await response.json()) as Record<string, unknown>).access_token, undefined, code);
  }
  for (const code of ['skewed', 'keyless']) assert.equal((await exchange(code)).status, 200, code);
});
