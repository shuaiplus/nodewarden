import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../src/config/limits';
import { ensureStorageSchema } from '../src/db/migrate';
import { hashApiKey } from '../src/utils/api-key';
import { verifyHs256Jwt } from '../src/utils/jwt';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg, smLogin, TOKEN_FIELDS } from './support/sm';

interface IssuedToken {
  id: string;
  name: string;
  clientSecret: string;
  expireAt: string | null;
  creationDate: string;
  revisionDate: string;
  object: string;
}

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const tokenPath = `/api/service-accounts/${account.id}/access-tokens`;
  const token = await postJson<IssuedToken>(env, owner, tokenPath, TOKEN_FIELDS);
  return { env, orgId, owner, account, tokenPath, token };
}

test('machine token issuance and identity exchange match upstream fields, signed claims, and ignore license limits', async () => {
  const { env, orgId, owner, account, tokenPath, token } = await setup();
  assert.deepEqual(Object.keys(token).sort(), ['id', 'name', 'clientSecret', 'expireAt', 'creationDate', 'revisionDate', 'object'].sort());
  assert.match(token.clientSecret, /^[A-Za-z0-9]{30}$/);
  assert.equal(token.object, 'accessTokenCreation');
  assert.equal(token.expireAt, null);
  assert.equal(token.revisionDate, token.creationDate);
  const stored = await env.DB.prepare('SELECT client_secret_hash, encrypted_payload, "key", wrapped_org_key FROM sm_access_tokens WHERE id = ?').bind(token.id).first();
  assert.deepEqual(stored, { client_secret_hash: await hashApiKey(token.clientSecret), encrypted_payload: TOKEN_FIELDS.encryptedPayload, key: TOKEN_FIELDS.key, wrapped_org_key: null });
  const list = await authedFetch(env, { path: tokenPath, userId: owner.id });
  assert.equal(list.status, 200);
  assert.deepEqual(await list.json(), { data: [{ id: token.id, name: token.name, scopes: ['api.secrets'], expireAt: null, creationDate: token.creationDate, revisionDate: token.creationDate, object: 'accessToken' }], object: 'list', continuationToken: null });
  const form = new FormData();
  form.set('license', new Blob([JSON.stringify({ useSecretsManager: false, smSeats: 0, smServiceAccounts: 0 })]), 'license.json');
  assert.equal((await authedFetch(env, { userId: owner.id, path: `/api/organizations/licenses/self-hosted/${orgId}`, method: 'POST', body: form })).status, 200);
  const login = await smLogin(env, token.id, token.clientSecret);
  assert.equal(login.status, 200);
  const body = await login.json() as any;
  assert.deepEqual(Object.keys(body).sort(), ['access_token', 'expires_in', 'token_type', 'scope', 'encrypted_payload'].sort());
  assert.equal(body.expires_in, 3600);
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.scope, 'api.secrets');
  assert.equal(body.encrypted_payload, TOKEN_FIELDS.encryptedPayload);
  const claims = await verifyHs256Jwt(body.access_token, env.JWT_SECRET);
  assert.ok(claims);
  assert.deepEqual(Object.keys(claims).sort(), ['iss', 'iat', 'nbf', 'exp', 'sub', 'type', 'organization', 'client_id', 'scope'].sort());
  assert.deepEqual({ iss: claims.iss, sub: claims.sub, type: claims.type, organization: claims.organization, client_id: claims.client_id, scope: claims.scope }, { iss: 'nodewarden', sub: account.id, type: 'ServiceAccount', organization: orgId, client_id: token.id, scope: ['api.secrets'] });
  assert.equal(claims.nbf, claims.iat);
  assert.equal(Number(claims.exp) - Number(claims.iat), 3600);
  const guidOnly = await authedFetch(env, { path: '/identity/connect/token', method: 'POST', body: new URLSearchParams({ grant_type: 'client_credentials', client_id: token.id, client_secret: token.clientSecret }) });
  assert.equal(guidOnly.status, 200);
  assert.equal((await guidOnly.json() as any).encrypted_payload, TOKEN_FIELDS.encryptedPayload);
  const expireAt = new Date(Date.now() + 60_000).toISOString();
  const expiring = await postJson<IssuedToken>(env, owner, tokenPath, { ...TOKEN_FIELDS, expireAt });
  assert.equal(expiring.expireAt, expireAt);
  assert.equal((await smLogin(env, expiring.id, expiring.clientSecret)).status, 200);
});

test('machine token input and failed exchanges return the expected request or client error', async () => {
  const { env, owner, tokenPath, token } = await setup();
  for (const body of [null, { ...TOKEN_FIELDS, name: 'plaintext' }, { ...TOKEN_FIELDS, encryptedPayload: 'plaintext' }, { ...TOKEN_FIELDS, key: undefined }, { ...TOKEN_FIELDS, expireAt: 'not-a-date' }, { ...TOKEN_FIELDS, expireAt: '2020-01-01T00:00:00.000Z' }]) {
    const response = await authedFetch(env, { userId: owner.id, path: tokenPath, method: 'POST', body });
    assert.equal(response.status, 400);
  }
  for (const fields of [
    { scope: 'api.secrets', client_secret: token.clientSecret },
    { scope: 'api.secrets', client_id: token.id },
    { client_id: token.id },
    {},
  ]) {
    const response = await authedFetch(env, { path: '/identity/connect/token', method: 'POST', body: new URLSearchParams({ grant_type: 'client_credentials', ...fields }) });
    assert.equal(response.status, 400);
    assert.equal((await response.json() as any).error, 'invalid_request');
  }
  for (const [id, secret] of [[token.id, 'wrong'], [crypto.randomUUID(), token.clientSecret]]) {
    const response = await smLogin(env, id, secret);
    assert.equal(response.status, 400);
    assert.equal((await response.json() as any).error, 'invalid_client');
  }
  await env.DB.prepare('UPDATE sm_access_tokens SET expire_at = ? WHERE id = ?').bind('2020-01-01T00:00:00.000Z', token.id).run();
  let response = await smLogin(env, token.id, token.clientSecret);
  assert.equal(response.status, 400);
  assert.equal((await response.json() as any).error, 'invalid_client');
  await env.DB.prepare('DELETE FROM sm_access_tokens WHERE id = ?').bind(token.id).run();
  response = await smLogin(env, token.id, token.clientSecret);
  assert.equal(response.status, 400);
  assert.equal((await response.json() as any).error, 'invalid_client');
});

test('failed machine credentials lock out only their source IP', async () => {
  const { env, token } = await setup();
  const loginFrom = (ip: string, secret: string) => authedFetch(env, { path: '/identity/connect/token', method: 'POST', headers: { 'CF-Connecting-IP': ip }, body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'api.secrets', client_id: token.id, client_secret: secret }) });
  for (let attempt = 0; attempt < LIMITS.rateLimit.loginMaxAttempts; attempt++) {
    assert.equal((await loginFrom('203.0.113.20', 'wrong')).status, 400);
  }
  assert.equal((await loginFrom('203.0.113.20', token.clientSecret)).status, 429);
  assert.equal((await loginFrom('203.0.113.21', token.clientSecret)).status, 200);
});

test('schema replay purges legacy tokens and preserves every encrypted-payload token', async () => {
  const { env, account, token } = await setup();
  const legacyId = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO sm_access_tokens (id, service_account_id, name, client_secret_hash, created_at) VALUES (?, ?, ?, ?, ?)').bind(legacyId, account.id, ENCRYPTED_FIELD, await hashApiKey('old-secret'), token.creationDate).run();
  for (let replay = 0; replay < 2; replay++) {
    await ensureStorageSchema(env.DB);
    assert.equal(await env.DB.prepare('SELECT id FROM sm_access_tokens WHERE id = ?').bind(legacyId).first(), null);
    assert.deepEqual(await env.DB.prepare('SELECT encrypted_payload, "key" FROM sm_access_tokens WHERE id = ?').bind(token.id).first(), { encrypted_payload: TOKEN_FIELDS.encryptedPayload, key: TOKEN_FIELDS.key });
  }
  assert.equal((await smLogin(env, token.id, token.clientSecret)).status, 200);
});
