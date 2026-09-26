import assert from 'node:assert/strict';
import test from 'node:test';

import { ensureStorageSchema } from '../src/db/migrate';
import type { Env } from '../src/types';
import { authedFetch, createTestEnv } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedSmOrg } from './support/sm';

// The webapp's token button posted the raw 64-byte org key (encryption + MAC halves), base64-encoded.
const ORG_KEY_BYTES = 64;
const PLAINTEXT_ORG_KEY = Buffer.alloc(ORG_KEY_BYTES, 1).toString('base64');

interface IssuedToken {
  id: string;
  clientId: string;
  clientSecret: string;
}

// A token of a new machine account, created the way the webapp's token button did.
async function issueTokenWithOrgKey(): Promise<{ env: Env; orgId: string; token: IssuedToken }> {
  const env = await createTestEnv();
  const { orgId, owner } = await seedSmOrg(env);
  const account = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/service-accounts`, { name: ENCRYPTED_FIELD });
  const token = await postJson<IssuedToken>(env, owner, `/api/service-accounts/${account.id}/access-tokens`, {
    name: ENCRYPTED_FIELD,
    wrappedOrgKey: PLAINTEXT_ORG_KEY,
  });
  return { env, orgId, token };
}

function storedOrgKey(env: Env, tokenId: string): Promise<unknown> {
  return env.DB.prepare('SELECT wrapped_org_key FROM sm_access_tokens WHERE id = ?').bind(tokenId).first('wrapped_org_key');
}

// Upstream never holds an org key: the token response carries only `encrypted_payload`, and
// SecretsSyncResponseModel only `hasChanges` and `secrets`.
test('a token created with wrappedOrgKey stores NULL and no response carries the key', async () => {
  const { env, orgId, token } = await issueTokenWithOrgKey();
  assert.equal(await storedOrgKey(env, token.id), null);
  assert.equal('wrappedOrgKey' in token, false);

  const identity = await authedFetch(env, {
    method: 'POST',
    path: '/identity/connect/token',
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api.secrets',
      client_id: token.clientId,
      client_secret: token.clientSecret,
    }),
  });
  assert.equal(identity.status, 200);
  assert.equal('wrappedOrgKey' in (await identity.json() as object), false);

  const synced = await authedFetch(env, {
    path: `/api/organizations/${orgId}/secrets/sync`,
    headers: { Authorization: `Bearer ${token.clientId}:${token.clientSecret}` },
  });
  assert.equal(synced.status, 200);
  assert.equal('wrappedOrgKey' in (await synced.json() as object), false);
});

// Earlier builds stored the posted key, so the schema step clears what is already in D1.
test('the schema step scrubs a stored org key and replays cleanly', async () => {
  const { env, token } = await issueTokenWithOrgKey();
  await env.DB.prepare('UPDATE sm_access_tokens SET wrapped_org_key = ? WHERE id = ?').bind(PLAINTEXT_ORG_KEY, token.id).run();

  await ensureStorageSchema(env.DB);
  assert.equal(await storedOrgKey(env, token.id), null);
  await ensureStorageSchema(env.DB);
  assert.equal(await storedOrgKey(env, token.id), null);
});
