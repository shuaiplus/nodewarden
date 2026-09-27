import assert from 'node:assert/strict';
import test from 'node:test';

import { authedFetch, createTestEnv } from './support/env';

test('malformed token requests answer the OAuth error each grant has always returned', async () => {
  const env = await createTestEnv();
  const cases: Array<[unknown, string, string]> = [
    [new URLSearchParams({ grant_type: 'implicit' }), 'unsupported_grant_type', 'Unsupported grant type'],
    [new URLSearchParams({ username: 'user@example.test' }), 'unsupported_grant_type', 'Unsupported grant type'],
    [
      new URLSearchParams({ grant_type: 'password', username: 'user@example.test' }),
      'invalid_request',
      'Email and password are required',
    ],
    [
      new URLSearchParams({ grant_type: 'client_credentials', client_id: 'user.1', scope: 'api' }),
      'invalid_request',
      'Parameter error',
    ],
    [
      new URLSearchParams({ grant_type: 'webauthn', token: '  ' }),
      'invalid_request',
      'Passkey token and deviceResponse are required',
    ],
    [null, 'invalid_request', 'Invalid request payload'],
    [['grant_type', 'password'], 'invalid_request', 'Invalid request payload'],
  ];
  for (const [body, error, description] of cases) {
    const response = await authedFetch(env, { method: 'POST', path: '/identity/connect/token', body });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      error,
      error_description: description,
      ErrorModel: { Message: description, Object: 'error' },
    });
  }

  const prelogin = await authedFetch(env, { method: 'POST', path: '/identity/accounts/prelogin', body: { email: '' } });
  assert.equal(prelogin.status, 400);
  assert.equal(((await prelogin.json()) as { message: string }).message, 'Email is required');
});
