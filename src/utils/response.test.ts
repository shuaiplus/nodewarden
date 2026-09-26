import assert from 'node:assert/strict';
import { test } from 'node:test';

import { errorResponse } from './response';

// Official clients (web-v2026.9.0 error.response.ts) read top-level Message and
// ValidationErrors for every non-identity call; the CLI prints the raw JSON when
// both are missing. Upstream ErrorResponseModel names the shape.
test('error body carries the upstream top-level message next to the legacy fields', async () => {
  const message = 'Secret not found.';
  const body = await errorResponse(message, 404).json();
  assert.deepEqual(body, {
    message,
    validationErrors: null,
    object: 'error',
    error: message,
    error_description: message,
    ErrorModel: { Message: message, Object: 'error' },
  });
});

test('error body carries the validation errors map when one is passed', async () => {
  const validationErrors = { ProjectIds: ['Only one project assignment is supported.'] };
  const response = errorResponse('The model state is invalid.', 400, {}, validationErrors);
  assert.equal(response.status, 400);
  const body = await response.json() as { message: string; validationErrors: unknown };
  assert.equal(body.message, 'The model state is invalid.');
  assert.deepEqual(body.validationErrors, validationErrors);
});
