import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../config/limits';
import { createTestEnv } from '../test/support/env';
import { RateLimitService } from './ratelimit';

test('each failed login counts once against its key until the key locks out', async () => {
  const limiter = new RateLimitService(await createTestEnv());
  const { loginMaxAttempts, loginLockoutMinutes } = LIMITS.rateLimit;
  for (let attempt = 1; attempt < loginMaxAttempts; attempt++) {
    assert.deepEqual(await limiter.recordFailedLogin('guessing-client'), { locked: false });
    assert.equal((await limiter.checkLoginAttempt('guessing-client')).remainingAttempts, loginMaxAttempts - attempt);
  }
  assert.deepEqual(await limiter.recordFailedLogin('guessing-client'), { locked: true, retryAfterSeconds: loginLockoutMinutes * 60 });
  assert.equal((await limiter.checkLoginAttempt('guessing-client')).allowed, false);
  assert.equal((await limiter.checkLoginAttempt('other-client')).allowed, true);
});
