import assert from 'node:assert/strict';
import test from 'node:test';

import { buildConfigResponse } from '../config-response';

test('config enables the official Bitwarden desktop settings dialog', () => {
  const body = buildConfigResponse('https://vault.example.test');

  assert.equal(body.featureStates['desktop-ui-settings-dialog'], true);
  assert.equal(body.environment.vault, 'https://vault.example.test');
  assert.equal(body.environment.events, 'https://vault.example.test/events');
  assert.equal(body.object, 'config');
});
