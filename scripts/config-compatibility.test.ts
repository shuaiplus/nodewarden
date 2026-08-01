import assert from 'node:assert/strict';
import test from 'node:test';

import { buildConfigResponse } from '../src/config-response';

test('config enables the official Bitwarden desktop settings dialog', () => {
  const body = buildConfigResponse('https://vault.example.test');

  assert.equal(body.featureStates['desktop-ui-settings-dialog'], true);
  assert.equal(body.environment.vault, 'https://vault.example.test');
  assert.equal(body.object, 'config');
});
