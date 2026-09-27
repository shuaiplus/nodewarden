import assert from 'node:assert/strict';
import { test } from 'node:test';

import { readAuthRequestDeviceInfo } from './device';

const headers = { 'X-Device-Identifier': 'header-device', 'X-Device-Name': 'Header name', 'Device-Type': '9' };

test('device info takes body fields over headers, clips them and falls back to defaults', () => {
  const request = new Request('https://vault.example.test', { headers });
  assert.deepEqual(
    readAuthRequestDeviceInfo(
      { deviceIdentifier: ` ${'d'.repeat(200)} `, device_name: 'Body name', deviceType: 0 },
      request,
    ),
    {
      deviceIdentifier: 'd'.repeat(128),
      deviceName: 'Body name',
      deviceType: 0,
    },
  );
  assert.deepEqual(readAuthRequestDeviceInfo({ deviceIdentifier: '', deviceType: '' }, request), {
    deviceIdentifier: 'header-device',
    deviceName: 'Header name',
    deviceType: 9,
  });
  assert.deepEqual(
    readAuthRequestDeviceInfo(
      { deviceIdentifier: '   ', deviceName: 42, deviceType: 'phone' },
      new Request('https://vault.example.test'),
    ),
    {
      deviceIdentifier: null,
      deviceName: 'Unknown device',
      deviceType: 14,
    },
  );
});
