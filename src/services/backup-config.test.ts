import assert from 'node:assert/strict';
import { test } from 'node:test';

import { type WebDavBackupDestination, getDefaultBackupSettings, parseBackupSettings, serializeBackupSettings } from './backup-config';

const webdav: WebDavBackupDestination = {
  baseUrl: 'https://dav.example.com/nodewarden',
  username: 'backup',
  password: 'secret',
  remotePath: 'vault',
};

test('a saved per-destination schedule round-trips through parseBackupSettings unchanged', () => {
  const settings = getDefaultBackupSettings('UTC');
  settings.destinations[0].destination = webdav;
  settings.destinations[0].schedule = { ...settings.destinations[0].schedule, enabled: true, intervalHours: 12 };
  assert.deepEqual(parseBackupSettings(serializeBackupSettings(settings)), settings);
});

test('rows without per-destination schedules come back as the defaults for the admin to re-save', () => {
  const legacyRow = JSON.stringify({ frequency: 'weekly', enabled: true, destinationType: 'webdav', destination: webdav });
  const unscheduledRow = JSON.stringify({ enabled: true, frequency: 'daily', destinations: [{ id: 'd1', type: 'webdav', destination: webdav }] });
  for (const raw of [legacyRow, unscheduledRow]) {
    const { destinations } = parseBackupSettings(raw);
    assert.equal(destinations.length, 1);
    assert.deepEqual(destinations[0].schedule, getDefaultBackupSettings('UTC').destinations[0].schedule);
    assert.equal((destinations[0].destination as WebDavBackupDestination).baseUrl, '');
  }
});
