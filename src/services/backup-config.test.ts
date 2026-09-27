import assert from 'node:assert/strict';
import { test } from 'node:test';

import {
  REDACTED_BACKUP_SECRET,
  type WebDavBackupDestination,
  getDefaultBackupSettings,
  normalizeBackupEndpointUrl,
  normalizeBackupSettingsInput,
  parseBackupSettings,
  serializeBackupSettings,
} from './backup-config';

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
  const legacyRow = JSON.stringify({
    frequency: 'weekly',
    enabled: true,
    destinationType: 'webdav',
    destination: webdav,
  });
  const unscheduledRow = JSON.stringify({
    enabled: true,
    frequency: 'daily',
    destinations: [{ id: 'd1', type: 'webdav', destination: webdav }],
  });
  for (const raw of [legacyRow, unscheduledRow]) {
    const { destinations } = parseBackupSettings(raw);
    assert.equal(destinations.length, 1);
    assert.deepEqual(destinations[0].schedule, getDefaultBackupSettings('UTC').destinations[0].schedule);
    assert.equal((destinations[0].destination as WebDavBackupDestination).baseUrl, '');
  }
});

test('a save keeps the stored secret behind a redacted value and rejects unsafe or incomplete scheduled destinations', () => {
  const previous = getDefaultBackupSettings('UTC');
  previous.destinations[0].destination = webdav;
  const [stored] = previous.destinations;
  const saved = normalizeBackupSettingsInput(
    [{ ...stored, destination: { ...webdav, password: REDACTED_BACKUP_SECRET } }],
    previous,
  );
  assert.equal(saved.success && (saved.data.destinations[0].destination as WebDavBackupDestination).password, 'secret');

  const scheduled = { ...stored, schedule: { ...stored.schedule, enabled: true } };
  const cases: Array<[unknown, string, string]> = [
    [
      { ...scheduled, destination: { ...webdav, baseUrl: 'http://127.0.0.1' } },
      'destinations.0.destination.baseUrl',
      'WebDAV server URL host is not allowed',
    ],
    [
      { ...scheduled, id: 'new', destination: { baseUrl: webdav.baseUrl } },
      'destinations.0.destination.username',
      'WebDAV username is required',
    ],
    [
      { ...scheduled, schedule: { retentionCount: 1001 } },
      'destinations.0.schedule.retentionCount',
      'Backup retention count must be between 1 and 1000',
    ],
  ];
  for (const [destination, path, message] of cases) {
    const [issue] = normalizeBackupSettingsInput([destination], previous).error?.issues ?? [];
    assert.deepEqual([issue?.path.join('.'), issue?.message], [path, message]);
  }
});

test('backup endpoints refuse private, reserved and mapped addresses but allow public hosts', () => {
  for (const url of [
    'http://10.0.0.1',
    'http://100.64.0.1',
    'http://0x7f.1',
    'http://198.51.100.7',
    'http://[::1]',
    'http://[::ffff:127.0.0.1]',
    'http://[fd00::1]',
    'http://[fe80::1]',
    'http://[2001:db8::1]',
  ]) {
    assert.throws(() => normalizeBackupEndpointUrl(url, 'WebDAV URL'), /WebDAV URL host is not allowed/, url);
  }
  for (const url of [
    'https://8.8.8.8',
    'https://[::ffff:8.8.8.8]',
    'https://[2606:4700::1111]',
    'https://10.0.0.1.example.com',
  ]) {
    assert.equal(normalizeBackupEndpointUrl(url, 'WebDAV URL'), new URL(url).toString().replace(/\/+$/, ''), url);
  }
});
