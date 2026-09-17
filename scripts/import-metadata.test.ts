import assert from 'node:assert/strict';
import test from 'node:test';

import {
  copyImportedCreationDate,
  copyImportedPasswordRevisionDate,
  normalizeImportedCreationDate,
  normalizeImportedPasswordRevisionDate,
  readImportedCreationDate,
} from '../shared/import-metadata';
import { normalizeBitwardenImport } from '../webapp/src/lib/import-formats-bitwarden';
import { buildPlainBitwardenJsonDocument } from '../webapp/src/lib/export-formats';

const fallback = '2026-09-17T02:00:00.000Z';

test('reads supported import creation date aliases', () => {
  assert.equal(readImportedCreationDate({ creationDate: '2024-01-02T03:04:05Z' }), '2024-01-02T03:04:05Z');
  assert.equal(readImportedCreationDate({ CreationDate: '2024-02-03T04:05:06Z' }), '2024-02-03T04:05:06Z');
  assert.equal(readImportedCreationDate({ createdAt: '2024-03-04T05:06:07Z' }), '2024-03-04T05:06:07Z');
  assert.equal(readImportedCreationDate({ created_at: '2024-04-05T06:07:08Z' }), '2024-04-05T06:07:08Z');
});

test('copies source creation metadata into a plaintext import payload', () => {
  const target: Record<string, unknown> = { name: 'encrypted-name' };
  copyImportedCreationDate({ creationDate: '2024-01-02T03:04:05.000Z' }, target);

  assert.deepEqual(target, {
    name: 'encrypted-name',
    creationDate: '2024-01-02T03:04:05.000Z',
  });
});

test('normalizes a valid imported creation date', () => {
  assert.equal(
    normalizeImportedCreationDate({ creationDate: '2024-01-02T03:04:05+08:00' }, fallback),
    '2024-01-01T19:04:05.000Z'
  );
});

test('falls back to import time for missing, empty, invalid, or non-string dates', () => {
  assert.equal(normalizeImportedCreationDate({}, fallback), fallback);
  assert.equal(normalizeImportedCreationDate({ creationDate: '' }, fallback), fallback);
  assert.equal(normalizeImportedCreationDate({ creationDate: 'not-a-date' }, fallback), fallback);
  assert.equal(normalizeImportedCreationDate({ creationDate: 1234 }, fallback), fallback);
});

test('preserves source password revision metadata instead of using import time', () => {
  const target: Record<string, unknown> = {
    login: { passwordRevisionDate: fallback },
  };
  copyImportedPasswordRevisionDate({
    login: { passwordRevisionDate: '2024-05-06T07:08:09+08:00' },
  }, target);

  assert.equal(
    (target.login as Record<string, unknown>).passwordRevisionDate,
    '2024-05-06T07:08:09+08:00'
  );
  assert.equal(
    normalizeImportedPasswordRevisionDate(target.login),
    '2024-05-05T23:08:09.000Z'
  );
});

test('uses null when an import omits password revision date', () => {
  const target: Record<string, unknown> = {
    login: { passwordRevisionDate: fallback },
  };
  copyImportedPasswordRevisionDate({ login: {} }, target);

  assert.equal((target.login as Record<string, unknown>).passwordRevisionDate, null);
  assert.equal(normalizeImportedPasswordRevisionDate({}), null);
});

test('uses the Unix epoch for an invalid password revision date like Vaultwarden', () => {
  assert.equal(
    normalizeImportedPasswordRevisionDate({ passwordRevisionDate: 'not-a-date' }),
    '1970-01-01T00:00:00.000Z'
  );
});

test('Bitwarden JSON normalization retains item and password timestamps', () => {
  const normalized = normalizeBitwardenImport({
    encrypted: false,
    items: [{
      id: 'cipher-1',
      type: 1,
      name: 'Example',
      creationDate: '2024-01-02T03:04:05.000Z',
      login: {
        password: 'secret',
        passwordRevisionDate: '2024-05-06T07:08:09.000Z',
      },
    }],
  });
  const cipher = normalized.ciphers[0];
  const login = cipher.login as Record<string, unknown>;

  assert.equal(cipher.creationDate, '2024-01-02T03:04:05.000Z');
  assert.equal(login.passwordRevisionDate, '2024-05-06T07:08:09.000Z');
});

test('plain JSON export includes password revision date for round trips', async () => {
  const key = Buffer.alloc(32).toString('base64');
  const exported = await buildPlainBitwardenJsonDocument({
    folders: [],
    ciphers: [{
      id: 'cipher-1',
      type: 1,
      name: 'Example',
      creationDate: '2024-01-02T03:04:05.000Z',
      revisionDate: '2024-06-07T08:09:10.000Z',
      login: {
        password: 'secret',
        passwordRevisionDate: '2024-05-06T07:08:09.000Z',
      },
    }],
    userEncB64: key,
    userMacB64: key,
  });
  const item = (exported.items as Array<Record<string, unknown>>)[0];
  const login = item.login as Record<string, unknown>;

  assert.equal(login.passwordRevisionDate, '2024-05-06T07:08:09.000Z');
});
