import assert from 'node:assert/strict';
import test from 'node:test';

import { normalizeBitwardenEncryptedAccountImport, normalizeBitwardenImport } from '../webapp/src/lib/import-formats-bitwarden';

test('plain Bitwarden exports coerce loose values and keep unknown cipher keys', () => {
  const payload = normalizeBitwardenImport({
    folders: [{ id: 'f1', name: ' Work ' }, null, { id: 'f2', name: '' }],
    items: [
      { type: '2', reprompt: '1', folderId: 'f1', collectionIds: ['c'], login: { username: 'u', extra: 1, uris: [null] } },
      { fields: [{ type: 'abc' }], passwordHistory: [{ password: '' }, { password: 'p' }] },
      null,
    ],
  });
  assert.deepEqual(payload.folders, [{ name: 'Work' }]);
  assert.deepEqual(payload.folderRelationships, [{ key: 0, value: 0 }]);
  const [first, second, third] = payload.ciphers;
  assert.equal(first.type, 2);
  assert.equal(first.reprompt, 1);
  assert.deepEqual(first.collectionIds, ['c']);
  assert.deepEqual(first.login, {
    username: 'u', password: null, totp: null, fido2Credentials: null, uris: [{ uri: null, uriChecksum: null, match: null }],
  });
  assert.deepEqual(second.fields, [{ name: null, value: null, type: 0, linkedId: null }]);
  assert.deepEqual(second.passwordHistory, [{ password: 'p', lastUsedDate: null }]);
  assert.equal(third.name, 'Untitled');
  assert.equal(third.login, null);
});

test('a single-folder export without explicit links puts every item in that folder', () => {
  const payload = normalizeBitwardenImport({ folders: [{ name: 'Only' }], items: [{}, {}] });
  assert.deepEqual(payload.folderRelationships, [{ key: 0, value: 0 }, { key: 1, value: 0 }]);
});

test('non-object and encrypted exports are refused by the plain importer', () => {
  assert.throws(() => normalizeBitwardenImport(null), /Invalid Bitwarden JSON/);
  assert.throws(() => normalizeBitwardenImport({ encrypted: true }), /encrypted import flow/);
});

test('encrypted account exports pass ciphers through and refuse organization exports', () => {
  const cipher = { name: '2.a|b|c', folderId: 'f' };
  const payload = normalizeBitwardenEncryptedAccountImport({ encrypted: true, folders: [{ id: 'f', name: '2.x|y|z' }], items: [cipher] });
  assert.deepEqual(payload, { ciphers: [cipher], folders: [{ name: '2.x|y|z' }], folderRelationships: [{ key: 0, value: 0 }] });
  assert.throws(() => normalizeBitwardenEncryptedAccountImport({ encrypted: true, collections: [] }), /organization export/);
});
