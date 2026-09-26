import assert from 'node:assert/strict';
import test from 'node:test';

// ─── Bitwarden organization export import ───────────────────────────────────
// Bitwarden org exports carry no folders array: folderId is always null and
// the vault's path structure lives in collections + per-item collectionIds.
// The parser mirrors the file's collections as the folder source so the
// "Original path from import file" folder mode maps org items, matching the
// sample at bitwarden.com/help/export-organization-items/.

const { normalizeBitwardenImport } = await import('../webapp/src/lib/import-formats-bitwarden');

const ORG_EXPORT = {
  encrypted: false,
  collections: [
    { id: 'coll-1', organizationId: 'org-1', name: 'Engineering', externalId: null },
    { id: 'coll-2', organizationId: 'org-1', name: 'Finance', externalId: null },
    { id: 'coll-3', organizationId: 'org-1', name: '', externalId: null },
  ],
  items: [
    { id: 'i1', type: 1, name: 'Item A', folderId: null, collectionIds: ['coll-1'], organizationId: 'org-1', login: { username: 'a', password: 'p' } },
    { id: 'i2', type: 1, name: 'Item B', folderId: null, collectionIds: ['coll-2', 'coll-1'], organizationId: 'org-1', login: { username: 'b', password: 'p' } },
    { id: 'i3', type: 2, name: 'Item C', folderId: null, collectionIds: [], organizationId: 'org-1', secureNote: { type: 0 } },
    { id: 'i4', type: 1, name: 'Item D', collectionIds: ['unknown-coll'], organizationId: 'org-1', login: { username: 'd', password: 'p' } },
  ],
};

const PERSONAL_EXPORT = {
  encrypted: false,
  folders: [{ id: 'f1', name: 'Work' }],
  items: [{ id: 'p1', type: 1, name: 'P', folderId: 'f1', login: {} }],
};

test('bitwarden org export: collections mirror into folders + relationships', () => {
  const result = normalizeBitwardenImport(ORG_EXPORT);
  assert.deepEqual(
    result.folders.map((folder) => folder.name),
    ['Engineering', 'Finance'],
    'unnamed collections are skipped'
  );
  assert.deepEqual(
    result.folderRelationships,
    [
      { key: 0, value: 0 },
      { key: 1, value: 1 },
    ],
    'item membership maps to its first known collection'
  );
});

test('bitwarden personal export with folders is unchanged', () => {
  const result = normalizeBitwardenImport(PERSONAL_EXPORT);
  assert.deepEqual(result.folders.map((folder) => folder.name), ['Work']);
  assert.deepEqual(result.folderRelationships, [{ key: 0, value: 0 }]);
});

test('folderId still wins over collectionIds when both resolve', () => {
  const mixed = {
    encrypted: false,
    folders: [{ id: 'f1', name: 'Folder' }],
    collections: [{ id: 'c1', name: 'Collection' }],
    items: [{ id: 'm1', type: 1, name: 'M', folderId: 'f1', collectionIds: ['c1'], login: {} }],
  };
  const result = normalizeBitwardenImport(mixed);
  assert.deepEqual(result.folders.map((folder) => folder.name), ['Folder']);
  assert.deepEqual(result.folderRelationships, [{ key: 0, value: 0 }]);
});
