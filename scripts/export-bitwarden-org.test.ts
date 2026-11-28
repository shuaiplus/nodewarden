import assert from 'node:assert/strict';
import test from 'node:test';

// ─── Bitwarden organization export ──────────────────────────────────────────
// The export must match Bitwarden's organization export shape
// ({ encrypted: false, collections, items }) so Bitwarden's org import can
// consume it: collections land as target-org collections and items carry
// organizationId + collectionIds (Bitwarden rejects org imports containing
// unassigned items).

const { encryptBw, base64ToBytes, bytesToBase64 } = await import('../webapp/src/lib/crypto');
const { buildBitwardenOrgJson } = await import('../webapp/src/lib/export-formats');

function randomKey(): { encB64: string; macB64: string } {
  const enc = new Uint8Array(32);
  const mac = new Uint8Array(32);
  crypto.getRandomValues(enc);
  crypto.getRandomValues(mac);
  return { encB64: bytesToBase64(enc), macB64: bytesToBase64(mac) };
}

const ORG_ID = 'org-1';
const userKey = randomKey();
const orgKey = randomKey();

async function encryptedName(value: string, key: { encB64: string; macB64: string }): Promise<string> {
  return encryptBw(new TextEncoder().encode(value), base64ToBytes(key.encB64), base64ToBytes(key.macB64));
}

test('bitwarden org export: shape, decryption, filtering, and unassigned skip', async () => {
  const encName = await encryptedName('Shared login', orgKey);
  const ciphers: any[] = [
    // Org item in one collection
    { id: 'c1', type: 1, organizationId: ORG_ID, folderId: null, name: encName, collectionIds: ['col-a'], login: { username: await encryptedName('user-a', orgKey), password: null, totp: null, uris: [] }, fields: [], passwordHistory: [] },
    // Org item in two collections
    { id: 'c2', type: 2, organizationId: ORG_ID, folderId: null, name: encName, collectionIds: ['col-a', 'col-b'], secureNote: { type: 0 }, fields: [], passwordHistory: [] },
    // Org item without any accessible collection → skipped
    { id: 'c3', type: 1, organizationId: ORG_ID, name: encName, collectionIds: [], login: null, fields: [], passwordHistory: [] },
    // Deleted org item → skipped
    { id: 'c4', type: 1, organizationId: ORG_ID, deletedDate: '2026-01-01T00:00:00Z', name: encName, collectionIds: ['col-a'], login: null, fields: [], passwordHistory: [] },
    // Personal item and other-org item → excluded
    { id: 'p1', type: 1, name: await encryptedName('Personal', userKey), login: null, fields: [], passwordHistory: [] },
    { id: 'o2', type: 1, organizationId: 'org-other', name: encName, collectionIds: ['col-z'], login: null, fields: [], passwordHistory: [] },
  ];

  const result = await buildBitwardenOrgJson({
    organizationId: ORG_ID,
    collections: [
      { id: 'col-a', organizationId: ORG_ID, name: await encryptedName('Engineering', orgKey), decName: 'Engineering', externalId: null },
      { id: 'col-b', organizationId: ORG_ID, name: await encryptedName('Finance', orgKey), externalId: null },
      { id: 'col-x', organizationId: 'org-other', name: 'Other org collection', externalId: null },
    ],
    ciphers,
    userEncB64: userKey.encB64,
    userMacB64: userKey.macB64,
    orgKeys: { [ORG_ID]: orgKey },
  });

  const doc = JSON.parse(result.json);
  assert.equal(doc.encrypted, false);
  assert.equal(doc.folders, undefined, 'org exports carry no folders array');
  assert.deepEqual(
    doc.collections,
    [
      { id: 'col-a', organizationId: ORG_ID, name: 'Engineering', externalId: null },
      // decName missing → falls back to decrypting the encrypted name with the org key
      { id: 'col-b', organizationId: ORG_ID, name: 'Finance', externalId: null },
    ],
    'only the target org collections are exported, with decrypted names'
  );
  assert.deepEqual(
    doc.items.map((item: Record<string, unknown>) => item.id),
    ['c1', 'c2'],
    'deleted, unassigned, personal, and other-org items are excluded'
  );
  assert.equal(doc.items[0].name, 'Shared login', 'item fields decrypt with the org key');
  assert.equal(doc.items[0].login.username, 'user-a');
  assert.deepEqual(doc.items[0].collectionIds, ['col-a']);
  assert.deepEqual(doc.items[1].collectionIds, ['col-a', 'col-b']);
  assert.equal(result.skippedUnassignedItems, 1, 'exactly one unassigned item was skipped');
});

test('bitwarden org export: missing org key fails loudly', async () => {
  await assert.rejects(
    () =>
      buildBitwardenOrgJson({
        organizationId: ORG_ID,
        collections: [],
        ciphers: [],
        userEncB64: userKey.encB64,
        userMacB64: userKey.macB64,
        orgKeys: {},
      }),
    /organization key is unavailable/i
  );
});
