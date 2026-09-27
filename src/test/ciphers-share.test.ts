import assert from 'node:assert/strict';
import test from 'node:test';

import { LIMITS } from '../config/limits';
import type { Env, User } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { createCollection, errorMessage, seedMember } from './support/sm';
import * as attachmentRepo from '../services/storage-attachment-repo';
import * as cipherRepo from '../services/storage-cipher-repo';

const { createOwnedOrganization } = await import('../handlers/organizations');

// Official clients move a personal item into an org (cipher form owner change, assign-collections,
// the data-ownership item transfer) by re-encrypting it under the org key and calling
// PUT /ciphers/{id}/share or PUT /ciphers/share (api.service.ts putShareCipher / putShareCiphers).
// Upstream CiphersController.PutShare / PutShareMany and their POST aliases @ v2026.9.1.
const ORG_KEY = '4.dGVzdA==';
const USER_ENCRYPTED = '2.dXNlcg==|dXNlcg==|dXNlcg==';
const ORG_ENCRYPTED = '2.b3Jn|b3Jn|b3Jn';
const LOGIN_TYPE = 1;
const ATTACHMENT_SIZE = 10;
const NOT_OWNED = 'Trying to share ciphers that you do not own.';
const NO_COLLECTION = 'You must select at least one collection.';
const MIXED_ORGS = 'All ciphers must be for the same organization.';
const ORG_MISMATCH = 'Organization mismatch. Re-sync if you recently moved this item, then try again.';
const INVALID_KEY = 'not-an-encstring';
// Well past the 1 s tolerance of the stale-revision check.
const STALE_REVISION_AGE_MS = 60 * 60 * 1000;

interface CipherBody {
  id: string;
  organizationId: string | null;
  collectionIds: string[];
  name: string;
  key: string | null;
  revisionDate: string;
  attachments: Array<{ id: string; key: string | null; fileName: string }> | null;
}

interface Fixture {
  env: Env;
  owner: User;
  orgId: string;
  collectionId: string;
}

async function setup(): Promise<Fixture> {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: ORG_KEY })).id;
  return { env, owner, orgId, collectionId: await createCollection(env, owner, orgId) };
}

async function createPersonalCipher(env: Env, user: User): Promise<string> {
  const response = await authedFetch(env, {
    method: 'POST',
    path: '/api/ciphers',
    body: { type: LOGIN_TYPE, name: USER_ENCRYPTED, key: USER_ENCRYPTED, login: { username: USER_ENCRYPTED } },
    userId: user.id,
  });
  assert.equal(response.status, 200);
  return ((await response.json()) as CipherBody).id;
}

async function addAttachment(env: Env, cipherId: string): Promise<string> {
  const attachmentId = crypto.randomUUID();
  await attachmentRepo.saveAttachment(env.DB, {
    id: attachmentId, cipherId, fileName: USER_ENCRYPTED, size: ATTACHMENT_SIZE, sizeName: `${ATTACHMENT_SIZE} Bytes`, key: USER_ENCRYPTED,
  });
  return attachmentId;
}

// The CipherRequest the client sends, e.g. after moveToOrganization re-encrypted it under the org key.
function cipherRequest(organizationId: string | null, extra: Record<string, unknown> = {}) {
  return { type: LOGIN_TYPE, organizationId, name: ORG_ENCRYPTED, key: ORG_ENCRYPTED, login: { username: ORG_ENCRYPTED }, ...extra };
}

// attachments2 carries each attachment's key and file name re-encrypted along with the cipher.
function rekeyedAttachment(attachmentId: string) {
  return { attachments2: { [attachmentId]: { fileName: ORG_ENCRYPTED, key: ORG_ENCRYPTED } } };
}

function attachmentKeys(cipher: CipherBody | undefined) {
  return cipher?.attachments?.map(({ id, key, fileName }) => ({ id, key, fileName }));
}

function share(
  env: Env, user: User, cipherId: string, orgId: string, collectionIds: string[], method = 'PUT', extra: Record<string, unknown> = {}
): Promise<Response> {
  return authedFetch(env, { method, path: `/api/ciphers/${cipherId}/share`, body: { cipher: cipherRequest(orgId, extra), collectionIds }, userId: user.id });
}

function shareMany(
  env: Env, user: User, ciphers: Array<{ id: string; orgId: string; extra?: Record<string, unknown> }>, collectionIds: string[], method = 'PUT'
): Promise<Response> {
  return authedFetch(env, {
    method,
    path: '/api/ciphers/share',
    body: { ciphers: ciphers.map(({ id, orgId, extra }) => cipherRequest(orgId, { id, ...extra })), collectionIds },
    userId: user.id,
  });
}

async function storedOrganizationId(env: Env, cipherId: string): Promise<string | null> {
  return (await cipherRepo.getCipher(env.DB, cipherId))?.organizationId ?? null;
}

async function syncedCipherIds(env: Env, user: User): Promise<string[]> {
  const response = await authedFetch(env, { path: '/api/sync', userId: user.id });
  assert.equal(response.status, 200);
  return ((await response.json()) as { ciphers: CipherBody[] }).ciphers.map((cipher) => cipher.id);
}

test('PUT /ciphers/{id}/share moves a personal cipher into the org with its re-encrypted data and collections', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const { user: member } = await seedMember(env, orgId, { collections: [{ collectionId, readOnly: false, hidePasswords: false, manage: false }] });
  const cipherId = await createPersonalCipher(env, owner);
  const attachmentId = await addAttachment(env, cipherId);
  assert.deepEqual(await syncedCipherIds(env, member), []);

  const response = await share(env, owner, cipherId, orgId, [collectionId], 'PUT', rekeyedAttachment(attachmentId));

  assert.equal(response.status, 200);
  const body = await response.json() as CipherBody;
  assert.equal(body.id, cipherId);
  assert.equal(body.organizationId, orgId);
  assert.deepEqual(body.collectionIds, [collectionId]);
  assert.equal(body.name, ORG_ENCRYPTED);
  assert.equal(body.key, ORG_ENCRYPTED);
  assert.deepEqual(attachmentKeys(body), [{ id: attachmentId, key: ORG_ENCRYPTED, fileName: ORG_ENCRYPTED }]);
  assert.equal(await storedOrganizationId(env, cipherId), orgId);
  // Every org member's revision moves, so the member's cached sync is not served stale.
  assert.deepEqual(await syncedCipherIds(env, member), [cipherId]);
});

test('POST /ciphers/{id}/share is the deprecated alias and shares instead of echoing the personal cipher', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherId = await createPersonalCipher(env, owner);

  const response = await share(env, owner, cipherId, orgId, [collectionId], 'POST');

  assert.equal(response.status, 200);
  assert.equal(((await response.json()) as CipherBody).organizationId, orgId);
  assert.equal(await storedOrganizationId(env, cipherId), orgId);
});

test('share refuses ciphers that are not the caller\'s personal items, orgs it is not in, and collections it cannot write', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const outsider = await seedUser(env);
  const { user: readOnlyMember } = await seedMember(env, orgId, { collections: [{ collectionId, readOnly: true, hidePasswords: false, manage: false }] });
  const otherOrgId = (await createOwnedOrganization(env, outsider, { name: 'Other', key: ORG_KEY })).id;
  const otherOrgCollectionId = await createCollection(env, outsider, otherOrgId);
  const ownerCipherId = await createPersonalCipher(env, owner);
  const outsiderCipherId = await createPersonalCipher(env, outsider);
  const readOnlyCipherId = await createPersonalCipher(env, readOnlyMember);

  assert.equal((await share(env, owner, outsiderCipherId, orgId, [collectionId])).status, 404);
  assert.equal((await share(env, outsider, outsiderCipherId, orgId, [collectionId])).status, 404);
  assert.equal((await share(env, readOnlyMember, readOnlyCipherId, orgId, [collectionId])).status, 400);
  assert.equal((await share(env, owner, ownerCipherId, orgId, [otherOrgCollectionId])).status, 400);
  const empty = await share(env, owner, ownerCipherId, orgId, []);
  assert.equal(empty.status, 400);
  assert.equal(await errorMessage(empty), NO_COLLECTION);
  for (const cipherId of [ownerCipherId, outsiderCipherId, readOnlyCipherId]) {
    assert.equal(await storedOrganizationId(env, cipherId), null);
  }

  assert.equal((await share(env, owner, ownerCipherId, orgId, [collectionId])).status, 200);
  // Once in the org it is no longer a personal item, so it cannot be shared again.
  assert.equal((await share(env, owner, ownerCipherId, orgId, [collectionId])).status, 404);
});

test('PUT /ciphers/share moves many personal ciphers and lists them with their new revision dates', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherIds = [await createPersonalCipher(env, owner), await createPersonalCipher(env, owner)];
  const attachmentId = await addAttachment(env, cipherIds[0]);

  const response = await shareMany(env, owner, [
    { id: cipherIds[0], orgId, extra: rekeyedAttachment(attachmentId) },
    { id: cipherIds[1], orgId },
  ], [collectionId]);

  assert.equal(response.status, 200);
  const body = await response.json() as { object: string; data: CipherBody[] };
  assert.equal(body.object, 'list');
  assert.deepEqual(body.data.map((cipher) => cipher.id).sort(), [...cipherIds].sort());
  for (const cipher of body.data) {
    assert.equal(cipher.organizationId, orgId);
    assert.deepEqual(cipher.collectionIds, [collectionId]);
    assert.ok(cipher.revisionDate);
  }
  assert.deepEqual(
    attachmentKeys(body.data.find((cipher) => cipher.id === cipherIds[0])),
    [{ id: attachmentId, key: ORG_ENCRYPTED, fileName: ORG_ENCRYPTED }]
  );
  for (const cipherId of cipherIds) {
    assert.equal(await storedOrganizationId(env, cipherId), orgId);
  }
});

test('POST /ciphers/share is the deprecated bulk alias', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherId = await createPersonalCipher(env, owner);

  assert.equal((await shareMany(env, owner, [{ id: cipherId, orgId }], [collectionId], 'POST')).status, 200);
  assert.equal(await storedOrganizationId(env, cipherId), orgId);
});

test('PUT /ciphers/share shares nothing when any cipher is not the caller\'s, the org is not theirs, or orgs differ', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const outsider = await seedUser(env);
  const otherOrgId = (await createOwnedOrganization(env, owner, { name: 'Other', key: ORG_KEY })).id;
  const ownerCipherId = await createPersonalCipher(env, owner);
  const outsiderCipherId = await createPersonalCipher(env, outsider);

  const notOwned = await shareMany(env, owner, [{ id: ownerCipherId, orgId }, { id: outsiderCipherId, orgId }], [collectionId]);
  assert.equal(notOwned.status, 400);
  assert.equal(await errorMessage(notOwned), NOT_OWNED);
  assert.equal((await shareMany(env, outsider, [{ id: outsiderCipherId, orgId }], [collectionId])).status, 404);
  const mixed = await shareMany(env, owner, [{ id: ownerCipherId, orgId }, { id: outsiderCipherId, orgId: otherOrgId }], [collectionId]);
  assert.equal(mixed.status, 400);
  assert.equal(await errorMessage(mixed), MIXED_ORGS);

  assert.equal(await storedOrganizationId(env, ownerCipherId), null);
  assert.equal(await storedOrganizationId(env, outsiderCipherId), null);
});

test('share refuses the request bodies the upstream request models reject, and oversized bulk shares', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherId = await createPersonalCipher(env, owner);
  const rejections: Array<[() => Promise<Response>, string]> = [
    [() => share(env, owner, cipherId, orgId, [collectionId], 'PUT', { organizationId: null }), 'Cipher OrganizationId is required.'],
    [() => shareMany(env, owner, [], [collectionId]), 'You must select at least one cipher.'],
    [() => shareMany(env, owner, [{ id: cipherId, orgId, extra: { id: null } }], [collectionId]), 'All Ciphers must have an Id and OrganizationId.'],
    [
      () => shareMany(env, owner, Array.from({ length: LIMITS.performance.importItemLimit + 1 }, () => ({ id: cipherId, orgId })), [collectionId]),
      `Share exceeds maximum of ${LIMITS.performance.importItemLimit} items`,
    ],
  ];

  for (const [send, message] of rejections) {
    const response = await send();
    assert.equal(response.status, 400);
    assert.equal(await errorMessage(response), message);
  }
  assert.equal(await storedOrganizationId(env, cipherId), null);
});

test('share writes nothing when a re-encrypted body is stale or carries an invalid key', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherIds = [await createPersonalCipher(env, owner), await createPersonalCipher(env, owner)];
  const staleRevision = new Date(Date.now() - STALE_REVISION_AGE_MS).toISOString();

  const stale = await share(env, owner, cipherIds[0], orgId, [collectionId], 'PUT', { lastKnownRevisionDate: staleRevision });
  assert.equal(stale.status, 400);
  const invalidKey = await shareMany(env, owner, [{ id: cipherIds[0], orgId }, { id: cipherIds[1], orgId, extra: { key: INVALID_KEY } }], [collectionId]);
  assert.equal(invalidKey.status, 400);

  for (const cipherId of cipherIds) {
    assert.equal(await storedOrganizationId(env, cipherId), null);
  }
});

// Upstream CiphersController.Put: only share moves an item between the personal vault and an org.
test('PUT /ciphers/{id} edits a cipher with its attachment metadata but never changes its organization', async () => {
  const { env, owner, orgId, collectionId } = await setup();
  const cipherId = await createPersonalCipher(env, owner);
  const attachmentId = await addAttachment(env, cipherId);
  const update = (body: Record<string, unknown>) => authedFetch(env, { method: 'PUT', path: `/api/ciphers/${cipherId}`, body, userId: owner.id });

  const edited = await update(cipherRequest(null, rekeyedAttachment(attachmentId)));
  assert.equal(edited.status, 200);
  const body = await edited.json() as CipherBody;
  assert.equal(body.name, ORG_ENCRYPTED);
  assert.deepEqual(attachmentKeys(body), [{ id: attachmentId, key: ORG_ENCRYPTED, fileName: ORG_ENCRYPTED }]);

  const intoOrg = await update(cipherRequest(orgId));
  assert.equal(intoOrg.status, 400);
  assert.equal(await errorMessage(intoOrg), ORG_MISMATCH);
  assert.equal(await storedOrganizationId(env, cipherId), null);

  assert.equal((await share(env, owner, cipherId, orgId, [collectionId])).status, 200);
  const outOfOrg = await update(cipherRequest(null));
  assert.equal(outOfOrg.status, 400);
  assert.equal(await errorMessage(outOfOrg), ORG_MISMATCH);
  assert.equal(await storedOrganizationId(env, cipherId), orgId);
});
