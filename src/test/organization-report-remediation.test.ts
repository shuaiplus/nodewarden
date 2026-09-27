import assert from 'node:assert/strict';
import test from 'node:test';

import { getOrm } from '../db/client';
import { cipherCollections } from '../db/schema';
import { MembershipStatus, MembershipType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';
import * as cipherRepo from '../services/storage-cipher-repo';

const CHANGED = '2.Y2hhbmdlZA==|Y2hhbmdlZA==|Y2hhbmdlZA==';
const FIELDS = {
  type: 1,
  name: ENCRYPTED_FIELD,
  notes: ENCRYPTED_FIELD,
  login: { username: ENCRYPTED_FIELD, password: ENCRYPTED_FIELD },
};

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner, admin } = await seedSmOrg(env);
  const collection = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/collections`, {
    name: ENCRYPTED_FIELD,
  });
  const create = (assigned = true, organizationId: string | null = orgId) =>
    postJson<{ id: string; revisionDate: string }>(env, owner, '/api/ciphers/create', {
      cipher: { ...FIELDS, organizationId },
      collectionIds: assigned && organizationId ? [collection.id] : [],
    });
  const updateBody = (revisionDate: string) => ({
    ...FIELDS,
    organizationId: orgId,
    name: CHANGED,
    login: { username: ENCRYPTED_FIELD, password: CHANGED },
    lastKnownRevisionDate: revisionDate,
  });
  const request = (userId: string, id: string, method: string, suffix = 'admin', body?: unknown) =>
    authedFetch(env, { userId, path: `/api/ciphers/${id}${suffix ? `/${suffix}` : ''}`, method, body });
  return { env, orgId, owner, admin, collection, create, updateBody, request, storage: env.DB };
}

test('confirmed owners, admins and edit-any Custom members can remediate assigned and unassigned org ciphers', async () => {
  const { env, orgId, owner, admin, collection, create, updateBody, request, storage } = await setup();
  const { user: custom } = await seedMember(env, orgId, {
    type: MembershipType.Custom,
    permissions: { editAnyCollection: true },
  });
  for (const actor of [owner, admin, custom]) {
    for (const assigned of [true, false]) {
      const cipher = await create(assigned);
      const changed = await request(actor.id, cipher.id, 'PUT', 'admin', updateBody(cipher.revisionDate));
      assert.equal(changed.status, 200);
      const body = (await changed.json()) as any;
      assert.equal(body.id, cipher.id);
      assert.equal(body.object, 'cipherMini');
      assert.equal(body.organizationId, orgId);
      assert.equal(body.name, CHANGED);
      assert.equal(body.login.password, CHANGED);
      assert.deepEqual(body.collectionIds, assigned ? [collection.id] : []);
      assert.equal((await cipherRepo.getCipher(storage, cipher.id))!.userId, owner.id);
      assert.deepEqual(await orgRepo.listCipherCollectionIds(env.DB, cipher.id), assigned ? [collection.id] : []);
      const deleted = await request(actor.id, cipher.id, 'PUT', 'delete-admin');
      assert.equal(deleted.status, 200);
      assert.equal(await deleted.text(), '');
      assert.ok((await cipherRepo.getCipher(storage, cipher.id))!.deletedAt);
      assert.deepEqual(await orgRepo.listCipherCollectionIds(env.DB, cipher.id), assigned ? [collection.id] : []);
      const removed = await request(actor.id, cipher.id, 'DELETE');
      assert.equal(removed.ok, true);
      assert.equal(await removed.text(), '');
      assert.equal(await cipherRepo.getCipher(storage, cipher.id), null);
      assert.deepEqual(await orgRepo.listCipherCollectionIds(env.DB, cipher.id), []);
    }
  }
  const active = await create(false);
  assert.equal((await request(owner.id, active.id, 'DELETE')).status, 204);
  assert.equal(await cipherRepo.getCipher(storage, active.id), null);
});

test('admin remediation denies report, export, delete-only and ordinary roles without changing cipher state', async () => {
  const { env, orgId, owner, create, updateBody, request, storage } = await setup();
  const cipher = await create();
  const original = await cipherRepo.getCipher(storage, cipher.id);
  const denied = [
    (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { accessReports: true } })).user,
    (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { accessImportExport: true } })).user,
    (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { deleteAnyCollection: true } })).user,
    (await seedMember(env, orgId)).user,
    (await seedMember(env, orgId, { accessAll: true })).user,
    (await seedMember(env, orgId, { type: MembershipType.Admin, status: MembershipStatus.Revoked })).user,
    await seedUser(env),
  ];
  for (const actor of denied) {
    assert.equal((await request(actor.id, cipher.id, 'PUT', 'admin', updateBody(cipher.revisionDate))).status, 404);
    assert.equal((await request(actor.id, cipher.id, 'PUT', 'delete-admin')).status, 404);
    assert.equal((await request(actor.id, cipher.id, 'DELETE')).status, 404);
    assert.deepEqual(await cipherRepo.getCipher(storage, cipher.id), original);
  }
  const personal = await create(false, null);
  const foreign = await seedSmOrg(env);
  const outside = await postJson<{ id: string }>(env, foreign.owner, '/api/ciphers/create', {
    cipher: { ...FIELDS, organizationId: foreign.orgId },
    collectionIds: [],
  });
  for (const id of [personal.id, outside.id]) {
    const before = await cipherRepo.getCipher(storage, id);
    assert.equal((await request(owner.id, id, 'PUT', 'admin', updateBody(cipher.revisionDate))).status, 404);
    assert.equal((await request(owner.id, id, 'PUT', 'delete-admin')).status, 404);
    assert.equal((await request(owner.id, id, 'DELETE')).status, 404);
    assert.deepEqual(await cipherRepo.getCipher(storage, id), before);
  }
});

test('admin PUT validates revisions and organization ownership while preserving collection assignments', async () => {
  const { env, orgId, owner, collection, create, updateBody, request, storage } = await setup();
  const cipher = await create();
  const before = await cipherRepo.getCipher(storage, cipher.id);
  const stale = await request(
    owner.id,
    cipher.id,
    'PUT',
    'admin',
    updateBody(new Date(Date.parse(cipher.revisionDate) - 60_000).toISOString()),
  );
  assert.equal(stale.status, 400);
  assert.match(((await stale.json()) as any).message, /out of date/i);
  const foreign = await seedSmOrg(env);
  const moved = await request(owner.id, cipher.id, 'PUT', 'admin', {
    ...updateBody(cipher.revisionDate),
    organizationId: foreign.orgId,
  });
  assert.equal(moved.status, 400);
  assert.match(((await moved.json()) as any).message, /Organization mismatch/);
  assert.deepEqual(await cipherRepo.getCipher(storage, cipher.id), before);
  const otherCollection = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/collections`, {
    name: ENCRYPTED_FIELD,
  });
  const changed = await request(owner.id, cipher.id, 'PUT', 'admin', {
    ...updateBody(cipher.revisionDate),
    collectionIds: [otherCollection.id],
  });
  assert.equal(changed.status, 200);
  assert.deepEqual(((await changed.json()) as any).collectionIds, [collection.id]);
  assert.deepEqual(await orgRepo.listCipherCollectionIds(env.DB, cipher.id), [collection.id]);
});

test('ordinary personal and collection-authorized org mutation routes keep their original permission rules', async () => {
  const { env, orgId, owner, collection, create, updateBody, request, storage } = await setup();
  const { user: editor } = await seedMember(env, orgId);
  const { user: reporter } = await seedMember(env, orgId, {
    type: MembershipType.Custom,
    permissions: { accessReports: true },
  });
  const editorMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, editor.id, orgId))!;
  await orgRepo.replaceCollectionAccess(env.DB, collection.id, {
    users: [{ member: editorMember, readOnly: false, hidePasswords: false, manage: false }],
  });
  const cipher = await create();
  assert.equal((await request(editor.id, cipher.id, 'PUT', 'admin', updateBody(cipher.revisionDate))).status, 404);
  assert.equal((await request(reporter.id, cipher.id, 'PUT', '', updateBody(cipher.revisionDate))).status, 404);
  const edited = await request(editor.id, cipher.id, 'PUT', '', updateBody(cipher.revisionDate));
  assert.equal(edited.status, 200);
  assert.equal(((await edited.json()) as any).object, 'cipherDetails');
  assert.equal((await request(editor.id, cipher.id, 'PUT', 'delete')).status, 200);
  assert.ok((await cipherRepo.getCipher(storage, cipher.id))!.deletedAt);
  assert.equal((await request(editor.id, cipher.id, 'DELETE', '')).status, 204);
  assert.equal(await cipherRepo.getCipher(storage, cipher.id), null);
  const personal = await create(false, null);
  assert.equal((await request(editor.id, personal.id, 'PUT', '', { ...FIELDS, organizationId: null })).status, 404);
  assert.equal(
    (
      await request(owner.id, personal.id, 'PUT', '', {
        ...FIELDS,
        organizationId: null,
        name: CHANGED,
        lastKnownRevisionDate: personal.revisionDate,
      })
    ).status,
    200,
  );
  assert.equal((await request(owner.id, personal.id, 'PUT', 'delete')).status, 200);
  assert.equal((await request(owner.id, personal.id, 'DELETE', '')).status, 204);
});

test('legacy foreign collection links stay excluded from admin edit responses', async () => {
  const { env, owner, collection, create, updateBody, request } = await setup();
  const foreign = await seedSmOrg(env);
  const foreignCollection = (await orgRepo.listCollectionsByOrg(env.DB, foreign.orgId))[0];
  const cipher = await create();
  await getOrm(env.DB).insert(cipherCollections).values({ cipherId: cipher.id, collectionId: foreignCollection.id });
  const updated = await request(owner.id, cipher.id, 'PUT', 'admin', updateBody(cipher.revisionDate));
  assert.equal(updated.status, 200);
  assert.deepEqual(((await updated.json()) as any).collectionIds, [collection.id]);
  const read = await request(owner.id, cipher.id, 'GET');
  assert.equal(read.status, 200);
  assert.deepEqual(((await read.json()) as any).collectionIds, [collection.id]);
});

test('a Custom organization editor can complete the report form collection-change sequence without personal read access', async () => {
  const { env, orgId, owner, create, updateBody, request } = await setup();
  const { user: custom } = await seedMember(env, orgId, {
    type: MembershipType.Custom,
    permissions: { editAnyCollection: true },
  });
  const destination = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/collections`, {
    name: ENCRYPTED_FIELD,
  });
  const cipher = await create(false);
  assert.equal((await request(custom.id, cipher.id, 'GET', '')).status, 404);
  assert.equal((await request(custom.id, cipher.id, 'PUT', 'admin', updateBody(cipher.revisionDate))).status, 200);
  const reassigned = await request(custom.id, cipher.id, 'PUT', 'collections-admin', {
    collectionIds: [destination.id],
  });
  assert.equal(reassigned.status, 200);
  assert.deepEqual(((await reassigned.json()) as any).collectionIds, [destination.id]);
  assert.equal((await request(custom.id, cipher.id, 'GET', '')).status, 404);
  assert.equal((await request(custom.id, cipher.id, 'GET', 'admin')).status, 200);
});
