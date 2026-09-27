import assert from 'node:assert/strict';
import test from 'node:test';

import { chunkRows, columnCount, getOrm } from '../db/client';
import { cipherCollections, orgGroupMembers, orgGroups } from '../db/schema';
import { cipherUpsert } from '../services/storage-cipher-repo';
import { MembershipStatus, MembershipType } from '../services/org-types';
import * as orgRepo from '../services/storage-org-repo';
import type { Cipher } from '../types';
import { authedFetch, createTestEnv, seedUser } from './support/env';
import { ENCRYPTED_FIELD, postJson, seedMember, seedSmOrg } from './support/sm';

function encryptedCipher(userId: string, organizationId: string | null): Cipher {
  const now = new Date().toISOString();
  return {
    id: crypto.randomUUID(), userId, organizationId, type: 1, folderId: null,
    name: ENCRYPTED_FIELD, notes: ENCRYPTED_FIELD, favorite: false,
    login: { username: ENCRYPTED_FIELD, password: ENCRYPTED_FIELD, uris: [{ uri: ENCRYPTED_FIELD, match: null }], totp: null },
    card: null, identity: null, secureNote: null, sshKey: null, fields: null,
    passwordHistory: null, reprompt: 0, key: ENCRYPTED_FIELD,
    createdAt: now, updatedAt: now, archivedAt: null, deletedAt: null,
  };
}

async function setup() {
  const env = await createTestEnv();
  const { orgId, owner, admin } = await seedSmOrg(env);
  const collection = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/collections`, { name: ENCRYPTED_FIELD });
  const target = encryptedCipher(owner.id, orgId);
  const personal = encryptedCipher(owner.id, null);
  await getOrm(env.DB).batch([cipherUpsert(env.DB, target), cipherUpsert(env.DB, personal)]);
  await orgRepo.replaceCipherCollections(env.DB, target.id, [collection.id]);
  const request = (userId: string, path: string) => authedFetch(env, { userId, path });
  return { env, orgId, owner, admin, collection, target, personal, request };
}

test('organization report list returns every encrypted org cipher and collection mapping above the D1 parameter cap', async () => {
  const { env, orgId, owner, collection, target, personal, request } = await setup();
  const foreign = await seedSmOrg(env);
  const outside = encryptedCipher(foreign.owner.id, foreign.orgId);
  const foreignCollection = await postJson<{ id: string }>(env, foreign.owner, `/api/organizations/${foreign.orgId}/collections`, { name: ENCRYPTED_FIELD });
  const ciphers = Array.from({ length: 124 }, () => encryptedCipher(owner.id, orgId));
  ciphers[0].edit = false;
  ciphers[0].viewPassword = false;
  ciphers[0].permissions = { delete: false, restore: false };
  ciphers[0].futureEncryptedField = ENCRYPTED_FIELD;
  ciphers[1].deletedAt = ciphers[1].updatedAt;
  ciphers[2].archivedAt = ciphers[2].updatedAt;
  await getOrm(env.DB).batch([cipherUpsert(env.DB, outside), ...ciphers.map(cipher => cipherUpsert(env.DB, cipher))]);
  const orm = getOrm(env.DB);
  await orm.batch([
    orm.insert(cipherCollections).values({ cipherId: target.id, collectionId: foreignCollection.id }),
    ...chunkRows(ciphers.slice(1), columnCount(cipherCollections))
      .map(chunk => orm.insert(cipherCollections).values(chunk.map(cipher => ({ cipherId: cipher.id, collectionId: collection.id })))),
  ]);
  for (const query of ['', '&includeMemberItems=true', '&includeMemberItems=false']) {
    const response = await request(owner.id, `/api/ciphers/organization-details?organizationId=${orgId}${query}`);
    assert.equal(response.status, 200);
    const body = await response.json() as any;
    assert.equal(body.object, 'list');
    assert.equal(body.continuationToken, null);
    assert.equal(body.data.length, 125);
    assert.deepEqual(new Set(body.data.map((cipher: any) => cipher.id)), new Set([target.id, ...ciphers.map(cipher => cipher.id)]));
    assert.ok(body.data.every((cipher: any) => cipher.id !== personal.id && cipher.id !== outside.id));
    for (const cipher of body.data) {
      assert.equal(cipher.object, 'cipherMiniDetails');
      assert.equal(cipher.organizationId, orgId);
      assert.equal(cipher.name, ENCRYPTED_FIELD);
      assert.equal(cipher.key, ENCRYPTED_FIELD);
      assert.equal(cipher.login.username, ENCRYPTED_FIELD);
      assert.equal(cipher.login.password, ENCRYPTED_FIELD);
      assert.deepEqual(cipher.collectionIds, cipher.id === ciphers[0].id ? [] : [collection.id]);
      for (const field of ['folderId', 'favorite', 'edit', 'viewPassword', 'permissions']) assert.equal(Object.hasOwn(cipher, field), false);
    }
    const preserved = body.data.find((cipher: any) => cipher.id === ciphers[0].id);
    assert.equal(preserved.futureEncryptedField, ENCRYPTED_FIELD);
    assert.ok(body.data.find((cipher: any) => cipher.id === ciphers[1].id).deletedDate);
    assert.ok(body.data.find((cipher: any) => cipher.id === ciphers[2].id).archivedDate);
  }
  const normal = await request(owner.id, `/api/ciphers/${ciphers[0].id}`);
  assert.equal(normal.status, 200);
  const normalBody = await normal.json() as any;
  assert.equal(normalBody.edit, false);
  assert.equal(normalBody.viewPassword, false);
  assert.deepEqual(normalBody.permissions, { delete: false, restore: false });
  const admin = await request(owner.id, `/api/ciphers/${target.id}/admin`);
  assert.equal(admin.status, 200);
  assert.deepEqual((await admin.json() as any).collectionIds, [collection.id]);
});

test('report and admin-detail gates use explicit org permissions rather than ordinary collection access', async () => {
  const { env, orgId, owner, admin, target, personal, request } = await setup();
  const cases = [
    { user: owner, list: true, detail: true },
    { user: admin, list: true, detail: true },
    { user: (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { accessReports: true } })).user, list: true, detail: false },
    { user: (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { accessImportExport: true } })).user, list: true, detail: false },
    { user: (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { editAnyCollection: true } })).user, list: true, detail: true },
    { user: (await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { deleteAnyCollection: true } })).user, list: false, detail: true },
    { user: (await seedMember(env, orgId)).user, list: false, detail: false },
    { user: (await seedMember(env, orgId, { accessAll: true })).user, list: false, detail: false },
    { user: (await seedMember(env, orgId, { type: MembershipType.Admin, status: MembershipStatus.Revoked })).user, list: false, detail: false },
    { user: (await seedMember(env, orgId, { type: MembershipType.Admin, status: MembershipStatus.Accepted })).user, list: false, detail: false },
    { user: await seedUser(env), list: false, detail: false },
  ];
  for (const { user, list, detail } of cases) {
    const report = await request(user.id, `/api/ciphers/organization-details?organizationId=${orgId}&includeMemberItems=true`);
    assert.equal(report.status, list ? 200 : 404, `report access for ${user.id}`);
    if (list) assert.deepEqual((await report.json() as any).data.map((cipher: any) => cipher.id), [target.id]);
    const response = await request(user.id, `/api/ciphers/${target.id}/admin`);
    assert.equal(response.status, detail ? 200 : 404, `admin access for ${user.id}`);
    if (detail) {
      const body = await response.json() as any;
      assert.equal(body.id, target.id);
      assert.equal(body.object, 'cipherMiniDetails');
      assert.equal(body.login.password, ENCRYPTED_FIELD);
    }
  }
  assert.equal((await request(owner.id, `/api/ciphers/${personal.id}/admin`)).status, 404);
  assert.equal((await request(owner.id, `/api/ciphers/${crypto.randomUUID()}/admin`)).status, 404);
});

test('member list includes only same-org group IDs on includeGroups=true and omits groups by default', async () => {
  const { env, orgId, owner, admin, request } = await setup();
  const { user } = await seedMember(env, orgId);
  const member = (await orgRepo.getMembershipByUserAndOrg(env.DB, user.id, orgId))!;
  const foreign = await seedSmOrg(env);
  const groupIds = [crypto.randomUUID(), crypto.randomUUID(), crypto.randomUUID()];
  const now = new Date().toISOString();
  const orm = getOrm(env.DB);
  await orm.batch([
    orm.insert(orgGroups).values(groupIds.map((id, index) => ({ id, orgId: index === 2 ? foreign.orgId : orgId, name: ENCRYPTED_FIELD, accessAll: 0, createdAt: now, updatedAt: now }))),
    orm.insert(orgGroupMembers).values(groupIds.map(groupId => ({ groupId, membershipId: member.id }))),
  ]);
  const path = `/api/organizations/${orgId}/users`;
  const plain = await request(owner.id, path);
  assert.equal(plain.status, 200);
  assert.ok((await plain.json() as any).data.every((item: any) => !Object.hasOwn(item, 'groups')));
  const included = await request(owner.id, `${path}?includeGroups=true`);
  assert.equal(included.status, 200);
  const body = await included.json() as any;
  assert.deepEqual(new Set(body.data.find((item: any) => item.id === member.id).groups), new Set(groupIds.slice(0, 2)));
  assert.deepEqual(body.data.find((item: any) => item.userId === admin.id).groups, []);
  assert.ok(body.data.every((item: any) => Array.isArray(item.groups) && item.object === 'organizationUserUserDetails'));
  const disabled = await request(owner.id, `${path}?includeGroups=false`);
  assert.ok((await disabled.json() as any).data.every((item: any) => !Object.hasOwn(item, 'groups')));
});

test('a report-only Custom member can load V2 report dependencies without gaining collection or cipher management', async () => {
  const { env, orgId, owner, collection, target, request } = await setup();
  const { user: reporter } = await seedMember(env, orgId, { type: MembershipType.Custom, permissions: { accessReports: true } });
  const { user: ordinary } = await seedMember(env, orgId);
  const ownerMember = (await orgRepo.getMembershipByUserAndOrg(env.DB, owner.id, orgId))!;
  const group = await postJson<{ id: string }>(env, owner, `/api/organizations/${orgId}/groups`, { name: ENCRYPTED_FIELD, users: [ownerMember.id] });
  await orgRepo.replaceCollectionAccess(env.DB, collection.id, {
    users: [{ member: ownerMember, readOnly: false, hidePasswords: false, manage: true }],
    groups: [{ groupId: group.id, readOnly: true, hidePasswords: false, manage: false }],
  });
  const orgPath = `/api/organizations/${orgId}`;
  const collections = await request(reporter.id, `${orgPath}/collections/details`);
  assert.equal(collections.status, 200);
  const metadata = (await collections.json() as any).data.find((item: any) => item.id === collection.id);
  assert.ok(metadata);
  assert.equal(metadata.object, 'collectionAccessDetails');
  assert.equal(metadata.assigned, false);
  assert.equal(metadata.manage, false);
  assert.deepEqual(metadata.users.map((item: any) => item.id), [ownerMember.id]);
  assert.deepEqual(metadata.groups.map((item: any) => item.id), [group.id]);
  const users = await request(reporter.id, `${orgPath}/users?includeGroups=true`);
  assert.equal(users.status, 200);
  assert.deepEqual((await users.json() as any).data.find((item: any) => item.id === ownerMember.id).groups, [group.id]);
  const groups = await request(reporter.id, `${orgPath}/groups`);
  assert.equal(groups.status, 200);
  assert.deepEqual((await groups.json() as any).data.map((item: any) => item.id), [group.id]);
  assert.equal((await request(reporter.id, `/api/ciphers/organization-details?organizationId=${orgId}&includeMemberItems=true`)).status, 200);
  assert.equal((await request(reporter.id, `${orgPath}/collections/${collection.id}/details`)).status, 404);
  assert.equal((await request(reporter.id, `${orgPath}/collections/${collection.id}/users`)).status, 404);
  assert.equal((await authedFetch(env, { userId: reporter.id, path: `${orgPath}/collections/${collection.id}`, method: 'PUT', body: { name: ENCRYPTED_FIELD, users: [], groups: [] } })).status, 404);
  assert.equal((await request(reporter.id, `${orgPath}/users/${ownerMember.id}?includeGroups=true`)).status, 403);
  assert.equal((await request(reporter.id, `/api/ciphers/${target.id}/admin`)).status, 404);
  assert.deepEqual((await (await request(ordinary.id, `${orgPath}/collections/details`)).json() as any).data, []);
});
