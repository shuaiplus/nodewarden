import assert from 'node:assert/strict';
import test from 'node:test';

import { D1_MAX_BOUND_PARAMETERS, getOrm, userRowMatches } from '../db/client';
import { MembershipStatus, MembershipType } from '../services/org-types';
import * as cipherRepo from '../services/storage-cipher-repo';
import * as orgRepo from '../services/storage-org-repo';
import type { Cipher, Env } from '../types';
import { createTestEnv, seedUser } from './support/env';
import { seedMember, seedMembership } from './support/sm';

const PAST = '2020-01-01T00:00:00.000Z';
// One more id than a statement can bind, so every bulk writer has to chunk.
const MANY_CIPHER_COUNT = D1_MAX_BOUND_PARAMETERS + 1;

function cipher(id: string, userId: string, organizationId: string | null, name: string): Cipher {
  return {
    id,
    userId,
    organizationId,
    name,
    type: 1,
    folderId: null,
    notes: null,
    favorite: false,
    login: null,
    card: null,
    identity: null,
    secureNote: null,
    sshKey: null,
    fields: null,
    passwordHistory: null,
    reprompt: 0,
    key: null,
    createdAt: PAST,
    updatedAt: PAST,
    archivedAt: null,
    deletedAt: null,
  };
}

async function insertOrganization(env: Env): Promise<string> {
  const id = crypto.randomUUID();
  await orgRepo.insertOrganization(env.DB, {
    id,
    name: 'Org',
    billingEmail: 'billing@example.test',
    identifier: null,
    privateKey: null,
    publicKey: null,
    createdAt: PAST,
    updatedAt: PAST,
  });
  return id;
}

// Handlers authorize before saving; this guard is what stops a colliding id from taking over someone else's row.
test("a colliding cipher upsert overwrites only its own user's row or a row already in the incoming organization", async () => {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const intruder = await seedUser(env);
  const personalId = crypto.randomUUID();
  const orgItemId = crypto.randomUUID();
  await cipherRepo.saveCipher(env.DB, cipher(personalId, owner.id, null, 'personal'));
  await cipherRepo.saveCipher(env.DB, cipher(orgItemId, owner.id, 'org-a', 'org item'));
  const stored = async (id: string) => {
    const row = await cipherRepo.getCipher(env.DB, id);
    return [row?.userId, row?.organizationId, row?.name];
  };

  const refused = [
    [personalId, null],
    [personalId, 'org-a'],
    [orgItemId, 'org-b'],
    [orgItemId, null],
  ] as const;
  for (const [index, [id, organizationId]] of refused.entries()) {
    await cipherRepo.saveCipher(env.DB, cipher(id, intruder.id, organizationId, `overwrite ${index}`));
  }
  assert.deepEqual(await stored(personalId), [owner.id, null, 'personal']);
  assert.deepEqual(await stored(orgItemId), [owner.id, 'org-a', 'org item']);

  await cipherRepo.saveCipher(env.DB, cipher(orgItemId, intruder.id, 'org-a', 'org edit'));
  await cipherRepo.saveCipher(env.DB, cipher(personalId, owner.id, null, 'own edit'));
  assert.deepEqual(await stored(orgItemId), [owner.id, 'org-a', 'org edit']);
  assert.deepEqual(await stored(personalId), [owner.id, null, 'own edit']);
});

test('org items pass to the oldest other confirmed Owner of their own org, else its oldest confirmed member, ties by membership id', async () => {
  const env = await createTestEnv();
  const departing = await seedUser(env);
  const ownersOrg = await insertOrganization(env);
  const membersOrg = await insertOrganization(env);
  const member = async (
    orgId: string,
    type: number,
    createdAt: string,
    fields: { id?: string; status?: number } = {},
  ) => (await seedMember(env, orgId, { type, createdAt, updatedAt: createdAt, ...fields })).user.id;
  // The departing user is the oldest Owner of both orgs, so only excluding them keeps them from inheriting.
  for (const orgId of [ownersOrg, membersOrg]) {
    await seedMembership(env, orgId, {
      userId: departing.id,
      type: MembershipType.Owner,
      createdAt: '2000-01-01T00:00:00.000Z',
    });
  }
  await member(ownersOrg, MembershipType.Owner, '2001-01-01T00:00:00.000Z', { status: MembershipStatus.Accepted });
  await member(ownersOrg, MembershipType.Admin, '2002-01-01T00:00:00.000Z');
  const tiedOwner = await member(ownersOrg, MembershipType.Owner, '2005-01-01T00:00:00.000Z', { id: 'membership-b' });
  const ownerHeir = await member(ownersOrg, MembershipType.Owner, '2005-01-01T00:00:00.000Z', { id: 'membership-a' });
  await member(ownersOrg, MembershipType.Owner, '2010-01-01T00:00:00.000Z');
  await member(membersOrg, MembershipType.User, '2003-01-01T00:00:00.000Z', { status: MembershipStatus.Revoked });
  const memberHeir = await member(membersOrg, MembershipType.User, '2004-01-01T00:00:00.000Z');
  await member(membersOrg, MembershipType.Admin, '2006-01-01T00:00:00.000Z');
  const items = {
    [ownersOrg]: [departing.id, ownersOrg],
    [membersOrg]: [departing.id, membersOrg],
    personal: [departing.id, null],
    othersItem: [tiedOwner, ownersOrg],
  } as const;
  for (const [id, [userId, organizationId]] of Object.entries(items)) {
    await cipherRepo.saveCipher(env.DB, cipher(id, userId, organizationId, id));
  }

  await cipherRepo.reassignOrganizationCiphers(env.DB, departing.id, userRowMatches(getOrm(env.DB), departing.id));

  const owners = await Promise.all(
    Object.keys(items).map(async (id) => (await cipherRepo.getCipher(env.DB, id))?.userId),
  );
  assert.deepEqual(owners, [ownerHeir, memberHeir, departing.id, tiedOwner]);
});

test('bulk cipher writers chunk more ids than one statement can bind', async () => {
  const env = await createTestEnv();
  const user = await seedUser(env);
  const ids = Array.from({ length: MANY_CIPHER_COUNT }, () => crypto.randomUUID());
  for (const id of ids) await cipherRepo.saveCipher(env.DB, cipher(id, user.id, null, 'item'));
  const states = async () =>
    (await cipherRepo.getCiphersByIds(env.DB, ids, user.id)).map(({ deletedAt, archivedAt, folderId }) => [
      Boolean(deletedAt),
      Boolean(archivedAt),
      folderId,
    ]);
  const everyCipher = (state: unknown[]) => ids.map(() => state);

  await cipherRepo.bulkSoftDeleteCiphers(env.DB, ids, user.id);
  assert.deepEqual(await states(), everyCipher([true, false, null]));
  await cipherRepo.bulkRestoreCiphers(env.DB, ids, user.id);
  assert.deepEqual(await states(), everyCipher([false, false, null]));
  await cipherRepo.bulkArchiveCiphers(env.DB, ids, user.id);
  assert.deepEqual(await states(), everyCipher([false, true, null]));
  await cipherRepo.bulkUnarchiveCiphers(env.DB, ids, user.id);
  assert.deepEqual(await states(), everyCipher([false, false, null]));
  await cipherRepo.bulkMoveCiphers(env.DB, ids, 'folder', user.id);
  assert.deepEqual(await states(), everyCipher([false, false, 'folder']));
});
