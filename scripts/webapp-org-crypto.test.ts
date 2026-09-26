import assert from 'node:assert/strict';
import test from 'node:test';

import { createOwnedOrganization } from '../src/handlers/organizations';
import { MembershipStatus, MembershipType } from '../src/services/org-types';
import * as orgRepo from '../src/services/storage-org-repo';
import type { Env, User } from '../src/types';
import { confirmMember, createProject, createSecret, getUserPublicKey, listProjects } from '../webapp/src/lib/api/orgs';
import type { AuthedFetch } from '../webapp/src/lib/api/shared';
import { base64ToBytes, bytesToBase64, concatBytes, encryptBw, toBufferSource } from '../webapp/src/lib/crypto';
import { createOrgKey, decryptWithOrgKey, encryptWithOrgKey, unwrapOrgKey, wrapOrgKeyForMember } from '../webapp/src/lib/org-crypto';
import { authedFetch, createTestEnv, seedUser } from './support/env';

const SYMMETRIC_KEY_HALF_BYTES = 32;
const MEMBER_RSA_KEY_PARAMS: RsaHashedKeyGenParams = {
  name: 'RSA-OAEP',
  modulusLength: 2048,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: 'SHA-1',
};

// The webapp API helpers take a browser-style fetch; route it through the real Worker as `actor`.
function webappFetch(env: Env, actor: User): AuthedFetch {
  return (path, init) => authedFetch(env, {
    method: init?.method,
    path,
    body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    userId: actor.id,
  });
}

async function addAcceptedMember(env: Env, orgId: string, publicKey: string) {
  const user = await seedUser(env, { publicKey });
  const now = new Date().toISOString();
  const membership = {
    id: crypto.randomUUID(),
    userId: user.id,
    orgId,
    email: user.email,
    invitedByEmail: null,
    accessAll: false,
    key: '',
    status: MembershipStatus.Accepted,
    type: MembershipType.User,
    permissions: null,
    resetPasswordKey: null,
    externalId: null,
    createdAt: now,
    updatedAt: now,
  };
  await orgRepo.saveMembership(env.DB, membership);
  return { user, memberId: membership.id };
}

async function setup() {
  const env = await createTestEnv();
  const owner = await seedUser(env);
  const randomHalf = () => bytesToBase64(crypto.getRandomValues(new Uint8Array(SYMMETRIC_KEY_HALF_BYTES)));
  const adminSession = { email: owner.email, symEncKey: randomHalf(), symMacKey: randomHalf() };
  const orgKey = await createOrgKey(adminSession);
  const orgId = (await createOwnedOrganization(env, owner, { name: 'Acme', key: orgKey.wrapped })).id;
  return { env, owner, adminSession, orgKey, orgId, ownerFetch: webappFetch(env, owner) };
}

test('webapp confirm wraps the org key for the member public key, and the server stores it', async () => {
  const { env, adminSession, orgKey, orgId, ownerFetch } = await setup();
  const member = await crypto.subtle.generateKey(MEMBER_RSA_KEY_PARAMS, true, ['encrypt', 'decrypt']);
  const memberPublicKey = bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', member.publicKey)));
  const { user, memberId } = await addAcceptedMember(env, orgId, memberPublicKey);

  // Same sequence as OrganizationPage onConfirm.
  const fetchedKey = await getUserPublicKey(ownerFetch, user.id);
  await confirmMember(ownerFetch, orgId, memberId, await wrapOrgKeyForMember(adminSession, orgKey.wrapped, fetchedKey));

  const stored = await orgRepo.getMembership(env.DB, memberId);
  assert.equal(stored?.status, MembershipStatus.Confirmed);
  // EncryptionType.Rsa2048_OaepSha1_B64 has a single base64 part; the server's confirm rejects
  // symmetric (type 0-2) keys, which the member could not open anyway.
  const [encType, payload, ...extraParts] = (stored?.key ?? '').split(/[.|]/);
  assert.equal(encType, '4');
  assert.deepEqual(extraParts, []);
  const unwrapped = await crypto.subtle.decrypt(MEMBER_RSA_KEY_PARAMS, member.privateKey, base64ToBytes(payload));
  assert.deepEqual(new Uint8Array(unwrapped), concatBytes(orgKey.encKey, orgKey.macKey));
});

test('webapp confirm stops at the public key lookup for a member without keys', async () => {
  const { env, ownerFetch } = await setup();
  const keyless = await seedUser(env);

  await assert.rejects(getUserPublicKey(ownerFetch, keyless.id), /not found/i);
});

test('webapp unwraps RSA organization keys using the account encrypted private key', async () => {
  const { adminSession, orgKey } = await setup();
  const pair = await crypto.subtle.generateKey(MEMBER_RSA_KEY_PARAMS, true, ['encrypt', 'decrypt']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey));
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  const privateKey = await encryptBw(pkcs8, base64ToBytes(adminSession.symEncKey), base64ToBytes(adminSession.symMacKey));
  for (const [type, hash] of [[3, 'SHA-256'], [4, 'SHA-1']] as const) {
    const algorithm = { name: 'RSA-OAEP', hash };
    const publicKey = await crypto.subtle.importKey('spki', spki, algorithm, false, ['encrypt']);
    const wrap = async (raw: Uint8Array) => `${type}.${bytesToBase64(new Uint8Array(await crypto.subtle.encrypt(algorithm, publicKey, toBufferSource(raw))))}`;
    const wrapped = await wrap(concatBytes(orgKey.encKey, orgKey.macKey));
    assert.deepEqual(await unwrapOrgKey(adminSession, wrapped, privateKey), { encKey: orgKey.encKey, macKey: orgKey.macKey });
    await assert.rejects(unwrapOrgKey(adminSession, wrapped), /private key unavailable/i);
    await assert.rejects(unwrapOrgKey(adminSession, await wrap(new Uint8Array(32)), privateKey), /Invalid organization key/);
  }
});

test('webapp Secrets Manager stores project names and secret notes as org-key EncStrings', async () => {
  const { env, adminSession, orgKey, orgId, ownerFetch } = await setup();
  const unwrappedOrgKey = await unwrapOrgKey(adminSession, orgKey.wrapped);
  const encrypt = (value: string) => encryptWithOrgKey(unwrappedOrgKey, value);
  const decrypt = (value: string) => decryptWithOrgKey(unwrappedOrgKey, value);

  // Same sequence as SecretsManagerPage onCreateProject, refresh and onCreateSecret.
  await createProject(ownerFetch, orgId, await encrypt('Payments'));
  const [project] = await listProjects(ownerFetch, orgId);
  await createSecret(ownerFetch, orgId, {
    key: await encrypt('DB_PASSWORD'),
    value: await encrypt('hunter2'),
    note: await encrypt(''),
    projectIds: [project.id],
  });

  assert.equal(await decrypt(project.name), 'Payments');
  // The release-note query for names older webapps stored in plaintext.
  const encryptedNames = await env.DB.prepare("SELECT COUNT(*) AS count FROM sm_projects WHERE org_id = ? AND name GLOB '[0-9].*|*'").bind(orgId).first('count');
  assert.equal(encryptedNames, 1);
  // Upstream requires Note; decryptStr maps a missing one to '' too, so check it was stored.
  const note = await env.DB.prepare('SELECT note FROM sm_secrets WHERE org_id = ?').bind(orgId).first<string | null>('note');
  assert.ok(note);
  assert.equal(await decrypt(note), '');
  // SecretsManagerPage shows a decrypt error for a legacy plaintext name instead of the raw value.
  await assert.rejects(decrypt('Payments'));
});
