import assert from 'node:assert/strict';
import test from 'node:test';

// ─── Org crypto: OAEP wrap/unwrap round-trip ────────────────────────────────
// Official Bitwarden clients wrap org keys with RSA-OAEP SHA-1 (despite the
// "Rsa2048_OaepSha256_B64" type name — a well-known Bitwarden quirk). These
// tests verify the SHA-1 wrap unwraps via SHA-1 and that the SHA-256
// fallback works for legacy wraps.

test('org key SHA-1 OAEP round-trip recovers the original key', async () => {
  const { generateOrganizationKeyBytes, orgKeyBytesToParts, generateOrganizationKeyPair,
          wrapOrganizationKeyForUser, unwrapOrganizationKeyDetailed } =
    await import('../webapp/src/lib/org-crypto');
  const { bytesToBase64 } = await import('../webapp/src/lib/crypto');

  // Generate a 64-byte org key
  const orgKey = generateOrganizationKeyBytes();
  assert.equal(orgKey.length, 64, 'org key is 64 bytes');

  // Generate the user's RSA keypair
  const keyPair = await generateOrganizationKeyPair(orgKeyBytesToParts(orgKey));
  assert.ok(keyPair.publicKeyB64, 'public key');
  assert.ok(keyPair.encryptedPrivateKey, 'encrypted private key');

  // Wrap the org key with the user's public key (SHA-1 OAEP)
  const wrapped = await wrapOrganizationKeyForUser(orgKey, keyPair.publicKeyB64);
  assert.ok(wrapped.startsWith('4.'), 'wrapped key is a type-4 EncString');

  // Decrypt the private key (org-key encrypted)
  const { decryptBw } = await import('../webapp/src/lib/crypto');
  const parts = orgKeyBytesToParts(orgKey);
  const pkcs8 = await decryptBw(keyPair.encryptedPrivateKey, parts.encBytes, parts.macBytes);
  assert.ok(pkcs8.length > 800, 'RSA private key is meaningful size');

  // Unwrap the org key with the private key
  const unwrapped = await unwrapOrganizationKeyDetailed('test-org', wrapped, pkcs8);
  assert.ok(unwrapped, 'unwrap succeeded');
  assert.equal(bytesToBase64(unwrapped.raw), bytesToBase64(orgKey), 'round-trip recovers exact key');
  assert.equal(unwrapped.legacySha256Wrap, false, 'SHA-1 wrap is not legacy');
});

test('org key SHA-256 OAEP wrap unwraps via fallback (legacy migration path)', async () => {
  const { generateOrganizationKeyBytes, orgKeyBytesToParts, generateOrganizationKeyPair,
          unwrapOrganizationKeyDetailed } =
    await import('../webapp/src/lib/org-crypto');
  const { bytesToBase64, base64ToBytes } = await import('../webapp/src/lib/crypto');

  const orgKey = generateOrganizationKeyBytes();
  const keyPair = await generateOrganizationKeyPair(orgKeyBytesToParts(orgKey));

  // Manually wrap with SHA-256 (simulating a legacy NodeWarden wrap)
  const subtle = globalThis.crypto.subtle;
  const pubKey = await subtle.importKey(
    'spki',
    base64ToBytes(keyPair.publicKeyB64),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
  const wrappedBytes = new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, orgKey));
  const legacyWrapped = `4.${bytesToBase64(wrappedBytes)}`;

  // Decrypt the private key
  const { decryptBw } = await import('../webapp/src/lib/crypto');
  const parts = orgKeyBytesToParts(orgKey);
  const pkcs8 = await decryptBw(keyPair.encryptedPrivateKey, parts.encBytes, parts.macBytes);

  // Unwrap via the detailed path (tries SHA-1 first, then SHA-256)
  const unwrapped = await unwrapOrganizationKeyDetailed('test-org', legacyWrapped, pkcs8);
  assert.ok(unwrapped, 'legacy SHA-256 wrap unwraps');
  assert.equal(bytesToBase64(unwrapped.raw), bytesToBase64(orgKey), 'key recovered');
  assert.equal(unwrapped.legacySha256Wrap, true, 'flagged as legacy SHA-256 wrap');
});

test('legacy SHA-256 wrap repairs into a SHA-1 wrap (repair flow round-trip)', async () => {
  // Mirrors webapp/src/lib/org-key-repair.ts: detect the legacy wrap via the
  // detailed unwrap, re-wrap with the official SHA-1 hash, and verify the
  // repaired wrap no longer reports legacy and still decrypts to the same
  // org key material.
  const { generateOrganizationKeyBytes, orgKeyBytesToParts, generateOrganizationKeyPair,
          unwrapOrganizationKeyDetailed, wrapOrganizationKeyForUser } =
    await import('../webapp/src/lib/org-crypto');
  const { bytesToBase64, base64ToBytes, decryptBw } = await import('../webapp/src/lib/crypto');

  const orgKey = generateOrganizationKeyBytes();
  const keyPair = await generateOrganizationKeyPair(orgKeyBytesToParts(orgKey));

  // Legacy wrap: RSA-OAEP SHA-256 (pre-2026-09 webapp behavior)
  const subtle = globalThis.crypto.subtle;
  const pubKey = await subtle.importKey(
    'spki',
    base64ToBytes(keyPair.publicKeyB64),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt']
  );
  const legacyWrapped = `4.${bytesToBase64(new Uint8Array(await subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, orgKey)))}`;

  const parts = orgKeyBytesToParts(orgKey);
  const pkcs8 = await decryptBw(keyPair.encryptedPrivateKey, parts.encBytes, parts.macBytes);

  // Detection: the repair flow sees the legacy flag on the member's own row
  const before = await unwrapOrganizationKeyDetailed('repair-org', legacyWrapped, pkcs8);
  assert.ok(before, 'legacy wrap unwraps via fallback');
  assert.equal(before.legacySha256Wrap, true, 'detected as legacy SHA-256 wrap');

  // Repair: re-wrap the org key with the official SHA-1 hash
  const repairedWrap = await wrapOrganizationKeyForUser(before.raw, keyPair.publicKeyB64);
  assert.ok(repairedWrap.startsWith('4.'), 'repaired wrap is a type-4 EncString');

  const after = await unwrapOrganizationKeyDetailed('repair-org', repairedWrap, pkcs8);
  assert.ok(after, 'repaired wrap unwraps with SHA-1 first (no fallback needed)');
  assert.equal(after.legacySha256Wrap, false, 'repaired wrap is not legacy');
  assert.equal(bytesToBase64(after.raw), bytesToBase64(orgKey), 'same org key material after repair');
});

test('org key split into enc/mac parts correctly', async () => {
  const { orgKeyBytesToParts } = await import('../webapp/src/lib/org-crypto');
  const { bytesToBase64 } = await import('../webapp/src/lib/crypto');

  const raw = new Uint8Array(64);
  for (let i = 0; i < 64; i++) raw[i] = i;
  const parts = orgKeyBytesToParts(raw);

  assert.equal(parts.encBytes.length, 32, 'enc half is 32 bytes');
  assert.equal(parts.macBytes.length, 32, 'mac half is 32 bytes');
  assert.equal(bytesToBase64(parts.encBytes), bytesToBase64(raw.slice(0, 32)));
  assert.equal(bytesToBase64(parts.macBytes), bytesToBase64(raw.slice(32, 64)));
});

test('looksLikeEncString distinguishes legacy encrypted org names from plaintext', async () => {
  const { looksLikeEncString, encryptBw } = await import('../webapp/src/lib/crypto');
  const { generateOrganizationKeyBytes, orgKeyBytesToParts } =
    await import('../webapp/src/lib/org-crypto');

  // A real type-2 EncString (what legacy org names were stored as)
  const parts = orgKeyBytesToParts(generateOrganizationKeyBytes());
  const encName = await encryptBw(new TextEncoder().encode('Family'), parts.encBytes, parts.macBytes);
  assert.equal(looksLikeEncString(encName), true, 'type-2 EncString is detected');

  // Plaintext names, including digit-dot forms, must render as themselves
  assert.equal(looksLikeEncString('Family'), false, 'plain name');
  assert.equal(looksLikeEncString('1. Acme Corp'), false, 'numbered name with spaces');
  assert.equal(looksLikeEncString('2.Q3 budget'), false, 'digit-dot name, no pipe-separated base64 body');
  assert.equal(looksLikeEncString('2026. Plans'), false, 'year-dot name');
  assert.equal(looksLikeEncString(''), false, 'empty');
  assert.equal(looksLikeEncString(null), false, 'null');
  assert.equal(looksLikeEncString(undefined), false, 'undefined');
});

test('unwrapOrganizationKeyDetailed returns null for invalid format', async () => {
  const { unwrapOrganizationKeyDetailed } = await import('../webapp/src/lib/org-crypto');

  const pkcs8 = new Uint8Array(100);
  const result = await unwrapOrganizationKeyDetailed('org', 'not-an-encstring', pkcs8);
  assert.equal(result, null, 'invalid format returns null');

  const result2 = await unwrapOrganizationKeyDetailed('org', '2.something|else|here', pkcs8);
  assert.equal(result2, null, 'wrong encstring type returns null');

  const result3 = await unwrapOrganizationKeyDetailed('org', null, pkcs8);
  assert.equal(result3, null, 'null key returns null');
});
