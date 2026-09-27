import assert from 'node:assert/strict';
import test from 'node:test';

import { argon2id } from '@noble/hashes/argon2.js';
import { sha256 } from '@noble/hashes/sha2.js';

import {
  base64ToBytes,
  bytesToBase64,
  decryptBw,
  decryptBwFileData,
  decryptStr,
  deriveKdfMaterial,
  encryptBw,
  encryptBwFileData,
  encryptBwRsa,
  pbkdf2,
} from '../webapp/src/lib/crypto';
import { unwrapOrgKey } from '../webapp/src/lib/org-crypto';

// Produced by the hand-rolled WebCrypto implementation the SDK adapters replaced: data written by
// earlier webapp versions must keep opening.
const LEGACY = {
  key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+Pw==',
  plaintext: 'correct horse ✓',
  encString: '2.YEPNP9oT0lNdgN0DbKdi/g==|k8NVn9pXW2c50FbyirHeFWPC1evthwUuzF1kk4fX0LU=|syjUGW8v8BTpFlLkNn4mplG21nCAISysrKhC7uzp7DM=',
  filePlaintext: 'attachment bytes',
  fileData: 'AlRLDUEuBsGGNXQuPslN3Yeo+dvqDr73mit9sxlV2abd2D71YqzHKe8bE1HOUiyKQ3IepYiv9ovzpGRowG+d7hCzwhvA4/VdinwNoXDYJgSI',
  // Test-only RSA-2048 key; the vault key above wrapped for it as type 4 (RSA-OAEP SHA-1).
  rsaPrivateKey: [
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCa+5z6ZA0nC1s+H1pYlDHNfleVGUK+rejbcMaXNVrFK9iU',
    'M2b1lrWQuOLxniIFNZpqJaqpkyagrlx9jvPCJy187FsFioKErUcECx85WM3UI0vOvdzQoi/Uj8eHh7L66As8TDgV2gO/fmoY',
    'CXGwypZDnX9Mp5EQbxUp0j03GvIDArjPUgBGlf9lfC97trdI3T8btAZ4zLO9y9j4P2acsqwvnNjXQ3seVJGh1MJ2tZuWseHr',
    'm2uzd/xg5hyja7ZbY8W0epPXLGl5UWoMXd1V/T3Ce+CHPnjXXc/oKXkujs6xbCGEtWAWkXggaXwVJ+qLVfNO37FHAfg35n59',
    'xokIe0m9AgMBAAECggEAByvaXSmxBBv96ld4Dj45Obl9YvxKvtj8O98xiUCiRRpcyKrCOl3xY9NySNzY1SXgUcYRagxRjsDS',
    'rcqmE9dNPwkOwyhgFrSP4yuCk9w8lfLWKKhXZd4DWZIXmPlZ+ksvbehW9gfjAYLfdOJG/Pe60UEh6VGdoEWLlKZSR9D63tG4',
    'fJhhDTkeGbRVm604B0506RJcIZsXwH7c1oq6abTEd7HnQDfSFoJryhBgtyu2t5ESqeF730DFPKRQmjU4+ST2h20nlzrdmoGF',
    '8hl4XwOcXqGKLMoadtlKXj0jKAmA3SsWnOaDtBXP+uwd9t1BjkTGeE44rWCJWHJvrjXlAw9Y8QKBgQDLBV1G2sWKU0DbPJAQ',
    'jxBatyTtcBqpumPmyv81/asgvWCD7II8N7q4YbRrqxqpnlCM1SO0BLBr7T/UMarTHguOtyqxECCAIH5kAaVvPUCNELmKBb57',
    'zQOJ/Olsr+39lNkc6hIxcBnQm6Y8zx9/f/W5nncYbCniGl5UNHATkMNYpQKBgQDDbRtKkhV8DQDXul/0TfTja2qRzEZf/IQn',
    '6tmKXSrmymE6MC7sDt4z4BX5YcADt3rZgKdvW6g+6R0qjuSKD/mREt2U05Yef9t4NTt+IzTexEEmvT62Fymr+pJdsNgI+3x0',
    'VVGf+V2Fb5C7abkypo1I63xPccRQSANSSeFPGmfJOQKBgQCYANAxuKKmSmcIvnNusm6gPPdc/s43veIGbn5eQiraPHAC1hU8',
    'WM1oN18KLfWsgWf1ya8NnWUpqVxc10L7BkfI9sL0BwsOY0W+Qq1GeCnYdGk2Oc7AimLX8ZAjXCVn8wYLbAVrFm99jMwOQ1Vl',
    '9LxZ2Zd5paJGM0/k4832GDDqMQKBgAeZ1cbnuagyhUbeu96vrYeu5N042b/f/W/kBYQJLaL+Whu+RgTuaxwPaith7ur2FvQg',
    'ueJt6TRRMs418pOgHW/UEQQ52ovjIzEguOimC+diMLqF/8trSTakL08vkqd+yI9pxhv3wfhvp2xypz5eFf6xEguw/Ba3RlHM',
    'B9RgzYqZAoGAcV+BKUAkQgu9sPQLMZysJXHOCESa5UXVWc6SWrXLzOv0wrL705N/PP/1la3VGy57SBR+PZhIPUFrkU7eG+3H',
    'esetSwuc8VMJ81ntbz0EFUr1iFzYfbP4tfIUvZdTnM/rFJfelzjirWlufxeeludrwMfLnHUWNWThXpUJSU5L6w8=',
  ].join(''),
  rsaWrappedKey: [
    '4.F6JD+sfbNslBfmUggIxp/TADu3GoFJMiFGDldbelUEB/zuO+LLnMTOFZDG1KkpaRho4aO9BKyhd2HbjmUdcrE0aTIIpmHF',
    '2AHw8eaMSIw32B0Wj0r+VRG7MMhnNtrjXa6smGoZ3b7ZY7zt9alHNQFuzgt3v2oX/wZyveaU6aLpHBPNj9ISSMg0OtX1QHSl',
    'peHw14z/rpLGFQLUP6NfjEL036B/2s9VSf5yyppUdjXub+hxNZPFy+YWvtHbTImeCnirfT3hDc51QEcR4XVww7LTU44JGeNQ',
    'qhqjcuyDK2LFAPwP2SnrFswcRaXmFukl9vHHBR0Ne0o44WW4zw96zG8g==',
  ].join(''),
};

const SYMMETRIC_KEY_HALF_BYTES = 32;
const HMAC_SHA256_BYTES = 32;
const key = base64ToBytes(LEGACY.key);
const encKey = key.slice(0, SYMMETRIC_KEY_HALF_BYTES);
const macKey = key.slice(SYMMETRIC_KEY_HALF_BYTES);
const encoder = new TextEncoder();

test('SDK adapters open legacy EncStrings and round-trip new type 2 ones', async () => {
  assert.equal(await decryptStr(LEGACY.encString, encKey, macKey), LEGACY.plaintext);

  const encrypted = await encryptBw(encoder.encode(LEGACY.plaintext), encKey, macKey);
  assert.match(encrypted, /^2\.[^|]+\|[^|]+\|[^|]+$/);
  assert.notEqual(encrypted, LEGACY.encString);
  assert.equal(await decryptStr(encrypted, encKey, macKey), LEGACY.plaintext);
  assert.equal(await decryptStr(null, encKey, macKey), '');

  const zeroMac = bytesToBase64(new Uint8Array(HMAC_SHA256_BYTES));
  const tampered = `${LEGACY.encString.slice(0, LEGACY.encString.lastIndexOf('|'))}|${zeroMac}`;
  await assert.rejects(decryptBw(tampered, encKey, macKey));
  await assert.rejects(decryptBw(LEGACY.encString, macKey, encKey));
});

test('SDK adapters open legacy attachment file data and round-trip new ones', async () => {
  assert.equal(new TextDecoder().decode(await decryptBwFileData(base64ToBytes(LEGACY.fileData), encKey, macKey)), LEGACY.filePlaintext);

  const encrypted = await encryptBwFileData(encoder.encode(LEGACY.filePlaintext), encKey, macKey);
  assert.equal(encrypted[0], 2);
  assert.equal(new TextDecoder().decode(await decryptBwFileData(encrypted, encKey, macKey)), LEGACY.filePlaintext);
});

test('type 4 key wrapping interoperates with the legacy wrap and the account private key unwrap', async () => {
  const session = { symEncKey: bytesToBase64(encKey), symMacKey: bytesToBase64(macKey) };
  const encryptedPrivateKey = await encryptBw(base64ToBytes(LEGACY.rsaPrivateKey), encKey, macKey);
  assert.deepEqual(await unwrapOrgKey(session, LEGACY.rsaWrappedKey, encryptedPrivateKey), { encKey, macKey });

  const privateKey = await crypto.subtle.importKey('pkcs8', base64ToBytes(LEGACY.rsaPrivateKey), { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['decrypt']);
  const { n, e } = await crypto.subtle.exportKey('jwk', privateKey);
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n, e, alg: 'RSA-OAEP' }, { name: 'RSA-OAEP', hash: 'SHA-1' }, true, ['encrypt']);
  const wrapped = await encryptBwRsa(key, bytesToBase64(new Uint8Array(await crypto.subtle.exportKey('spki', publicKey))));
  assert.match(wrapped, /^4\.[A-Za-z0-9+/]+=*$/);
  assert.deepEqual(await unwrapOrgKey(session, wrapped, encryptedPrivateKey), { encKey, macKey });
});

test('SDK KDF matches WebCrypto PBKDF2 and hashes the Argon2id salt like official clients', async () => {
  const password = 'correct horse battery staple';
  const salt = 'user@example.test';
  const iterations = 5000;
  assert.deepEqual(await deriveKdfMaterial(password, salt, { pBKDF2: { iterations } }), await pbkdf2(password, salt, iterations, SYMMETRIC_KEY_HALF_BYTES));

  const argon = { iterations: 2, memory: 16, parallelism: 1 };
  const kibPerMib = 1024;
  assert.deepEqual(
    await deriveKdfMaterial(password, salt, { argon2id: argon }),
    argon2id(encoder.encode(password), sha256(encoder.encode(salt)), { t: argon.iterations, m: argon.memory * kibPerMib, p: argon.parallelism, dkLen: SYMMETRIC_KEY_HALF_BYTES })
  );
  await assert.rejects(deriveKdfMaterial(password, salt, { pBKDF2: { iterations: 1 } }));
});
