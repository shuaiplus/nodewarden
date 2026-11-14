import assert from 'node:assert/strict';
import test from 'node:test';

import {
  isEncryptedFieldUnresolved,
  hasUnresolvedCipherData,
} from '../webapp/src/hooks/useVaultSendActions';
import {
  isResolvedEncryptedField,
  hasUnresolvedEncryptedFields,
} from '../webapp/src/lib/api/vault';
import type { Cipher } from '../webapp/src/lib/types';

const VALID_ENC = '2.v13fK+485/n5q5PZgQh41w==|z1qX/q9aQ8s148Vp|9c4JvA90v+485/n5q5PZgQh41w==';

test('isEncryptedFieldUnresolved treats decrypted empty string as resolved', () => {
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, ''), false);
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, '   '), false);
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, 'Mastercard'), false);
  assert.equal(isEncryptedFieldUnresolved(null, ''), false);
  assert.equal(isEncryptedFieldUnresolved('', ''), false);
});

test('isEncryptedFieldUnresolved flags unreadable cipher string or missing decrypted', () => {
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, VALID_ENC), true);
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, null), true);
  assert.equal(isEncryptedFieldUnresolved(VALID_ENC, undefined), true);
});

test('hasUnresolvedCipherData and hasUnresolvedEncryptedFields permit card with valid empty fields (e.g. only brand set)', () => {
  const cardCipher: Cipher = {
    id: 'test-card-1',
    type: 3,
    name: VALID_ENC,
    decName: '2233 Card',
    card: {
      cardholderName: VALID_ENC,
      decCardholderName: '',
      number: VALID_ENC,
      decNumber: '',
      brand: VALID_ENC,
      decBrand: 'Mastercard',
      expMonth: VALID_ENC,
      decExpMonth: '',
      expYear: VALID_ENC,
      decExpYear: '',
      code: VALID_ENC,
      decCode: '',
    },
  };
  assert.equal(hasUnresolvedCipherData(cardCipher), false);
  assert.equal(hasUnresolvedEncryptedFields(cardCipher), false);
});

test('hasUnresolvedCipherData and hasUnresolvedEncryptedFields catch genuine failure when item name or cipher fails decryption', () => {
  const failedNameCipher: Cipher = {
    id: 'test-card-2',
    type: 3,
    name: VALID_ENC,
    decName: '',
  };
  assert.equal(hasUnresolvedCipherData(failedNameCipher), true);
  assert.equal(hasUnresolvedEncryptedFields(failedNameCipher), true);

  const explicitlyUnresolvedCipher: Cipher = {
    id: 'test-card-3',
    type: 3,
    name: VALID_ENC,
    decName: 'Valid Name',
    unresolved: true,
  };
  assert.equal(hasUnresolvedCipherData(explicitlyUnresolvedCipher), true);
  assert.equal(hasUnresolvedEncryptedFields(explicitlyUnresolvedCipher), true);
});

test('isResolvedEncryptedField treats decrypted empty string as resolved', () => {
  assert.equal(isResolvedEncryptedField(VALID_ENC, ''), true);
  assert.equal(isResolvedEncryptedField(VALID_ENC, 'Mastercard'), true);
  assert.equal(isResolvedEncryptedField(VALID_ENC, VALID_ENC), false);
  assert.equal(isResolvedEncryptedField(VALID_ENC, null), false);
});
