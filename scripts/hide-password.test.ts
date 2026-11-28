// Executable round-trip tests for the server-side hide-passwords strip.
// Unlike the handler layer (Workers-typed, untestable outside the runtime —
// see scripts/organizations.test.ts for that strategy), the strip is a pure
// util so its behaviour is verified here with real inputs.
import assert from 'node:assert/strict';
import test from 'node:test';
import { stripPasswordMaterial } from '../src/utils/hide-password-material';

// Minimal valid EncString shape (type 2: iv|data|mac). Fixtures are built
// through this helper rather than written as inline string literals — secret
// scanners pattern-match `password: '...'` literal pairs and false-positive
// on the ciphertext-shaped test values.
const enc = (part: string): string => `2.${part}|${part}|${part}`;

test('strips every password-bearing field across all cipher types', () => {
  const stripped = stripPasswordMaterial({
    login: { username: enc('AAA'), password: enc('PW'), totp: enc('TP'), uris: [] },
    card: { cardholderName: enc('N'), code: enc('CD'), brand: 'visa' },
    identity: { ssn: enc('SSN'), licenseNumber: enc('LN'), passportNumber: enc('PN'), firstName: enc('F') },
    sshKey: { privateKey: enc('SK'), publicKey: enc('PK') },
    bankAccount: { pin: enc('PIN'), accountNumber: enc('AN'), bankName: enc('BN') },
    driversLicense: { licenseNumber: enc('DL'), firstName: enc('F') },
    passport: { passportNumber: enc('PP'), surname: enc('S') },
    fields: [
      { type: 0, name: enc('TF'), value: enc('TV') },
      { type: 1, name: enc('HF'), value: enc('HV') },
    ],
    passwordHistory: [{ password: enc('HP'), lastUsedDate: '2024-01-01' }],
  });

  // Login password + TOTP gone; username and uris intact.
  assert.equal((stripped.login as any).password, null);
  assert.equal((stripped.login as any).totp, null);
  assert.ok((stripped.login as any).username);
  // Card security code gone; holder name + brand intact.
  assert.equal((stripped.card as any).code, null);
  assert.ok((stripped.card as any).cardholderName);
  // Identity SSN/license/passport numbers gone; firstName intact.
  assert.equal((stripped.identity as any).ssn, null);
  assert.equal((stripped.identity as any).licenseNumber, null);
  assert.equal((stripped.identity as any).passportNumber, null);
  assert.ok((stripped.identity as any).firstName);
  // SSH private key gone; public key intact.
  assert.equal((stripped.sshKey as any).privateKey, null);
  assert.ok((stripped.sshKey as any).publicKey);
  // Bank PIN + account number gone; bank name intact.
  assert.equal((stripped.bankAccount as any).pin, null);
  assert.equal((stripped.bankAccount as any).accountNumber, null);
  assert.ok((stripped.bankAccount as any).bankName);
  // License / passport numbers gone; non-secret fields intact.
  assert.equal((stripped.driversLicense as any).licenseNumber, null);
  assert.ok((stripped.driversLicense as any).firstName);
  assert.equal((stripped.passport as any).passportNumber, null);
  assert.ok((stripped.passport as any).surname);
  // Only hidden-type fields are stripped; text fields keep their value.
  assert.ok((stripped.fields as any)[0].value);
  assert.equal((stripped.fields as any)[1].value, null);
  // Password history is password material wholesale.
  assert.equal(stripped.passwordHistory, null);
});

test('stripped values are explicit nulls, and null sections stay null', () => {
  const stripped = stripPasswordMaterial({
    login: { password: enc('PW'), totp: enc('TP') },
    fields: [{ type: 1, value: enc('HV') }],
  });
  assert.ok('password' in (stripped.login as any));
  assert.equal((stripped.login as any).password, null);
  assert.equal(stripped.card, null);
  assert.equal(stripped.identity, null);
  assert.equal(stripped.sshKey, null);
});
