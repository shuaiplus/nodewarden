import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseGoogleAuthenticatorMigrationPage,
  type GoogleAuthenticatorMigrationPage,
} from '../webapp/src/lib/google-authenticator-migration';
import { normalizeTotpInput } from '../webapp/src/lib/crypto';
import { decodeSingleQrCode } from '../webapp/src/lib/qr-code';

function encodeVarint(value: number): number[] {
  const bytes: number[] = [];
  let remaining = value >>> 0;
  do {
    const byte = remaining & 0x7f;
    remaining >>>= 7;
    bytes.push(remaining ? byte | 0x80 : byte);
  } while (remaining);
  return bytes;
}

function fieldVarint(number: number, value: number): number[] {
  return [...encodeVarint(number << 3), ...encodeVarint(value)];
}

function fieldBytes(number: number, value: Uint8Array): number[] {
  return [...encodeVarint((number << 3) | 2), ...encodeVarint(value.length), ...value];
}

function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function buildOtpParameter(options: {
  secret?: Uint8Array;
  name?: string;
  issuer?: string;
  algorithm?: number;
  digits?: number;
  type?: number;
  extra?: number[];
}): Uint8Array {
  const out: number[] = [];
  if (options.secret) out.push(...fieldBytes(1, options.secret));
  if (options.name != null) out.push(...fieldBytes(2, utf8(options.name)));
  if (options.issuer != null) out.push(...fieldBytes(3, utf8(options.issuer)));
  if (options.algorithm != null) out.push(...fieldVarint(4, options.algorithm));
  if (options.digits != null) out.push(...fieldVarint(5, options.digits));
  if (options.type != null) out.push(...fieldVarint(6, options.type));
  if (options.extra) out.push(...options.extra);
  return Uint8Array.from(out);
}

function migrationUri(options: {
  accounts: Uint8Array[];
  version?: number;
  batchSize?: number;
  batchIndex?: number;
  batchId?: number;
  extra?: number[];
}): string {
  const out: number[] = [];
  for (const account of options.accounts) out.push(...fieldBytes(1, account));
  out.push(...fieldVarint(2, options.version ?? 1));
  out.push(...fieldVarint(3, options.batchSize ?? 1));
  out.push(...fieldVarint(4, options.batchIndex ?? 0));
  out.push(...fieldVarint(5, options.batchId ?? 123));
  if (options.extra) out.push(...options.extra);
  return `otpauth-migration://offline?data=${encodeURIComponent(Buffer.from(out).toString('base64'))}`;
}

const validSecret = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

const validAccount = buildOtpParameter({
  secret: validSecret,
  name: 'alice@example.test',
  issuer: 'Example',
  algorithm: 1,
  digits: 1,
  type: 2,
});

test('parses batch metadata and accepted TOTP accounts', () => {
  const page = parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [validAccount],
    version: 1,
    batchSize: 3,
    batchIndex: 2,
    batchId: 0x80000001,
  }));

  assert.equal(page.ok, true);
  if (!page.ok) return;
  assert.deepEqual(page.page, {
    batchId: 0x80000001,
    batchSize: 3,
    batchIndex: 2,
    version: 1,
    accounts: [{
      kind: 'accepted',
      issuer: 'Example',
      name: 'alice@example.test',
      algorithm: 'SHA-1',
      digits: 6,
      period: 30,
      totp: 'otpauth://totp/Example%3Aalice%40example.test?secret=AEBAGBAFAYDQQCIK&algorithm=SHA1&digits=6&period=30&issuer=Example',
    }],
  } satisfies GoogleAuthenticatorMigrationPage);
});

test('accepts SHA-256/SHA-512 and 8-digit records plus unspecified defaults', () => {
  const sha256 = buildOtpParameter({
    secret: validSecret,
    name: 'sha256',
    algorithm: 2,
    digits: 2,
    type: 2,
  });
  const sha512 = buildOtpParameter({
    secret: validSecret,
    name: 'sha512',
    algorithm: 3,
    digits: 1,
    type: 2,
  });
  const unspecified = buildOtpParameter({
    secret: validSecret,
    name: 'default',
    algorithm: 0,
    digits: 0,
    type: 2,
  });

  const page = parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [sha256, sha512, unspecified],
  }));
  assert.equal(page.ok, true);
  if (!page.ok) return;
  assert.equal(page.page.accounts[0].kind, 'accepted');
  assert.equal(page.page.accounts[1].kind, 'accepted');
  assert.equal(page.page.accounts[2].kind, 'accepted');
  if (page.page.accounts[0].kind !== 'accepted') return;
  if (page.page.accounts[1].kind !== 'accepted') return;
  if (page.page.accounts[2].kind !== 'accepted') return;
  assert.equal(page.page.accounts[0].algorithm, 'SHA-256');
  assert.equal(page.page.accounts[0].digits, 8);
  assert.equal(page.page.accounts[1].algorithm, 'SHA-512');
  assert.equal(page.page.accounts[1].digits, 6);
  assert.equal(page.page.accounts[2].algorithm, 'SHA-1');
  assert.equal(page.page.accounts[2].digits, 6);
});

test('reports incompatible records without exposing a TOTP URI', () => {
  const hotp = buildOtpParameter({ secret: validSecret, type: 1 });
  const md5 = buildOtpParameter({ secret: validSecret, algorithm: 4, type: 2 });
  const unknownDigits = buildOtpParameter({ secret: validSecret, digits: 9, type: 2 });
  const missingSecret = buildOtpParameter({ name: 'x', type: 2 });
  const page = parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [hotp, md5, unknownDigits, missingSecret],
  }));

  assert.equal(page.ok, true);
  if (!page.ok) return;
  assert.deepEqual(page.page.accounts, [
    { kind: 'excluded', reason: 'hotp' },
    { kind: 'excluded', reason: 'unsupported-algorithm' },
    { kind: 'excluded', reason: 'unsupported-digits' },
    { kind: 'excluded', reason: 'missing-secret' },
  ]);
  assert.ok(!JSON.stringify(page).includes('otpauth://'));
});

test('rejects malformed, unsupported, and incomplete migration pages', () => {
  assert.deepEqual(parseGoogleAuthenticatorMigrationPage('otpauth-migration://offline?data=%%%'), {
    ok: false,
    reason: 'invalid-data',
  });
  assert.deepEqual(parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [buildOtpParameter({ secret: validSecret, type: 2 })],
    version: 2,
  })), {
    ok: false,
    reason: 'unsupported-version',
  });
  assert.deepEqual(parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [validAccount],
    batchSize: 0,
  })), {
    ok: false,
    reason: 'invalid-batch',
  });
  assert.deepEqual(parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [validAccount],
    batchIndex: 5,
    batchSize: 2,
  })), {
    ok: false,
    reason: 'invalid-batch',
  });
});

test('preserves high-bit batch ids and skips unknown protobuf fields', () => {
  const page = parseGoogleAuthenticatorMigrationPage(migrationUri({
    accounts: [buildOtpParameter({
      secret: validSecret,
      type: 2,
      extra: fieldBytes(99, utf8('ignored')),
    })],
    batchId: 0xffffffff,
    extra: fieldBytes(42, utf8('future')),
  }));
  assert.equal(page.ok, true);
  if (!page.ok) return;
  assert.equal(page.page.batchId, 0xffffffff);
  assert.equal(page.page.accounts[0].kind, 'accepted');
});

test('keeps the legacy one-account normalization behavior', () => {
  const uri = migrationUri({ accounts: [validAccount] });
  assert.equal(
    normalizeTotpInput(uri),
    'otpauth://totp/Example%3Aalice%40example.test?secret=AEBAGBAFAYDQQCIK&algorithm=SHA1&digits=6&period=30&issuer=Example',
  );
  const multi = migrationUri({
    accounts: [validAccount, validAccount],
    batchSize: 1,
  });
  assert.equal(normalizeTotpInput(multi), '');
});

test('qr decode helper returns unreadable without leaking frame details', async () => {
  const bitmap = {
    width: 8,
    height: 8,
    close() {},
  } as ImageBitmap;
  const canvas = {
    width: 0,
    height: 0,
    getContext() {
      return {
        fillStyle: '',
        fillRect() {},
        drawImage() {},
        getImageData() {
          return { data: new Uint8ClampedArray(8 * 8 * 4) };
        },
      };
    },
  } as unknown as HTMLCanvasElement;
  const previousDocument = (globalThis as { document?: Document }).document;
  (globalThis as { document: Document }).document = {
    createElement(tag: string) {
      if (tag === 'canvas') return canvas;
      throw new Error(`unexpected element ${tag}`);
    },
  } as Document;
  try {
    const result = await decodeSingleQrCode(bitmap);
    assert.deepEqual(result, { ok: false, reason: 'unreadable' });
    assert.ok(!JSON.stringify(result).includes('ImageData'));
  } finally {
    if (previousDocument) (globalThis as { document: Document }).document = previousDocument;
    else delete (globalThis as { document?: Document }).document;
  }
});
