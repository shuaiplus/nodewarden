import type { SshKeyOptions } from '@/lib/password-generator';

export interface GeneratedSshKey {
  type: 'ED25519' | 'RSA';
  bits: number;
  publicKey: string;
  privateKey: string;
  fingerprint: string;
}

const encoder = new TextEncoder();

function concat(...chunks: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }
  return output;
}

function uint32(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function sshString(value: string | Uint8Array): Uint8Array {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  return concat(uint32(bytes.length), bytes);
}

function base64UrlBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const decoded = atob(normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '='));
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function base64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function mpint(value: Uint8Array): Uint8Array {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) offset += 1;
  let bytes = value.subarray(offset);
  if (bytes[0] & 0x80) bytes = concat(new Uint8Array([0]), bytes);
  return sshString(bytes);
}

function openSshPrivateKey(publicBlob: Uint8Array, fields: Uint8Array[]): string {
  const check = new Uint32Array(1);
  crypto.getRandomValues(check);
  let privateBlock = concat(uint32(check[0]), uint32(check[0]), ...fields, sshString(''));
  const paddingLength = 8 - (privateBlock.length % 8);
  privateBlock = concat(privateBlock, Uint8Array.from({ length: paddingLength }, (_, index) => index + 1));
  const envelope = concat(
    encoder.encode('openssh-key-v1\0'),
    sshString('none'),
    sshString('none'),
    sshString(new Uint8Array()),
    uint32(1),
    sshString(publicBlob),
    sshString(privateBlock),
  );
  const body = base64(envelope).match(/.{1,70}/g)?.join('\n') || '';
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${body}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

async function fingerprint(publicBlob: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', Uint8Array.from(publicBlob).buffer));
  return `SHA256:${base64(digest).replace(/=+$/, '')}`;
}

function required(jwk: JsonWebKey, property: keyof JsonWebKey): Uint8Array {
  const value = jwk[property];
  if (typeof value !== 'string' || !value) throw new Error(`The generated key is missing ${String(property)}`);
  return base64UrlBytes(value);
}

async function generateEd25519(comment: string): Promise<GeneratedSshKey> {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']) as CryptoKeyPair;
  const [privateJwk, publicJwk] = await Promise.all([
    crypto.subtle.exportKey('jwk', pair.privateKey),
    crypto.subtle.exportKey('jwk', pair.publicKey),
  ]);
  const publicBytes = required(publicJwk, 'x');
  const seed = required(privateJwk, 'd');
  const publicBlob = concat(sshString('ssh-ed25519'), sshString(publicBytes));
  const privateKey = openSshPrivateKey(publicBlob, [
    sshString('ssh-ed25519'),
    sshString(publicBytes),
    sshString(concat(seed, publicBytes)),
  ]);
  return {
    type: 'ED25519',
    bits: 256,
    publicKey: `ssh-ed25519 ${base64(publicBlob)}${comment ? ` ${comment}` : ''}`,
    privateKey,
    fingerprint: await fingerprint(publicBlob),
  };
}

async function generateRsa(length: SshKeyOptions['rsaLength'], comment: string): Promise<GeneratedSshKey> {
  const pair = await crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: length,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['sign', 'verify']) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const n = required(privateJwk, 'n');
  const e = required(privateJwk, 'e');
  const d = required(privateJwk, 'd');
  const qi = required(privateJwk, 'qi');
  const p = required(privateJwk, 'p');
  const q = required(privateJwk, 'q');
  const publicBlob = concat(sshString('ssh-rsa'), mpint(e), mpint(n));
  const privateKey = openSshPrivateKey(publicBlob, [
    sshString('ssh-rsa'),
    mpint(n), mpint(e), mpint(d), mpint(qi), mpint(p), mpint(q),
  ]);
  return {
    type: 'RSA',
    bits: length,
    publicKey: `ssh-rsa ${base64(publicBlob)}${comment ? ` ${comment}` : ''}`,
    privateKey,
    fingerprint: await fingerprint(publicBlob),
  };
}

export async function generateSshKey(options: SshKeyOptions): Promise<GeneratedSshKey> {
  if (!crypto?.subtle) throw new Error('Web Crypto is unavailable');
  const comment = options.comment.replace(/[\r\n]+/g, ' ').trim();
  return options.type === 'rsa' ? generateRsa(options.rsaLength, comment) : generateEd25519(comment);
}
