function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array | null {
  const normalized = base64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized) return null;
  const padLength = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLength);
  try {
    const binary = atob(padded);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function encodeUint32(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value >>> 0, false);
  return out;
}

function encodeSshString(value: Uint8Array): Uint8Array {
  return concatBytes(encodeUint32(value.length), value);
}

function extractSshBlobFromPublicKey(publicKey: string): Uint8Array | null {
  const text = String(publicKey || '').trim();
  if (!text) return null;
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^([A-Za-z0-9-]+)\s+([A-Za-z0-9+/=_-]+)(?:\s+.*)?$/);
    if (!match) continue;
    const keyType = match[1].toLowerCase();
    if (!keyType.startsWith('ssh-') && !keyType.startsWith('ecdsa-')) continue;
    return base64ToBytes(match[2]);
  }
  return null;
}

export async function computeSshFingerprint(publicKey: string): Promise<string> {
  const blob = extractSshBlobFromPublicKey(publicKey);
  if (!blob) return '';
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', blob as unknown as BufferSource));
  return `SHA256:${bytesToBase64(digest).replace(/=+$/g, '')}`;
}

function toOpenSshPrivateKeyPem(bytes: Uint8Array): string {
  const b64 = bytesToBase64(bytes);
  const chunks: string[] = [];
  for (let i = 0; i < b64.length; i += 70) chunks.push(b64.slice(i, i + 70));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${chunks.join('\n')}\n-----END OPENSSH PRIVATE KEY-----\n`;
}

function extractEd25519RawPublicKey(spki: Uint8Array): Uint8Array | null {
  const prefix = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
  const hasPrefix = spki.length >= prefix.length + 32 && prefix.every((value, idx) => spki[idx] === value);
  if (hasPrefix) return spki.slice(prefix.length, prefix.length + 32);
  if (spki.length >= 32) return spki.slice(spki.length - 32);
  return null;
}

function extractEd25519SeedFromPkcs8(pkcs8: Uint8Array): Uint8Array | null {
  const prefix = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  const hasPrefix = pkcs8.length >= prefix.length + 32 && prefix.every((value, idx) => pkcs8[idx] === value);
  if (hasPrefix) return pkcs8.slice(prefix.length, prefix.length + 32);

  for (let i = 0; i <= pkcs8.length - 34; i += 1) {
    if (pkcs8[i] === 0x04 && pkcs8[i + 1] === 0x20) {
      return pkcs8.slice(i + 2, i + 34);
    }
  }
  return null;
}

function buildOpenSshEd25519PrivateKey(seed: Uint8Array, rawPublic: Uint8Array, comment = ''): string {
  const encoder = new TextEncoder();
  const keyType = encoder.encode('ssh-ed25519');
  const sshBlob = concatBytes(encodeSshString(keyType), encodeSshString(rawPublic));
  const privateKey = concatBytes(seed, rawPublic);
  const check = crypto.getRandomValues(new Uint8Array(4));
  let privateBlock = concatBytes(
    check,
    check,
    encodeSshString(keyType),
    encodeSshString(rawPublic),
    encodeSshString(privateKey),
    encodeSshString(encoder.encode(comment))
  );
  const paddingLength = (8 - (privateBlock.length % 8)) % 8 || 8;
  const padding = new Uint8Array(paddingLength);
  for (let i = 0; i < paddingLength; i += 1) padding[i] = i + 1;
  privateBlock = concatBytes(privateBlock, padding);

  const authMagic = encoder.encode('openssh-key-v1\0');
  const payload = concatBytes(
    authMagic,
    encodeSshString(encoder.encode('none')),
    encodeSshString(encoder.encode('none')),
    encodeSshString(new Uint8Array(0)),
    encodeUint32(1),
    encodeSshString(sshBlob),
    encodeSshString(privateBlock)
  );
  return toOpenSshPrivateKeyPem(payload);
}

export async function generateDefaultSshKeyMaterial(): Promise<{ privateKey: string; publicKey: string; fingerprint: string }> {
  const keyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const rawPublic = extractEd25519RawPublicKey(spki);
  if (!rawPublic) throw new Error('Cannot export Ed25519 public key');
  const seed = extractEd25519SeedFromPkcs8(pkcs8);
  if (!seed) throw new Error('Cannot export Ed25519 private key');

  const encoder = new TextEncoder();
  const sshBlob = concatBytes(encodeSshString(encoder.encode('ssh-ed25519')), encodeSshString(rawPublic));
  const publicKey = `ssh-ed25519 ${bytesToBase64(sshBlob)}`;
  const privateKey = buildOpenSshEd25519PrivateKey(seed, rawPublic);
  const fingerprint = await computeSshFingerprint(publicKey);
  return { privateKey, publicKey, fingerprint };
}
