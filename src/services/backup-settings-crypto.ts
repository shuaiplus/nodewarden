import { decodeBase64, encodeBase64 } from 'hono/utils/encode';
import type { Env, User } from '../types';

// CONTRACT:
// Backup settings contain provider credentials. They are stored as a v2 envelope:
// - runtime: AES-GCM encrypted with a key derived from JWT_SECRET for the current
//   server's scheduled backup runner.
// - portable: AES-GCM encrypted with a random DEK; that DEK is RSA-wrapped for
//   active admin public keys so settings can be repaired after restore/migration.
//   Historical/imported databases may not have usable admin public keys; in that
//   case portable.wraps is empty but the runtime ciphertext is still encrypted.
//
// New admin-entered provider secrets, such as mail API keys, should use this
// pattern or a deliberately documented replacement. Do not store provider
// secrets as plain config JSON.
const RUNTIME_SALT = 'nodewarden.backup-settings.runtime.v2';
const RUNTIME_INFO = 'runtime';
const PORTABLE_ALGORITHM = 'RSA-OAEP';
const PORTABLE_HASH = 'SHA-1';
const AES_GCM_ALGORITHM = 'AES-GCM';
const AES_GCM_IV_BYTES = 12;
const PORTABLE_DEK_BYTES = 32;

export interface BackupSettingsRuntimeEnvelope {
  iv: string;
  ciphertext: string;
}

export interface BackupSettingsPortableWrap {
  userId: string;
  wrappedKey: string;
}

export interface BackupSettingsPortableEnvelope {
  iv: string;
  ciphertext: string;
  wraps: BackupSettingsPortableWrap[];
}

export interface BackupSettingsEnvelopeV2 {
  version: 2;
  runtime: BackupSettingsRuntimeEnvelope;
  portable: BackupSettingsPortableEnvelope;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

async function deriveRuntimeKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(secret), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(RUNTIME_SALT),
      info: encoder.encode(RUNTIME_INFO),
    },
    keyMaterial,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: AES_GCM_ALGORITHM }, false, ['encrypt', 'decrypt']);
}

async function encryptAesGcm(
  plaintext: Uint8Array,
  key: CryptoKey,
): Promise<{ iv: Uint8Array; ciphertext: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: AES_GCM_ALGORITHM, iv }, key, plaintext));
  return { iv, ciphertext };
}

export function parseBackupSettingsEnvelope(raw: string | null): BackupSettingsEnvelopeV2 | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    if (!isPlainObject(parsed) || Number(parsed.version) !== 2) return null;
    const runtime = parsed.runtime;
    const portable = parsed.portable;
    if (!isPlainObject(runtime) || !isPlainObject(portable)) return null;
    if (!Array.isArray(portable.wraps)) return null;
    if (typeof runtime.iv !== 'string' || typeof runtime.ciphertext !== 'string') return null;
    if (typeof portable.iv !== 'string' || typeof portable.ciphertext !== 'string') return null;
    return {
      version: 2,
      runtime: {
        iv: runtime.iv,
        ciphertext: runtime.ciphertext,
      },
      portable: {
        iv: portable.iv,
        ciphertext: portable.ciphertext,
        wraps: portable.wraps
          .filter((entry): entry is Record<string, unknown> => isPlainObject(entry))
          .map((entry) => ({
            userId: String(entry.userId || '').trim(),
            wrappedKey: String(entry.wrappedKey || '').trim(),
          }))
          .filter((entry) => entry.userId && entry.wrappedKey),
      },
    };
  } catch {
    return null;
  }
}

export function exportPortableBackupSettingsEnvelope(raw: string | null): string | null {
  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) return null;
  return JSON.stringify({
    version: 2,
    portableOnly: true,
    runtime: {
      iv: '',
      ciphertext: '',
    },
    portable: envelope.portable,
  });
}

export async function encryptBackupSettingsEnvelope(
  plaintext: string,
  env: Env,
  users: Pick<User, 'id' | 'publicKey' | 'role' | 'status'>[],
): Promise<string> {
  const encoder = new TextEncoder();
  // Only active admins with a public key can unwrap the portable copy.
  const eligibleUsers = users.filter(
    (user) =>
      user.role === 'admin' &&
      user.status === 'active' &&
      typeof user.publicKey === 'string' &&
      user.publicKey.trim().length > 0,
  );

  const runtimeKey = await deriveRuntimeKey(env.JWT_SECRET);
  const runtime = await encryptAesGcm(encoder.encode(plaintext), runtimeKey);

  const portableDek = crypto.getRandomValues(new Uint8Array(PORTABLE_DEK_BYTES));
  const portableKey = await crypto.subtle.importKey('raw', portableDek, { name: AES_GCM_ALGORITHM }, false, [
    'encrypt',
  ]);
  const portableCipher = await encryptAesGcm(encoder.encode(plaintext), portableKey);

  const wraps: BackupSettingsPortableWrap[] = [];
  for (const user of eligibleUsers) {
    try {
      const publicKey = await crypto.subtle.importKey(
        'spki',
        decodeBase64(user.publicKey!),
        { name: PORTABLE_ALGORITHM, hash: PORTABLE_HASH },
        false,
        ['encrypt'],
      );
      const wrappedKey = await crypto.subtle.encrypt({ name: PORTABLE_ALGORITHM }, publicKey, portableDek);
      wraps.push({
        userId: user.id,
        wrappedKey: encodeBase64(wrappedKey),
      });
    } catch {
      // Keep runtime settings usable even if an imported admin key is malformed.
    }
  }

  // encryptAesGcm's arrays each own their whole buffer, so .buffer is exactly their bytes.
  const envelope: BackupSettingsEnvelopeV2 = {
    version: 2,
    runtime: {
      iv: encodeBase64(runtime.iv.buffer),
      ciphertext: encodeBase64(runtime.ciphertext.buffer),
    },
    portable: {
      iv: encodeBase64(portableCipher.iv.buffer),
      ciphertext: encodeBase64(portableCipher.ciphertext.buffer),
      wraps,
    },
  };

  return JSON.stringify(envelope);
}

export async function decryptBackupSettingsRuntime(raw: string, env: Env): Promise<string> {
  const envelope = parseBackupSettingsEnvelope(raw);
  if (!envelope) {
    throw new Error('Backup settings envelope is invalid');
  }
  const runtimeKey = await deriveRuntimeKey(env.JWT_SECRET);
  const ciphertext = decodeBase64(envelope.runtime.ciphertext);
  const iv = decodeBase64(envelope.runtime.iv);
  const plaintext = await crypto.subtle.decrypt({ name: AES_GCM_ALGORITHM, iv }, runtimeKey, ciphertext);
  return new TextDecoder().decode(plaintext);
}
