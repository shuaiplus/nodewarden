import { z } from 'zod';
import { readEnvConfig } from '../config/env';
import type { Env } from '../types';

// Registration reads each value from its first usable alias: anything but a non-blank string or a
// number reads as absent, and a nested section that is not an object falls back to the flat fields.
const text = z.string().trim().catch('');
const count = z.number().optional().catch(undefined);
const section = <Shape extends z.ZodRawShape>(shape: Shape) => z.object(shape).optional().catch(undefined);
const below = (value: number | undefined, minimum: number) => value !== undefined && value < minimum;

// Server KdfSettings, nested in the master password authentication and unlock data.
export const KdfSettings = section({ kdfType: count, kdf: count, iterations: count, memory: count, parallelism: count });

// Hints are non-secret reminders; a blank one means none.
export const MasterPasswordHint = z.string()
  .trim()
  .max(120, { error: 'masterPasswordHint must be 120 characters or fewer' })
  .nullish()
  .transform((hint) => hint || null);

const asymmetricKeys = section({ publicKey: text, encryptedPrivateKey: text, privateKey: text });

// Official web RegisterFinish nests the hash, wrapped user key and KDF under masterPasswordAuthentication
// and masterPasswordUnlock and the key pair under userAsymmetricKeys; the NodeWarden webapp posts them flat.
// The checks run in order, so the first failing one is the reported message.
export const RegisterSchema = z.object({
  email: text,
  name: text,
  masterPasswordHash: text,
  key: text,
  userSymmetricKey: text,
  publicKey: text,
  encryptedPrivateKey: text,
  masterPasswordHint: MasterPasswordHint,
  inviteCode: text,
  emailVerificationToken: text,
  token: text,
  kdf: count,
  kdfIterations: count,
  kdfMemory: count,
  kdfParallelism: count,
  masterPasswordAuthentication: section({ masterPasswordAuthenticationHash: text, hash: text, kdf: KdfSettings }),
  masterPasswordUnlock: section({ masterKeyWrappedUserKey: text, key: text, kdf: KdfSettings }),
  userAsymmetricKeys: asymmetricKeys,
  keys: asymmetricKeys,
}).transform(({ masterPasswordAuthentication: auth, masterPasswordUnlock: unlock, ...body }) => {
  const keys = body.userAsymmetricKeys ?? body.keys;
  const kdf = auth?.kdf ?? unlock?.kdf;
  const email = body.email.toLowerCase();
  return {
    email,
    name: body.name || email,
    masterPasswordHash: auth?.masterPasswordAuthenticationHash || auth?.hash || body.masterPasswordHash,
    key: unlock?.masterKeyWrappedUserKey || unlock?.key || body.userSymmetricKey || body.key,
    publicKey: keys?.publicKey || body.publicKey,
    privateKey: keys?.encryptedPrivateKey || keys?.privateKey || body.encryptedPrivateKey,
    kdf: kdf?.kdfType ?? kdf?.kdf ?? body.kdf,
    kdfIterations: kdf?.iterations ?? body.kdfIterations,
    kdfMemory: kdf?.memory ?? body.kdfMemory,
    kdfParallelism: kdf?.parallelism ?? body.kdfParallelism,
    inviteCode: body.inviteCode,
    masterPasswordHint: body.masterPasswordHint,
    emailVerificationToken: body.emailVerificationToken || body.token,
  };
})
  .refine((user) => user.email && user.masterPasswordHash && user.key, 'Email, masterPasswordHash, and key are required')
  .refine((user) => user.email.includes('@') && user.email.length >= 3, 'Invalid email address')
  .refine((user) => user.privateKey && user.publicKey, 'Private key and public key are required')
  // Bitwarden minimums; an absent KDF type means PBKDF2-SHA256.
  .refine(({ kdf = 0 }) => kdf === 0 || kdf === 1, 'KDF type must be PBKDF2-SHA256 or Argon2id')
  .refine(({ kdf = 0, kdfIterations }) => kdf !== 0 || !below(kdfIterations, 100_000), 'PBKDF2 iterations must be at least 100000')
  .refine(({ kdf, kdfIterations }) => kdf !== 1 || !below(kdfIterations, 2), 'Argon2id iterations must be at least 2')
  .refine(({ kdf, kdfMemory }) => kdf !== 1 || !below(kdfMemory, 16), 'Argon2id memory must be at least 16 MiB')
  .refine(({ kdf, kdfParallelism }) => kdf !== 1 || !below(kdfParallelism, 1), 'Argon2id parallelism must be at least 1');

export function isOpenRegistrationEnabled(env: Partial<Env>): boolean {
  return readEnvConfig(env).ALLOW_OPEN_REGISTRATION;
}
