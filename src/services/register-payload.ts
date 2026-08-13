export interface ParsedRegisterRequest {
  email: string;
  name: string;
  masterPasswordHash: string;
  key: string;
  publicKey: string;
  privateKey: string;
  kdf?: number;
  kdfIterations?: number;
  kdfMemory?: number;
  kdfParallelism?: number;
  inviteCode: string;
  masterPasswordHint: string | null;
  emailVerificationToken: string;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function readString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function readNumber(...values: unknown[]): number | undefined {
  for (const value of values) {
    if (typeof value === 'number' && Number.isFinite(value)) return value;
  }
  return undefined;
}

function readKdf(source: unknown): {
  kdf?: number;
  kdfIterations?: number;
  kdfMemory?: number;
  kdfParallelism?: number;
} {
  const rec = asRecord(source);
  if (!rec) return {};
  return {
    kdf: readNumber(rec.kdfType, rec.KdfType, rec.kdf),
    kdfIterations: readNumber(rec.iterations, rec.Iterations),
    kdfMemory: readNumber(rec.memory, rec.Memory),
    kdfParallelism: readNumber(rec.parallelism, rec.Parallelism),
  };
}

export function parseRegisterPayload(body: Record<string, unknown>): ParsedRegisterRequest | string {
  const auth = asRecord(body.masterPasswordAuthentication);
  const unlock = asRecord(body.masterPasswordUnlock);
  const keys = asRecord(body.userAsymmetricKeys) || asRecord(body.keys);
  const nestedKdf = {
    ...readKdf(unlock?.kdf),
    ...readKdf(auth?.kdf),
  };

  const email = readString(body.email).toLowerCase();
  const masterPasswordHash = readString(
    auth?.masterPasswordAuthenticationHash,
    auth?.hash,
    body.masterPasswordHash
  );
  const key = readString(
    unlock?.masterKeyWrappedUserKey,
    unlock?.key,
    body.userSymmetricKey,
    body.key
  );
  const publicKey = readString(keys?.publicKey, body.publicKey);
  const privateKey = readString(keys?.encryptedPrivateKey, keys?.privateKey, body.encryptedPrivateKey);
  const name = readString(body.name) || email;

  if (!email || !masterPasswordHash || !key) {
    return 'Email, masterPasswordHash, and key are required';
  }
  if (!email.includes('@') || email.length < 3) {
    return 'Invalid email address';
  }
  if (!privateKey || !publicKey) {
    return 'Private key and public key are required';
  }

  const hint = readString(body.masterPasswordHint);
  return {
    email,
    name,
    masterPasswordHash,
    key,
    publicKey,
    privateKey,
    kdf: readNumber(nestedKdf.kdf, body.kdf),
    kdfIterations: readNumber(nestedKdf.kdfIterations, body.kdfIterations),
    kdfMemory: readNumber(nestedKdf.kdfMemory, body.kdfMemory),
    kdfParallelism: readNumber(nestedKdf.kdfParallelism, body.kdfParallelism),
    inviteCode: readString(body.inviteCode),
    masterPasswordHint: hint || null,
    emailVerificationToken: readString(body.emailVerificationToken, body.token),
  };
}

export function isOpenRegistrationEnabled(env: { ALLOW_OPEN_REGISTRATION?: string }): boolean {
  return String(env.ALLOW_OPEN_REGISTRATION || '').trim() === '1';
}
