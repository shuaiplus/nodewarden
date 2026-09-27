import type { Env } from '../types';
import { signHs256Jwt, verifyHs256Jwt } from './jwt';

const USER_VERIFICATION_TOKEN_TYPE = 'nodewarden.user-verification.v1';
const USER_VERIFICATION_TOKEN_TTL_SECONDS = 5 * 60;

export type UserVerificationPurpose = 'backup.settings.repair';

interface UserVerificationTokenPayload {
  typ: typeof USER_VERIFICATION_TOKEN_TYPE;
  userId: string;
  method: 'passkey';
  purpose: UserVerificationPurpose;
  iat: number;
  exp: number;
}

export async function createPasskeyUserVerificationToken(
  env: Env,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return signHs256Jwt({
    typ: USER_VERIFICATION_TOKEN_TYPE,
    userId,
    method: 'passkey',
    purpose,
    iat: now,
    exp: now + USER_VERIFICATION_TOKEN_TTL_SECONDS,
  } satisfies UserVerificationTokenPayload, env.JWT_SECRET);
}

export async function verifyPasskeyUserVerificationToken(
  env: Env,
  token: string,
  userId: string,
  purpose: UserVerificationPurpose
): Promise<boolean> {
  const payload = await verifyHs256Jwt<UserVerificationTokenPayload>(token, env.JWT_SECRET);
  return payload?.typ === USER_VERIFICATION_TOKEN_TYPE
    && payload.userId === userId && payload.purpose === purpose && payload.method === 'passkey';
}
