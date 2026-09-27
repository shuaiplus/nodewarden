import { and, eq, exists } from 'drizzle-orm';
import { getOrm, userRowMatches, type Orm } from '../db/client';
import { session, trustedTwoFactorDeviceTokens, users, webauthnCredentials } from '../db/schema';
import { bound, coalesce, nullIf } from '../db/sql';
import type { User } from '../types';
import { isTotpEnabled } from '../utils/totp';
import { createRecoveryCode } from '../utils/recovery-code';

export type TwoFactorProviderType = 0 | 1 | 3 | 7;

type ProviderUser = Pick<User, 'totpSecret' | 'twoFactorEmail' | 'yubikeyKey1' | 'yubikeyKey2' | 'yubikeyKey3' | 'yubikeyKey4' | 'yubikeyKey5'>;

export function twoFactorProviders(user: ProviderUser, hasTwoFactorPasskey: boolean): TwoFactorProviderType[] {
  const providers: TwoFactorProviderType[] = [];
  if (isTotpEnabled(user.totpSecret)) providers.push(0);
  if (user.twoFactorEmail) providers.push(1);
  if ([user.yubikeyKey1, user.yubikeyKey2, user.yubikeyKey3, user.yubikeyKey4, user.yubikeyKey5].some(key => key?.trim())) providers.push(3);
  if (hasTwoFactorPasskey) providers.push(7);
  return providers;
}

// Per users row of the enclosing query: whether that user enrolled a passkey as a second factor.
export function hasTwoFactorPasskey(orm: Orm) {
  return exists(orm.select({ id: webauthnCredentials.id }).from(webauthnCredentials)
    .where(and(eq(webauthnCredentials.userId, users.id), eq(webauthnCredentials.purpose, 'twoFactor')))).mapWith(Boolean);
}

// Enrolment fills a missing recovery code but never replaces one the user may already have written down.
export function existingOrNewRecoveryCode() {
  return coalesce<string>(nullIf(users.totpRecoveryCode, ''), createRecoveryCode());
}

export async function ensureTwoFactorRecoveryCode(db: D1Database, userId: string, securityStamp: string): Promise<string | null> {
  const [row] = await getOrm(db).update(users).set({ totpRecoveryCode: existingOrNewRecoveryCode() })
    .where(and(eq(users.id, userId), eq(users.securityStamp, securityStamp))).returning({ code: users.totpRecoveryCode });
  return row?.code ?? null;
}

// Batch the result with getOrm(db).batch(); the first result's meta.changes reports whether the clear applied.
export function twoFactorClearStatements(
  db: D1Database,
  userId: string,
  { recoveryCode, securityStamp }: { recoveryCode: string | null; securityStamp: string },
  expected?: Pick<User, 'securityStamp' | 'totpRecoveryCode'>,
) {
  const orm = getOrm(db);
  // Each dependent delete runs only if this batch installed its fresh stamp.
  const cleared = userRowMatches(orm, userId, eq(users.securityStamp, securityStamp));
  return [
    orm.update(users).set({
      totpSecret: null, twoFactorEmail: null, totpRecoveryCode: recoveryCode,
      yubikeyKey1: null, yubikeyKey2: null, yubikeyKey3: null, yubikeyKey4: null, yubikeyKey5: null,
      yubikeyNfc: 0, securityStamp, updatedAt: new Date().toISOString(),
    }).where(and(eq(users.id, userId), expected && and(
      eq(users.status, 'active'), eq(users.securityStamp, expected.securityStamp),
      // A snapshot without a recovery code binds NULL and so never matches, as the equality always has.
      eq(users.totpRecoveryCode, bound(expected.totpRecoveryCode)),
    ))),
    orm.delete(webauthnCredentials).where(and(eq(webauthnCredentials.userId, userId), eq(webauthnCredentials.purpose, 'twoFactor'), cleared)),
    orm.delete(trustedTwoFactorDeviceTokens).where(and(eq(trustedTwoFactorDeviceTokens.userId, userId), cleared)),
    orm.delete(session).where(and(eq(session.userId, userId), cleared)),
  ] as const;
}
