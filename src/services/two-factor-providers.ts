import type { User } from '../types';
import { isTotpEnabled } from '../utils/totp';

export type TwoFactorProviderType = 0 | 3 | 7;

type ProviderUser = Pick<User, 'totpSecret' | 'yubikeyKey1' | 'yubikeyKey2' | 'yubikeyKey3' | 'yubikeyKey4' | 'yubikeyKey5'>;

export function twoFactorProviders(user: ProviderUser, hasTwoFactorPasskey: boolean): TwoFactorProviderType[] {
  const providers: TwoFactorProviderType[] = [];
  if (isTotpEnabled(user.totpSecret)) providers.push(0);
  if ([user.yubikeyKey1, user.yubikeyKey2, user.yubikeyKey3, user.yubikeyKey4, user.yubikeyKey5].some(key => key?.trim())) providers.push(3);
  if (hasTwoFactorPasskey) providers.push(7);
  return providers;
}

export function twoFactorClearStatements(
  db: D1Database,
  userId: string,
  { recoveryCode, securityStamp }: { recoveryCode: string | null; securityStamp: string },
): D1PreparedStatement[] {
  return [
    db.prepare(`UPDATE users SET totp_secret = NULL, totp_recovery_code = ?,
      yubikey_key1 = NULL, yubikey_key2 = NULL, yubikey_key3 = NULL, yubikey_key4 = NULL,
      yubikey_key5 = NULL, yubikey_nfc = 0, security_stamp = ?, updated_at = ? WHERE id = ?`)
      .bind(recoveryCode, securityStamp, new Date().toISOString(), userId),
    db.prepare("DELETE FROM webauthn_credentials WHERE user_id = ? AND purpose = 'twoFactor'").bind(userId),
    db.prepare('DELETE FROM two_factor WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM trusted_two_factor_device_tokens WHERE user_id = ?').bind(userId),
    db.prepare('DELETE FROM session WHERE user_id = ?').bind(userId),
  ];
}
