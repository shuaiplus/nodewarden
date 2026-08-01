import { useMemo } from 'preact/hooks';
import {
  changeMasterPassword,
  bootstrapYubiKeyOtpApiCredentials,
  deleteAllAuthorizedDevices,
  deleteAuthorizedDevice,
  deleteAuthorizedDevices,
  deriveLoginHash,
  deleteAccountPasskey as deleteAccountPasskeyApi,
  deleteTwoFactorPasskey as deleteTwoFactorPasskeyApi,
  enableAccountPasskeyDirectUnlock as enableAccountPasskeyDirectUnlockApi,
  disableTwoFactorPasskeys as disableTwoFactorPasskeysApi,
  disableYubiKeyOtp,
  getCurrentDeviceIdentifier,
  getApiKey,
  getAccountPasskeyAttestationOptions,
  getAccountPasskeyUpdateAssertionOptions,
  getTotpRecoveryCode,
  getTwoFactorPasskeyChallenge,
  getTwoFactorPasskeySettings as getTwoFactorPasskeySettingsApi,
  getYubiKeyOtpSettings,
  listAccountPasskeys,
  rotateApiKey,
  revokeAuthorizedDeviceTrust,
  revokeAllAuthorizedDeviceTrust,
  saveAccountPasskey,
  saveTwoFactorPasskey,
  saveYubiKeyOtpApiCredentials,
  saveYubiKeyOtpSettings,
  setTotp,
  trustAuthorizedDevicePermanently,
  updateAuthorizedDeviceName,
  updateProfile,
} from '@/lib/api/auth';
import {
  AccountPasskeyPrfUnavailableError,
  assertAccountPasskey,
  buildAccountPasskeyPrfKeySet,
  buildAccountPasskeyPrfKeySetFromPrfKey,
  createAccountPasskeyCredential,
  createTwoFactorPasskeyCredential,
} from '@/lib/account-passkeys';
import { t } from '@/lib/i18n';
import type { AppConfirmState } from '@/components/AppGlobalOverlays';
import type { AuthedFetch } from '@/lib/api/shared';
import type { AccountPasskeyCredential, AuthorizedDevice, Profile, SessionState, TwoFactorPasskeySettings, YubiKeyOtpSettings } from '@/lib/types';

type Notify = (type: 'success' | 'error' | 'warning', text: string) => void;

interface UseAccountSecurityActionsOptions {
  authedFetch: AuthedFetch;
  profile: Profile | null;
  session: SessionState | null;
  defaultKdfIterations: number;
  disableTotpPassword: string;
  clearDisableTotpDialog: () => void;
  onLogoutNow: () => void;
  onNotify: Notify;
  onProfileUpdated: (profile: Profile) => void;
  onSetConfirm: (next: AppConfirmState | null) => void;
  refetchTwoFactorStatus: () => Promise<unknown>;
  refetchAuthorizedDevices: () => Promise<unknown>;
}

export default function useAccountSecurityActions(options: UseAccountSecurityActionsOptions) {
  const {
    authedFetch,
    profile,
    session,
    defaultKdfIterations,
    disableTotpPassword,
    clearDisableTotpDialog,
    onLogoutNow,
    onNotify,
    onProfileUpdated,
    onSetConfirm,
    refetchTwoFactorStatus,
    refetchAuthorizedDevices,
  } = options;

  return useMemo(
    () => {
      function confirmSaveLoginOnlyAccountPasskey(): Promise<boolean> {
        return new Promise((resolve) => {
          let settled = false;
          const finish = (shouldSave: boolean) => {
            if (settled) return;
            settled = true;
            onSetConfirm(null);
            resolve(shouldSave);
          };
          onSetConfirm({
            title: t('txt_account_passkey_direct_unlock_unavailable_title'),
            message: t('txt_account_passkey_direct_unlock_unavailable_message'),
            confirmText: t('txt_save_login_only_passkey'),
            cancelText: t('txt_do_not_save'),
            showIcon: true,
            onConfirm: () => finish(true),
            onCancel: () => finish(false),
          });
        });
      }

      return ({
      async changePassword(currentPassword: string, nextPassword: string, nextPassword2: string) {
        if (!profile) return;
        if (!currentPassword || !nextPassword) {
          onNotify('error', t('txt_current_new_password_is_required'));
          return;
        }
        if (nextPassword.length < 12) {
          onNotify('error', t('txt_new_password_must_be_at_least_12_chars'));
          return;
        }
        if (nextPassword !== nextPassword2) {
          onNotify('error', t('txt_new_passwords_do_not_match'));
          return;
        }
        onSetConfirm({
          title: t('txt_change_master_password'),
          message: t('txt_change_password_confirm_and_sign_out_all_devices'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await changeMasterPassword(authedFetch, {
                  email: profile.email,
                  currentPassword,
                  newPassword: nextPassword,
                  currentIterations: defaultKdfIterations,
                  profileKey: profile.key,
                });
                onNotify('success', t('txt_master_password_changed_signing_out_everywhere'));
                onLogoutNow();
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_change_password_failed'));
              }
            })();
          },
        });
      },

      async savePasswordHint(masterPasswordHint: string) {
        if (!profile) return;
        const normalized = String(masterPasswordHint || '').trim();
        if (normalized.length > 120) {
          onNotify('error', t('txt_password_hint_too_long'));
          return;
        }
        try {
          const nextProfile = await updateProfile(authedFetch, { masterPasswordHint: normalized });
          onProfileUpdated(nextProfile);
          onNotify('success', t('txt_profile_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_save_profile_failed'));
        }
      },

      async enableTotp(secret: string, token: string, masterPassword: string) {
        if (!profile) {
          const error = new Error(t('txt_profile_unavailable'));
          onNotify('error', error.message);
          throw error;
        }
        if (!secret.trim() || !token.trim()) {
          const error = new Error(t('txt_secret_and_code_are_required'));
          onNotify('error', error.message);
          throw error;
        }
        if (!masterPassword) {
          const error = new Error(t('txt_master_password_is_required'));
          onNotify('error', error.message);
          throw error;
        }
        try {
          const derived = await deriveLoginHash(profile.email, masterPassword, defaultKdfIterations);
          await setTotp(authedFetch, {
            enabled: true,
            secret: secret.trim(),
            token: token.trim(),
            masterPasswordHash: derived.hash,
          });
          onNotify('success', t('txt_totp_enabled'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_enable_totp_failed'));
          throw error;
        }
      },

      async disableTotp() {
        if (!profile) return;
        if (!disableTotpPassword) {
          onNotify('error', t('txt_please_input_master_password'));
          return;
        }
        try {
          const derived = await deriveLoginHash(profile.email, disableTotpPassword, defaultKdfIterations);
          await setTotp(authedFetch, { enabled: false, masterPasswordHash: derived.hash });
          clearDisableTotpDialog();
          await refetchTwoFactorStatus();
          onNotify('success', t('txt_totp_disabled'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_disable_totp_failed'));
        }
      },

      async getYubiKeySettings(masterPassword: string): Promise<YubiKeyOtpSettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        return getYubiKeyOtpSettings(authedFetch, derived.hash);
      },

      async saveYubiKeySettings(keys: string[], nfc: boolean, masterPassword: string): Promise<YubiKeyOtpSettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const settings = await saveYubiKeyOtpSettings(authedFetch, { keys, nfc, masterPasswordHash: derived.hash });
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_yubikeys_updated'));
        return settings;
      },

      async saveYubiKeyApiCredentials(clientId: string, secretKey: string, masterPassword: string): Promise<YubiKeyOtpSettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const settings = await saveYubiKeyOtpApiCredentials(authedFetch, {
          masterPasswordHash: derived.hash,
          yubicoClientId: clientId,
          yubicoSecretKey: secretKey,
        });
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_yubikey_config_updated'));
        return settings;
      },

      async bootstrapYubiKeyApiCredentials(otp: string, masterPassword: string): Promise<YubiKeyOtpSettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const settings = await bootstrapYubiKeyOtpApiCredentials(authedFetch, {
          masterPasswordHash: derived.hash,
          otp,
        });
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_yubikey_config_updated'));
        return settings;
      },

      async disableYubiKey(masterPassword: string): Promise<void> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        await disableYubiKeyOtp(authedFetch, derived.hash);
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_yubikey_disabled'));
      },

      async getTwoFactorPasskeySettings(masterPassword: string): Promise<TwoFactorPasskeySettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        return getTwoFactorPasskeySettingsApi(authedFetch, derived.hash);
      },

      async createTwoFactorPasskey(name: string, masterPassword: string): Promise<TwoFactorPasskeySettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const normalizedName = String(name || '').trim() || t('txt_passkey');
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const challenge = await getTwoFactorPasskeyChallenge(authedFetch, derived.hash);
        const deviceResponse = await createTwoFactorPasskeyCredential(challenge);
        const settings = await saveTwoFactorPasskey(authedFetch, {
          name: normalizedName,
          masterPasswordHash: derived.hash,
          deviceResponse,
        });
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_two_step_passkey_added'));
        return settings;
      },

      async deleteTwoFactorPasskey(id: number, masterPassword: string): Promise<TwoFactorPasskeySettings> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const settings = await deleteTwoFactorPasskeyApi(authedFetch, { id, masterPasswordHash: derived.hash });
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_two_step_passkey_removed'));
        return settings;
      },

      async disableTwoFactorPasskeys(masterPassword: string): Promise<void> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        await disableTwoFactorPasskeysApi(authedFetch, derived.hash);
        await refetchTwoFactorStatus();
        onNotify('success', t('txt_two_step_passkeys_disabled'));
      },

      async getRecoveryCode(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const code = await getTotpRecoveryCode(authedFetch, derived.hash);
        if (!code) throw new Error(t('txt_recovery_code_is_empty'));
        return code;
      },

      async getApiKey(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const key = await getApiKey(authedFetch, derived.hash);
        if (!key) throw new Error(t('txt_api_key_is_empty'));
        return key;
      },

      async rotateApiKey(masterPassword: string): Promise<string> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalized = String(masterPassword || '');
        if (!normalized) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalized, defaultKdfIterations);
        const key = await rotateApiKey(authedFetch, derived.hash);
        if (!key) throw new Error(t('txt_api_key_is_empty'));
        return key;
      },

      async listAccountPasskeys(): Promise<AccountPasskeyCredential[]> {
        return listAccountPasskeys(authedFetch);
      },

      async createAccountPasskey(name: string, masterPassword: string, directUnlock: boolean): Promise<AccountPasskeyCredential | null> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalizedPassword = String(masterPassword || '');
        if (!normalizedPassword) throw new Error(t('txt_master_password_is_required'));
        const normalizedName = String(name || '').trim() || t('txt_account_passkey');
        const derived = await deriveLoginHash(profile.email, normalizedPassword, defaultKdfIterations);
        const options = await getAccountPasskeyAttestationOptions(authedFetch, derived.hash);
        const pending = await createAccountPasskeyCredential(options, directUnlock);
        let keySet = null;
        let savedWithoutDirectUnlock = false;
        if (directUnlock) {
          if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
          if (!pending.supportsPrf) {
            const shouldSaveLoginOnly = await confirmSaveLoginOnlyAccountPasskey();
            if (!shouldSaveLoginOnly) {
              onNotify('warning', t('txt_account_passkey_not_saved'));
              return null;
            }
            savedWithoutDirectUnlock = true;
          } else {
            try {
              keySet = await buildAccountPasskeyPrfKeySet(pending, {
                symEncKey: session.symEncKey,
                symMacKey: session.symMacKey,
              });
            } catch (error) {
              if (!(error instanceof AccountPasskeyPrfUnavailableError)) throw error;
              const shouldSaveLoginOnly = await confirmSaveLoginOnlyAccountPasskey();
              if (!shouldSaveLoginOnly) {
                onNotify('warning', t('txt_account_passkey_not_saved'));
                return null;
              }
              savedWithoutDirectUnlock = true;
            }
          }
        }
        const credential = await saveAccountPasskey(authedFetch, {
          name: normalizedName,
          token: pending.token,
          deviceResponse: pending.request,
          supportsPrf: keySet ? true : savedWithoutDirectUnlock ? false : pending.supportsPrf,
          keySet,
        });
        onNotify('success', savedWithoutDirectUnlock ? t('txt_account_passkey_saved_login_only') : t('txt_account_passkey_saved'));
        return credential;
      },

      async enableAccountPasskeyDirectUnlock(id: string, masterPassword: string): Promise<void> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        if (!session?.symEncKey || !session?.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
        if (!String(id || '').trim()) throw new Error(t('txt_account_passkey_not_found'));
        const normalizedPassword = String(masterPassword || '');
        if (!normalizedPassword) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalizedPassword, defaultKdfIterations);
        const options = await getAccountPasskeyUpdateAssertionOptions(authedFetch, derived.hash, id);
        const assertion = await assertAccountPasskey(options);
        if (!assertion.prfKey) throw new Error(t('txt_account_passkey_prf_not_available'));
        const keySet = await buildAccountPasskeyPrfKeySetFromPrfKey(assertion.prfKey, {
          symEncKey: session.symEncKey,
          symMacKey: session.symMacKey,
        });
        await enableAccountPasskeyDirectUnlockApi(authedFetch, {
          token: assertion.token,
          deviceResponse: assertion.deviceResponse,
          keySet,
        });
        onNotify('success', t('txt_account_passkey_direct_unlock_enabled'));
      },

      async deleteAccountPasskey(id: string, masterPassword: string): Promise<void> {
        if (!profile) throw new Error(t('txt_profile_unavailable'));
        const normalizedPassword = String(masterPassword || '');
        if (!normalizedPassword) throw new Error(t('txt_master_password_is_required'));
        const derived = await deriveLoginHash(profile.email, normalizedPassword, defaultKdfIterations);
        await deleteAccountPasskeyApi(authedFetch, id, derived.hash);
        onNotify('success', t('txt_account_passkey_deleted'));
      },

      async refreshAuthorizedDevices() {
        await refetchAuthorizedDevices();
      },

      async renameAuthorizedDevice(device: AuthorizedDevice, name: string) {
        const normalized = String(name || '').trim();
        if (!normalized) {
          onNotify('error', t('txt_device_note_required'));
          return;
        }
        try {
          await updateAuthorizedDeviceName(authedFetch, device.identifier, normalized);
          await refetchAuthorizedDevices();
          onNotify('success', t('txt_device_note_updated'));
        } catch (error) {
          onNotify('error', error instanceof Error ? error.message : t('txt_update_device_note_failed'));
        }
      },

      openRevokeDeviceTrust(device: AuthorizedDevice) {
        onSetConfirm({
          title: t('txt_revoke_device_authorization'),
          message: t('txt_revoke_30_day_totp_trust_for_name', { name: device.name }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await revokeAuthorizedDeviceTrust(authedFetch, device.identifier);
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_device_authorization_revoked'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_revoke_device_trust_failed'));
              }
            })();
          },
        });
      },

      openTrustDevicePermanently(device: AuthorizedDevice) {
        onSetConfirm({
          title: t('txt_trust_device_permanently'),
          message: t('txt_trust_device_permanently_for_name', { name: device.name }),
          danger: false,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await trustAuthorizedDevicePermanently(authedFetch, device.identifier);
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_device_trusted_permanently'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_trust_device_permanently_failed'));
              }
            })();
          },
        });
      },

      openRemoveDevice(device: AuthorizedDevice) {
        onSetConfirm({
          title: t('txt_remove_device'),
          message: t('txt_remove_device_and_sign_out_name', { name: device.name }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await deleteAuthorizedDevice(authedFetch, device.identifier);
                if (device.identifier === getCurrentDeviceIdentifier()) {
                  onNotify('success', t('txt_device_removed'));
                  onLogoutNow();
                  return;
                }
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_device_removed'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_remove_device_failed'));
              }
            })();
          },
        });
      },

      openRemoveSelectedDevices(devices: AuthorizedDevice[]) {
        const selectedDevices = devices.filter((device) => String(device.identifier || '').trim());
        if (selectedDevices.length === 0) {
          onNotify('warning', t('txt_no_devices_selected'));
          return;
        }
        const includesCurrentDevice = selectedDevices.some((device) => device.identifier === getCurrentDeviceIdentifier());
        onSetConfirm({
          title: t('txt_remove_selected_devices', { count: selectedDevices.length }),
          message: includesCurrentDevice
            ? t('txt_remove_selected_devices_and_sign_out_current', { count: selectedDevices.length })
            : t('txt_remove_selected_devices_confirm', { count: selectedDevices.length }),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await deleteAuthorizedDevices(authedFetch, selectedDevices);
                onNotify('success', t('txt_selected_devices_removed', { count: selectedDevices.length }));
                if (includesCurrentDevice) {
                  onLogoutNow();
                  return;
                }
                await refetchAuthorizedDevices();
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_remove_selected_devices_failed'));
              }
            })();
          },
        });
      },

      openRevokeAllDeviceTrust() {
        onSetConfirm({
          title: t('txt_revoke_all_trusted_devices'),
          message: t('txt_revoke_30_day_totp_trust_from_all_devices'),
          danger: true,
          onConfirm: () => {
            onSetConfirm(null);
            void (async () => {
              try {
                await revokeAllAuthorizedDeviceTrust(authedFetch);
                await refetchAuthorizedDevices();
                onNotify('success', t('txt_all_device_authorizations_revoked'));
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_revoke_all_device_trust_failed'));
              }
            })();
          },
        });
      },

      openRemoveAllDevices() {
        onSetConfirm({
          title: t('txt_remove_all_devices'),
          message: `${t('txt_remove_all_devices_and_sign_out_all_sessions')}\n${t('txt_enter_master_password_to_continue')}`,
          danger: true,
          requireMasterPassword: true,
          onConfirm: (masterPassword) => {
            onSetConfirm(null);
            void (async () => {
              try {
                if (!profile) throw new Error(t('txt_profile_unavailable'));
                const normalizedPassword = String(masterPassword || '');
                if (!normalizedPassword.trim()) throw new Error(t('txt_master_password_is_required'));
                const derived = await deriveLoginHash(profile.email, normalizedPassword, defaultKdfIterations);
                await deleteAllAuthorizedDevices(authedFetch, derived.hash);
                onNotify('success', t('txt_all_devices_removed'));
                onLogoutNow();
              } catch (error) {
                onNotify('error', error instanceof Error ? error.message : t('txt_remove_all_devices_failed'));
              }
            })();
          },
        });
      },
      });
    },
    [
      authedFetch,
      clearDisableTotpDialog,
      defaultKdfIterations,
      disableTotpPassword,
      onLogoutNow,
      onNotify,
      onProfileUpdated,
      onSetConfirm,
      profile,
      session?.symEncKey,
      session?.symMacKey,
      refetchAuthorizedDevices,
      refetchTwoFactorStatus,
    ]
  );
}
