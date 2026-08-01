import { useEffect, useMemo, useState } from 'preact/hooks';
import ConfirmDialog from '@/components/ConfirmDialog';
import ToastHost from '@/components/ToastHost';
import { t } from '@/lib/i18n';
import type { ToastMessage } from '@/lib/types';

export interface AppConfirmState {
  title: string;
  message: string;
  danger?: boolean;
  showIcon?: boolean;
  confirmText?: string;
  cancelText?: string;
  hideCancel?: boolean;
  /** When true, dialog shows a master-password field and passes it to onConfirm. */
  requireMasterPassword?: boolean;
  onConfirm: (masterPassword?: string) => void;
  onCancel?: () => void;
}

interface AppGlobalOverlaysProps {
  toasts: ToastMessage[];
  onCloseToast: (id: string) => void;
  confirm: AppConfirmState | null;
  onCancelConfirm: () => void;
  pendingTotpOpen: boolean;
  pendingTotpProviderType?: number;
  pendingTotpAvailableProviders?: number[];
  totpCode: string;
  rememberDevice: boolean;
  onTotpCodeChange: (value: string) => void;
  onRememberDeviceChange: (checked: boolean) => void;
  onConfirmTotp: () => void;
  onSelectTotpProvider: (providerType: number) => void;
  onCancelTotp: () => void;
  onUseRecoveryCode: () => void;
  totpSubmitting: boolean;
  disableTotpOpen: boolean;
  disableTotpPassword: string;
  onDisableTotpPasswordChange: (value: string) => void;
  onConfirmDisableTotp: () => void;
  onCancelDisableTotp: () => void;
  disableTotpSubmitting: boolean;
}

const TWO_FACTOR_PROVIDER_AUTHENTICATOR = 0;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;
const TWO_FACTOR_PROVIDER_ORDER = [
  TWO_FACTOR_PROVIDER_WEBAUTHN,
  TWO_FACTOR_PROVIDER_YUBIKEY,
  TWO_FACTOR_PROVIDER_AUTHENTICATOR,
] as const;

function uniqueSupportedProviders(providerTypes: number[] | undefined): number[] {
  const available = new Set(providerTypes || []);
  return TWO_FACTOR_PROVIDER_ORDER.filter((provider) => available.has(provider));
}

function twoFactorProviderLabel(providerType: number): string {
  if (providerType === TWO_FACTOR_PROVIDER_WEBAUTHN) return t('txt_passkey');
  if (providerType === TWO_FACTOR_PROVIDER_YUBIKEY) return t('txt_otp_from_yubikey');
  return t('txt_authenticator_app');
}

export default function AppGlobalOverlays(props: AppGlobalOverlaysProps) {
  const [methodChooserOpen, setMethodChooserOpen] = useState(false);
  const [confirmPassword, setConfirmPassword] = useState('');
  const availableProviders = useMemo(
    () => uniqueSupportedProviders(props.pendingTotpAvailableProviders),
    [props.pendingTotpAvailableProviders]
  );
  const alternateProviders = availableProviders.filter((provider) => provider !== props.pendingTotpProviderType);
  const isYubiKeyOtp = props.pendingTotpProviderType === TWO_FACTOR_PROVIDER_YUBIKEY;
  const isWebAuthn = props.pendingTotpProviderType === TWO_FACTOR_PROVIDER_WEBAUTHN;
  const requireMasterPassword = !!props.confirm?.requireMasterPassword;

  useEffect(() => {
    setMethodChooserOpen(false);
  }, [props.pendingTotpOpen, props.pendingTotpProviderType]);

  useEffect(() => {
    setConfirmPassword('');
  }, [props.confirm?.title, props.confirm?.message, requireMasterPassword]);

  return (
    <>
      <ConfirmDialog
        open={!!props.confirm}
        title={props.confirm?.title || ''}
        message={props.confirm?.message || ''}
        danger={props.confirm?.danger}
        showIcon={props.confirm?.showIcon}
        confirmText={props.confirm?.confirmText}
        cancelText={props.confirm?.cancelText}
        hideCancel={props.confirm?.hideCancel}
        confirmDisabled={requireMasterPassword && !confirmPassword.trim()}
        onConfirm={() => {
          if (requireMasterPassword && !confirmPassword.trim()) return;
          props.confirm?.onConfirm(requireMasterPassword ? confirmPassword : undefined);
          setConfirmPassword('');
        }}
        onCancel={() => {
          setConfirmPassword('');
          (props.confirm?.onCancel || props.onCancelConfirm)();
        }}
      >
        {requireMasterPassword && (
          <label className="field">
            <span>{t('txt_master_password')}</span>
            <input
              className="input"
              type="password"
              autoComplete="current-password"
              value={confirmPassword}
              onInput={(e) => setConfirmPassword((e.currentTarget as HTMLInputElement).value)}
            />
          </label>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={props.pendingTotpOpen}
        title={isYubiKeyOtp ? `${t('txt_two_step_verification')} YubiKey` : isWebAuthn ? (
          <span className="dialog-title-stack">
            <span>{t('txt_two_step_verification')}</span>
            <span>{t('txt_passkey')}</span>
          </span>
        ) : t('txt_two_step_verification')}
        message={isYubiKeyOtp ? t('txt_press_yubikey_to_authenticate') : isWebAuthn ? t('txt_use_passkey_to_complete_two_step_verification') : t('txt_password_is_already_verified')}
        confirmText={t('txt_verify')}
        hideCancel
        closeButton
        showIcon={false}
        confirmDisabled={props.totpSubmitting}
        cancelDisabled={props.totpSubmitting}
        onConfirm={props.onConfirmTotp}
        onCancel={props.onCancelTotp}
        afterActions={(
          <div className="dialog-extra">
            <div className="dialog-divider" />
            {alternateProviders.length > 0 && (
              <div className="two-factor-method-switcher">
                <button
                  type="button"
                  className="btn btn-secondary dialog-btn"
                  disabled={props.totpSubmitting}
                  aria-expanded={methodChooserOpen}
                  onClick={() => setMethodChooserOpen((open) => !open)}
                >
                  {t('txt_select_another_verification_method')}
                </button>
                {methodChooserOpen && (
                  <div className="two-factor-method-list" role="list" aria-label={t('txt_select_two_step_login_method')}>
                    <div className="two-factor-method-label">{t('txt_select_two_step_login_method')}</div>
                    {alternateProviders.map((providerType) => (
                      <button
                        key={providerType}
                        type="button"
                        className="btn btn-secondary two-factor-method-option"
                        disabled={props.totpSubmitting}
                        onClick={() => {
                          setMethodChooserOpen(false);
                          props.onSelectTotpProvider(providerType);
                        }}
                      >
                        {twoFactorProviderLabel(providerType)}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
            <button type="button" className="btn btn-secondary dialog-btn" disabled={props.totpSubmitting} onClick={props.onUseRecoveryCode}>
              {t('txt_use_recovery_code')}
            </button>
          </div>
        )}
      >
        {isWebAuthn ? (
          <p className="muted-inline settings-field-note">{t('txt_touch_your_passkey_when_prompted')}</p>
        ) : (
          <label className="field">
            <span>{isYubiKeyOtp ? t('txt_otp_from_yubikey') : t('txt_totp_code')}</span>
            <input className="input" type={isYubiKeyOtp ? 'password' : 'text'} value={props.totpCode} autoComplete="one-time-code" onInput={(e) => props.onTotpCodeChange((e.currentTarget as HTMLInputElement).value)} />
          </label>
        )}
        <label className="check-line check-line-compact">
          <input type="checkbox" checked={props.rememberDevice} onChange={(e) => props.onRememberDeviceChange((e.currentTarget as HTMLInputElement).checked)} />
          <span>{t('txt_trust_this_device_for_30_days')}</span>
        </label>
      </ConfirmDialog>

      <ConfirmDialog
        open={props.disableTotpOpen}
        title={t('txt_disable_totp')}
        message={t('txt_enter_master_password_to_disable_two_step_verification')}
        confirmText={t('txt_disable_totp')}
        hideCancel
        closeButton
        danger
        showIcon={false}
        confirmDisabled={props.disableTotpSubmitting}
        cancelDisabled={props.disableTotpSubmitting}
        onConfirm={props.onConfirmDisableTotp}
        onCancel={props.onCancelDisableTotp}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input className="input" type="password" autoComplete="current-password" value={props.disableTotpPassword} onInput={(e) => props.onDisableTotpPasswordChange((e.currentTarget as HTMLInputElement).value)} />
        </label>
      </ConfirmDialog>

      <ToastHost toasts={props.toasts} onClose={props.onCloseToast} />
    </>
  );
}
