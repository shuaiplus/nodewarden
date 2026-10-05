import { useState } from 'preact/hooks';
import { Clipboard, Eye, EyeOff, LogIn, Send, X } from 'lucide-preact';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { copyTextToClipboard } from '@/lib/clipboard';
import { t } from '@/lib/i18n';

interface RecoverTwoFactorPageProps {
  values?: { email: string; password: string; recoveryCode: string };
  onChange?: (next: { email: string; password: string; recoveryCode: string }) => void;
  onSubmit?: () => void;
  onCancel?: () => void;
  // Present once the recovery code was accepted: two-step login is off and no session was created,
  // so the only sensible follow-up is to sign in again. The form props above are ignored here.
  recovered?: boolean;
  newRecoveryCode?: string;
  onSignIn?: () => void;
}

export default function RecoverTwoFactorPage(props: RecoverTwoFactorPageProps) {
  const [showPassword, setShowPassword] = useState(false);

  if (props.recovered) {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_two_step_verification_disabled')}>
          <p className="muted standalone-muted">{t('txt_recovery_code_used_two_step_disabled')}</p>

          {props.newRecoveryCode && (
            <label className="field">
              <span>{t('txt_new_recovery_code')}</span>
              <div className="totp-secret-input-wrap">
                {/* Read-only on purpose: it comes from the server, it is not editable. */}
                <input className="input totp-secret-input" value={props.newRecoveryCode} readOnly />
                <div className="totp-secret-actions">
                  <button
                    type="button"
                    className="btn btn-secondary small totp-secret-icon-btn"
                    title={t('txt_copy_code')}
                    aria-label={t('txt_copy_code')}
                    onClick={() => {
                      void copyTextToClipboard(props.newRecoveryCode || '', { successMessage: t('txt_recovery_code_copied') });
                    }}
                  >
                    <Clipboard size={14} className="btn-icon" />
                  </button>
                </div>
              </div>
            </label>
          )}

          <div className="field-grid">
            <button type="button" className="btn btn-primary" onClick={props.onSignIn}>
              <LogIn size={14} className="btn-icon" />
              {t('txt_sign_in_again')}
            </button>
          </div>
        </StandalonePageFrame>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <StandalonePageFrame title={t('txt_recover_two_step_login')}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            props.onSubmit?.();
          }}
        >
          <p className="muted standalone-muted">{t('txt_use_your_one_time_recovery_code_to_disable_two_step_verification')}</p>

          <label className="field">
            <span>{t('txt_email')}</span>
            <input
              className="input"
              type="email"
              value={props.values?.email ?? ''}
              autoComplete="username"
              onInput={(e) => props.onChange?.({ ...(props.values ?? { email: '', password: '', recoveryCode: '' }), email: (e.currentTarget as HTMLInputElement).value })}
            />
          </label>

          <label className="field">
            <span>{t('txt_master_password')}</span>
            <div className="password-wrap">
              <input
                className="input"
                type={showPassword ? 'text' : 'password'}
                value={props.values?.password ?? ''}
                autoComplete="current-password"
                onInput={(e) => props.onChange?.({ ...(props.values ?? { email: '', password: '', recoveryCode: '' }), password: (e.currentTarget as HTMLInputElement).value })}
              />
              <button type="button" className="eye-btn" onClick={() => setShowPassword((v) => !v)}>
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </label>

          <label className="field">
            <span>{t('txt_recovery_code')}</span>
            <input
              className="input"
              value={props.values?.recoveryCode ?? ''}
              autoComplete="one-time-code"
              onInput={(e) => props.onChange?.({ ...(props.values ?? { email: '', password: '', recoveryCode: '' }), recoveryCode: (e.currentTarget as HTMLInputElement).value.toUpperCase() })}
            />
          </label>

          <div className="field-grid">
            <button type="submit" className="btn btn-primary">
              <Send size={14} className="btn-icon" />
              {t('txt_submit')}
            </button>
            <button type="button" className="btn btn-secondary" onClick={props.onCancel}>
              <X size={14} className="btn-icon" />
              {t('txt_cancel')}
            </button>
          </div>
        </form>
      </StandalonePageFrame>
    </div>
  );
}
