import { useEffect, useState } from 'preact/hooks';
import { AlertTriangle, ArrowLeft, Eye, EyeOff, KeyRound, LogIn, LogOut, Unlock, UserPlus } from 'lucide-preact';
import NetworkStatusBadge from '@/components/NetworkStatusBadge';
import StandalonePageFrame from '@/components/StandalonePageFrame';
import { t } from '@/lib/i18n';
import { getCurrentNetworkStatus, subscribeNetworkStatus, type NetworkStatus } from '@/lib/network-status';

interface LoginValues {
  email: string;
  password: string;
}

interface RegisterValues {
  name: string;
  email: string;
  password: string;
  password2: string;
  passwordHint: string;
  inviteCode: string;
}

interface AuthViewsProps {
  mode: 'login' | 'register' | 'locked';
  relaxedLoginInput?: boolean;
  authPlaceholder?: string;
  unlockPlaceholder?: string;
  pendingAction: 'login' | 'passkey' | 'register' | 'unlock' | null;
  unlockReady: boolean;
  unlockPreparing: boolean;
  sessionRefreshError?: string;
  loginValues: LoginValues;
  pendingPasskeyPasswordEmail?: string | null;
  passkeyPassword: string;
  registerValues: RegisterValues;
  registrationInviteRequired?: boolean;
  unlockPassword: string;
  emailForLock: string;
  loginHintLoading: boolean;
  onChangeLogin: (next: LoginValues) => void;
  onChangePasskeyPassword: (password: string) => void;
  onChangeRegister: (next: RegisterValues) => void;
  onChangeUnlock: (password: string) => void;
  onSubmitLogin: () => void;
  onSubmitPasskey: () => void;
  onSubmitPasskeyUnlock: () => void;
  onSubmitPasskeyPassword: () => void;
  onSubmitRegister: () => void;
  onSubmitUnlock: () => void;
  onGotoLogin: () => void;
  onGotoRegister: () => void;
  onLogout: () => void;
  onTogglePasswordHint: () => void;
  onShowLockedPasswordHint: () => void;
  onRetrySessionRefresh: () => void;
}

function PasswordField(props: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  autoFocus?: boolean;
  autoComplete?: string;
  placeholder?: string;
}) {
  const [show, setShow] = useState(false);
  return (
    <label className="field">
      <span>{props.label}</span>
      <div className="password-wrap">
        <input
          className="input"
          type={show ? 'text' : 'password'}
          value={props.value}
          onInput={(e) => props.onInput((e.currentTarget as HTMLInputElement).value)}
          autoFocus={props.autoFocus}
          autoComplete={props.autoComplete}
          placeholder={props.placeholder}
        />
        <button type="button" className="eye-btn" onClick={() => setShow((v) => !v)}>
          {show ? <EyeOff size={16} /> : <Eye size={16} />}
        </button>
      </div>
    </label>
  );
}

function OfflineModeNotice() {
  const [status, setStatus] = useState<NetworkStatus>(getCurrentNetworkStatus);

  useEffect(() => subscribeNetworkStatus(setStatus), []);

  if (status !== 'offline') return null;

  return (
    <div className="offline-mode-notice" role="alert" aria-live="assertive">
      <div>
        <strong>{t('txt_offline_mode_notice_title')}</strong>
        <div className="offline-shortcut-list">
          <div className="offline-shortcut-row">
            <span className="offline-shortcut-label">{t('txt_offline_mode_notice_windows')}</span>
            <span className="offline-shortcut-value">
              <span className="offline-shortcut-chord"><kbd>Ctrl</kbd><span>+</span><kbd>F5</kbd></span>
            </span>
          </div>
          <div className="offline-shortcut-row">
            <span className="offline-shortcut-label">{t('txt_offline_mode_notice_macos')}</span>
            <span className="offline-shortcut-value">
              <span className="offline-shortcut-chord"><kbd>Command</kbd><span>+</span><kbd>Shift</kbd><span>+</span><kbd>R</kbd></span>
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function AuthViews(props: AuthViewsProps) {
  const loginBusy = props.pendingAction === 'login';
  const passkeyBusy = props.pendingAction === 'passkey';
  const registerBusy = props.pendingAction === 'register';
  const unlockBusy = props.pendingAction === 'unlock';
  const passkeyPasswordPending = !!props.pendingPasskeyPasswordEmail;
  const showInviteCodeField = props.registrationInviteRequired !== false || !!props.registerValues.inviteCode.trim();

  if (props.mode === 'locked') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_unlock_vault')} titleAccessory={<NetworkStatusBadge />}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              props.onSubmitUnlock();
            }}
          >
            <OfflineModeNotice />
            <p className="muted standalone-muted">{props.emailForLock}</p>
            <input type="text" value={props.emailForLock} autoComplete="username" readOnly hidden tabIndex={-1} aria-hidden="true" />
            <PasswordField
              label={t('txt_master_password')}
              value={props.unlockPassword}
              autoFocus
              autoComplete="current-password"
              placeholder={props.unlockPlaceholder}
              onInput={props.onChangeUnlock}
            />
            <div className="auth-support-row">
              <span />
              <button
                type="button"
                className="auth-link-btn"
                onClick={props.onShowLockedPasswordHint}
                disabled={unlockBusy || props.unlockPreparing}
              >
                {t('txt_show_password_hint')}
              </button>
            </div>
            {props.unlockPreparing ? (
              <p className="muted standalone-muted">{t('txt_loading')}</p>
            ) : null}
            {props.sessionRefreshError ? (
              <div className="offline-mode-notice" role="alert" aria-live="polite">
                <AlertTriangle size={18} />
                <div>
                  <strong>{props.sessionRefreshError}</strong>
                  <div>
                    <button type="button" className="auth-link-btn" onClick={props.onRetrySessionRefresh}>
                      {t('txt_refresh')}
                    </button>
                  </div>
                </div>
              </div>
            ) : null}
            <button type="submit" className="btn btn-primary full" disabled={unlockBusy || passkeyBusy || props.unlockPreparing || !props.unlockReady}>
              <Unlock size={16} className="btn-icon" />
              {unlockBusy ? t('txt_unlocking') : props.unlockPreparing ? t('txt_loading') : t('txt_unlock')}
            </button>
            <button
              type="button"
              className="btn btn-secondary full"
              onClick={props.onSubmitPasskeyUnlock}
              disabled={unlockBusy || passkeyBusy || props.unlockPreparing || !props.unlockReady}
            >
              <KeyRound size={16} className="btn-icon" />
              {passkeyBusy ? t('txt_unlocking') : t('txt_unlock_with_passkey')}
            </button>
            <div className="or">{t('txt_or')}</div>
            <button type="button" className="btn btn-secondary full" onClick={props.onLogout} disabled={unlockBusy || passkeyBusy}>
              <LogOut size={16} className="btn-icon" />
              {t('txt_log_out')}
            </button>
          </form>
        </StandalonePageFrame>
      </div>
    );
  }

  if (props.mode === 'register') {
    return (
      <div className="auth-page">
        <StandalonePageFrame title={t('txt_create_account')} titleAccessory={<NetworkStatusBadge />}>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              props.onSubmitRegister();
            }}
          >
            <label className="field">
              <span>{t('txt_name')}</span>
              <input
                className="input"
                value={props.registerValues.name}
                autoComplete="name"
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, name: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            <label className="field">
              <span>{t('txt_email')}</span>
              <input
                className="input"
                type="email"
                value={props.registerValues.email}
                autoComplete="email"
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, email: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            <PasswordField
              label={t('txt_master_password')}
              value={props.registerValues.password}
              autoComplete="new-password"
              onInput={(v) => props.onChangeRegister({ ...props.registerValues, password: v })}
            />
            <PasswordField
              label={t('txt_confirm_master_password')}
              value={props.registerValues.password2}
              autoComplete="new-password"
              onInput={(v) => props.onChangeRegister({ ...props.registerValues, password2: v })}
            />
            <label className="field">
              <span>{t('txt_password_hint_optional')}</span>
              <input
                className="input"
                maxLength={120}
                value={props.registerValues.passwordHint}
                placeholder={t('txt_password_hint_register_placeholder')}
                onInput={(e) =>
                  props.onChangeRegister({ ...props.registerValues, passwordHint: (e.currentTarget as HTMLInputElement).value })
                }
              />
            </label>
            {showInviteCodeField ? (
              <label className="field">
                <span>{t('txt_invite_code_required')}</span>
                <input
                  className="input"
                  value={props.registerValues.inviteCode}
                  autoComplete="off"
                  onInput={(e) =>
                    props.onChangeRegister({ ...props.registerValues, inviteCode: (e.currentTarget as HTMLInputElement).value })
                  }
                />
              </label>
            ) : null}
            <button type="submit" className="btn btn-primary full" disabled={registerBusy}>
              <UserPlus size={16} className="btn-icon" />
              {registerBusy ? t('txt_registering') : t('txt_create_account')}
            </button>
            <div className="or">{t('txt_or')}</div>
            <button type="button" className="btn btn-secondary full" onClick={props.onGotoLogin} disabled={registerBusy}>
              <ArrowLeft size={16} className="btn-icon" />
              {t('txt_back_to_login')}
            </button>
          </form>
        </StandalonePageFrame>
      </div>
    );
  }

  return (
    <div className="auth-page">
      <StandalonePageFrame title={t('txt_log_in')} titleAccessory={<NetworkStatusBadge />}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (passkeyPasswordPending) {
              props.onSubmitPasskeyPassword();
              return;
            }
            props.onSubmitLogin();
          }}
        >
          <OfflineModeNotice />
          {passkeyPasswordPending ? (
            <>
              <p className="muted standalone-muted">{props.pendingPasskeyPasswordEmail}</p>
              <input type="text" value={props.pendingPasskeyPasswordEmail || ''} autoComplete="username" readOnly hidden tabIndex={-1} aria-hidden="true" />
              <PasswordField
                label={t('txt_master_password')}
                value={props.passkeyPassword}
                autoFocus
                autoComplete="current-password"
                placeholder={props.authPlaceholder}
                onInput={props.onChangePasskeyPassword}
              />
              <button type="submit" className="btn btn-primary full" disabled={loginBusy}>
                <Unlock size={16} className="btn-icon" />
                {loginBusy ? t('txt_unlocking') : t('txt_unlock')}
              </button>
              <div className="or">{t('txt_or')}</div>
              <button type="button" className="btn btn-secondary full" onClick={props.onGotoLogin} disabled={loginBusy}>
                <ArrowLeft size={16} className="btn-icon" />
                {t('txt_back_to_login')}
              </button>
            </>
          ) : (
            <>
          <label className="field">
            <span>{t('txt_email')}</span>
            <input
              className="input"
              type={props.relaxedLoginInput ? 'text' : 'email'}
              value={props.loginValues.email}
              autoComplete="username"
              placeholder={props.authPlaceholder}
              autoFocus
              onInput={(e) => props.onChangeLogin({ ...props.loginValues, email: (e.currentTarget as HTMLInputElement).value })}
            />
          </label>
          <PasswordField
            label={t('txt_master_password')}
            value={props.loginValues.password}
            autoComplete="current-password"
            placeholder={props.authPlaceholder}
            onInput={(v) => props.onChangeLogin({ ...props.loginValues, password: v })}
          />
          <div className="auth-support-row">
            <span />
            <button
              type="button"
              className="auth-link-btn"
              onClick={props.onTogglePasswordHint}
              disabled={loginBusy || props.loginHintLoading || !props.loginValues.email.trim()}
            >
              {props.loginHintLoading
                ? t('txt_loading_password_hint')
                : t('txt_show_password_hint')}
            </button>
          </div>
          <button type="submit" className="btn btn-primary full" disabled={loginBusy || passkeyBusy}>
            <LogIn size={16} className="btn-icon" />
            {loginBusy ? t('txt_logging_in') : t('txt_log_in')}
          </button>
          <button type="button" className="btn btn-secondary full" onClick={props.onSubmitPasskey} disabled={loginBusy || passkeyBusy}>
            <KeyRound size={16} className="btn-icon" />
            {passkeyBusy ? t('txt_logging_in') : t('txt_login_with_passkey')}
          </button>
          <div className="or">{t('txt_or')}</div>
          <button type="button" className="btn btn-secondary full" onClick={props.onGotoRegister} disabled={loginBusy || passkeyBusy}>
            <UserPlus size={16} className="btn-icon" />
            {t('txt_create_account')}
          </button>
            </>
          )}
        </form>
      </StandalonePageFrame>
    </div>
  );
}
