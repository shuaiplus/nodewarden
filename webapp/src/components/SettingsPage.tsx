import { useEffect, useMemo, useState } from 'preact/hooks';
import { Clipboard, KeyRound, RefreshCw, ShieldCheck, ShieldOff, Trash2 } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import qrcode from 'qrcode-generator';
import type { AccountPasskeyCredential, Profile, TotpSetupRequest, TotpSetupResult, TwoFactorAuthenticatorSettings, TwoFactorPasskeyCredential, TwoFactorPasskeySettings, YubiKeyOtpSettings } from '@/lib/types';
import { AVAILABLE_LOCALES, getLocale, setLocale, t, type Locale } from '@/lib/i18n';
import ConfirmDialog from '@/components/ConfirmDialog';

interface SettingsPageProps {
  profile: Profile;
  totpEnabled: boolean;
  yubikeyEnabled: boolean;
  passkey2faEnabled: boolean;
  themePreference: ThemePreference;
  lockTimeoutMinutes: 0 | 1 | 5 | 15 | 30;
  sessionTimeoutAction: 'lock' | 'logout';
  onThemePreferenceChange: (preference: ThemePreference) => void;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onSavePasswordHint: (masterPasswordHint: string) => Promise<void>;
  onStartTotpSetup: (request: TotpSetupRequest) => Promise<TwoFactorAuthenticatorSettings>;
  onVerifyTotpSetup: (key: string, token: string, userVerificationToken: string, rotating: boolean) => Promise<TotpSetupResult>;
  onDisableTotp: (code: string) => Promise<void>;
  onGetYubiKeySettings: (masterPassword: string) => Promise<YubiKeyOtpSettings>;
  onSaveYubiKeySettings: (keys: string[], nfc: boolean, masterPassword: string) => Promise<YubiKeyOtpSettings>;
  onSaveYubiKeyApiCredentials: (clientId: string, secretKey: string, masterPassword: string) => Promise<YubiKeyOtpSettings>;
  onBootstrapYubiKeyApiCredentials: (otp: string, masterPassword: string) => Promise<YubiKeyOtpSettings>;
  onDisableYubiKey: (masterPassword: string) => Promise<void>;
  onGetTwoFactorPasskeySettings: (masterPassword: string) => Promise<TwoFactorPasskeySettings>;
  onCreateTwoFactorPasskey: (name: string, masterPassword: string) => Promise<TwoFactorPasskeySettings>;
  onDeleteTwoFactorPasskey: (id: number, masterPassword: string) => Promise<TwoFactorPasskeySettings>;
  onDisableTwoFactorPasskeys: (masterPassword: string) => Promise<void>;
  onGetRecoveryCode: (masterPassword: string) => Promise<string>;
  onGetApiKey: (masterPassword: string) => Promise<string>;
  onRotateApiKey: (masterPassword: string) => Promise<string>;
  onListAccountPasskeys: () => Promise<AccountPasskeyCredential[]>;
  onCreateAccountPasskey: (name: string, masterPassword: string, directUnlock: boolean) => Promise<AccountPasskeyCredential | null>;
  onEnableAccountPasskeyDirectUnlock: (id: string, masterPassword: string) => Promise<void>;
  onDeleteAccountPasskey: (id: string, masterPassword: string) => Promise<void>;
  onRefreshTwoFactorStatus: () => Promise<void>;
  onLockTimeoutChange: (minutes: 0 | 1 | 5 | 15 | 30) => void;
  onSessionTimeoutActionChange: (action: 'lock' | 'logout') => void;
  onNotify?: (type: 'success' | 'error' | 'warning', text: string) => void;
}

type ThemePreference = 'system' | 'light' | 'dark';
type SettingsSection = 'appearance' | 'session' | 'masterPassword' | 'twoStep' | 'keys';

// Every entry below is a sensitive action confirmed by typing one credential into the same dialog.
// The authenticator app is not one of them: it has its own multi-step dialog (`TotpManageStep`),
// because it needs a master password *and* a second-factor proof, and because the two operations it
// offers (replace the authenticator, turn it off) differ only in what they do at the very end.
type SecurityPromptAction =
  | 'recovery'
  | 'apiKey'
  | 'rotateApiKey'
  | 'manageYubiKey'
  | 'managePasskey2fa'
  | 'createPasskey'
  | 'enablePasskeyDirectUnlock'
  | 'deletePasskey';

// One dialog, four steps. `authenticate` proves the master password (or mints the first key, which
// the server only does behind that same proof), `choose` picks the operation, `verifyCurrent` proves
// the second factor that is in use right now, and `setup` shows the key the server just generated.
type TotpManageStep = 'authenticate' | 'choose' | 'verifyCurrent' | 'setup';
type TotpManageOperation = 'change' | 'disable';

const LOCK_TIMEOUT_OPTIONS = [
  { value: 1, labelKey: 'txt_timeout_1_minute' },
  { value: 5, labelKey: 'txt_timeout_5_minutes' },
  { value: 15, labelKey: 'txt_timeout_15_minutes' },
  { value: 30, labelKey: 'txt_timeout_30_minutes' },
  { value: 0, labelKey: 'txt_timeout_never' },
] as const;

const EMPTY_YUBIKEY_KEYS: [string, string, string, string, string] = ['', '', '', '', ''];

function formatStoredYubiKey(value: string): string {
  if (!value) return '';
  if (value.length >= 44) return value;
  return `${value}${'•'.repeat(44 - value.length)}`;
}

function normalizeYubiKeyFieldValue(value: string): string {
  return value.replace(/\s+/g, '').toLowerCase();
}

// The authenticator key is always generated by the server. This helper only turns the key the
// server returned into the standard otpauth URI the QR code is rendered from.
function buildOtpUri(email: string, secret: string): string {
  const issuer = 'NodeWarden';
  return `otpauth://totp/${encodeURIComponent(`${issuer}:${email}`)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// The setup key can be hand-edited, so it is normalized exactly like the server does before it is
// shown in the QR or submitted: uppercase, drop whitespace and '-' separators, trim trailing '='.
function normalizeTotpSecretInput(input: string): string {
  const raw = String(input || '').toUpperCase();
  let out = '';
  for (const char of raw) {
    if (char === ' ' || char === '\t' || char === '\n' || char === '\r' || char === '-') continue;
    out += char;
  }
  while (out.endsWith('=')) out = out.slice(0, -1);
  return out;
}

// Mirrors the server-side Base32 check: non-empty and made only of the RFC 4648 alphabet. It is a
// client convenience only — the server re-validates the key before committing it.
function isValidTotpSecretInput(input: string): boolean {
  const normalized = normalizeTotpSecretInput(input);
  if (!normalized) return false;
  for (const char of normalized) {
    if ('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char) === -1) return false;
  }
  return true;
}

function clearLegacyTotpSetupSecrets(): void {
  if (typeof window === 'undefined') return;
  const prefix = 'nodewarden.totp.secret.';
  const keys: string[] = [];
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    if (key?.startsWith(prefix)) keys.push(key);
  }
  for (const key of keys) {
    window.localStorage.removeItem(key);
  }
}

function formatDateTime(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return t('txt_dash');
  return date.toLocaleString();
}

export default function SettingsPage(props: SettingsPageProps) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newPassword2, setNewPassword2] = useState('');
  const [passwordHint, setPasswordHint] = useState(props.profile.masterPasswordHint || '');
  // The setup dialog only ever shows the key the server generated for this request. Nothing here is
  // produced client-side, and nothing is stored until the server verified a code from that key.
  const [totpSetupKey, setTotpSetupKey] = useState('');
  const [totpSetupToken, setTotpSetupToken] = useState('');
  const [totpSetupUserVerificationToken, setTotpSetupUserVerificationToken] = useState('');
  const [totpSetupRotating, setTotpSetupRotating] = useState(false);
  const [totpSubmitting, setTotpSubmitting] = useState(false);
  const [totpActive, setTotpActive] = useState(props.totpEnabled);
  // Which step of the authenticator dialog is open; null keeps it closed.
  const [totpManageStep, setTotpManageStep] = useState<TotpManageStep | null>(null);
  const [totpManageOperation, setTotpManageOperation] = useState<TotpManageOperation | null>(null);
  const [totpManageValue, setTotpManageValue] = useState('');
  const [totpManageSubmitting, setTotpManageSubmitting] = useState(false);
  // Set only when the server minted or replaced the recovery code (first enable, or a change that
  // consumed the old one): this is the one moment the user can write the new code down.
  const [totpNewRecoveryCode, setTotpNewRecoveryCode] = useState('');
  // Distinguishes "freshly minted" (first enable) from "consumed + replaced" (change authorized
  // with the recovery code) so the notice wording stays accurate.
  const [totpNewRecoveryCodeConsumed, setTotpNewRecoveryCodeConsumed] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [accountPasskeys, setAccountPasskeys] = useState<AccountPasskeyCredential[]>([]);
  const [accountPasskeysLoading, setAccountPasskeysLoading] = useState(false);
  const [accountPasskeyName, setAccountPasskeyName] = useState(t('txt_account_passkey'));
  const [accountPasskeyDirectUnlock, setAccountPasskeyDirectUnlock] = useState(true);
  const [accountPasskeyPromptId, setAccountPasskeyPromptId] = useState<string | null>(null);
  const [createPasskeyDialogOpen, setCreatePasskeyDialogOpen] = useState(false);
  const [createPasskeyMasterPassword, setCreatePasskeyMasterPassword] = useState('');
  const [rotateApiKeyConfirmOpen, setRotateApiKeyConfirmOpen] = useState(false);
  const [apiKeyDialogOpen, setApiKeyDialogOpen] = useState(false);
  const [yubiKeyDialogOpen, setYubiKeyDialogOpen] = useState(false);
  const [yubiKeyMasterPassword, setYubiKeyMasterPassword] = useState('');
  const [yubiKeyEnabled, setYubiKeyEnabled] = useState(props.yubikeyEnabled || !!props.profile.yubikeyEnabled);
  const [yubiKeyKeys, setYubiKeyKeys] = useState<[string, string, string, string, string]>(EMPTY_YUBIKEY_KEYS);
  const [yubiKeyStoredKeys, setYubiKeyStoredKeys] = useState<[string, string, string, string, string]>(EMPTY_YUBIKEY_KEYS);
  const [yubiKeyNfc, setYubiKeyNfc] = useState(false);
  const [yubiKeyYubicoConfigured, setYubiKeyYubicoConfigured] = useState(false);
  const [yubiKeyYubicoCanManage, setYubiKeyYubicoCanManage] = useState(false);
  const [yubiKeyYubicoClientId, setYubiKeyYubicoClientId] = useState('');
  const [yubiKeyYubicoSecretKey, setYubiKeyYubicoSecretKey] = useState('');
  const [yubiKeyBootstrapOtp, setYubiKeyBootstrapOtp] = useState('');
  const [yubiKeyConfigOpen, setYubiKeyConfigOpen] = useState(false);
  const [yubiKeySubmitting, setYubiKeySubmitting] = useState(false);
  const [twoFactorPasskeyEnabled, setTwoFactorPasskeyEnabled] = useState(props.passkey2faEnabled);
  const [twoFactorPasskeys, setTwoFactorPasskeys] = useState<TwoFactorPasskeyCredential[]>([]);
  const [twoFactorPasskeyDialogOpen, setTwoFactorPasskeyDialogOpen] = useState(false);
  const [twoFactorPasskeyMasterPassword, setTwoFactorPasskeyMasterPassword] = useState('');
  const [twoFactorPasskeyName, setTwoFactorPasskeyName] = useState(t('txt_passkey'));
  const [twoFactorPasskeySubmitting, setTwoFactorPasskeySubmitting] = useState(false);
  const [twoFactorStatusRefreshing, setTwoFactorStatusRefreshing] = useState(false);
  const [recoveryCodeDialogOpen, setRecoveryCodeDialogOpen] = useState(false);
  const [securityPrompt, setSecurityPrompt] = useState<SecurityPromptAction | null>(null);
  const [securityPromptValue, setSecurityPromptValue] = useState('');
  const [securityPromptSubmitting, setSecurityPromptSubmitting] = useState(false);
  const [selectedLocale, setSelectedLocale] = useState<Locale>(() => getLocale());
  const [activeSection, setActiveSection] = useState<SettingsSection>('appearance');

  useEffect(() => {
    clearLegacyTotpSetupSecrets();
  }, []);

  useEffect(() => {
    setTotpActive(props.totpEnabled);
    // Turning the authenticator off drops the recovery code with it, so the one-time notice cannot
    // outlive the credential it is about.
    if (!props.totpEnabled) {
      setTotpNewRecoveryCode('');
      setTotpNewRecoveryCodeConsumed(false);
    }
  }, [props.totpEnabled]);

  useEffect(() => {
    setPasswordHint(props.profile.masterPasswordHint || '');
  }, [props.profile.masterPasswordHint]);

  useEffect(() => {
    setYubiKeyEnabled(props.yubikeyEnabled || !!props.profile.yubikeyEnabled);
  }, [props.yubikeyEnabled, props.profile.yubikeyEnabled]);

  useEffect(() => {
    setTwoFactorPasskeyEnabled(props.passkey2faEnabled);
  }, [props.passkey2faEnabled]);

  useEffect(() => {
    void refreshAccountPasskeys();
  }, [props.profile.id]);

  const qrDataUrl = useMemo(() => {
    // The QR always follows the current input: if the user hand-edited the key, the QR reflects the
    // normalized version of what is in the box, never a stale server default.
    const secret = normalizeTotpSecretInput(totpSetupKey);
    if (!secret) return '';
    const qr = qrcode(0, 'M');
    qr.addData(buildOtpUri(props.profile.email, secret));
    qr.make();
    // Keep a visible quiet zone so authenticator apps can scan reliably in both themes.
    const svg = qr.createSvgTag({ scalable: true, margin: 4 });
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  }, [props.profile.email, totpSetupKey]);

  async function refreshAccountPasskeys(): Promise<void> {
    setAccountPasskeysLoading(true);
    try {
      setAccountPasskeys(await props.onListAccountPasskeys());
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_account_passkeys_load_failed'));
    } finally {
      setAccountPasskeysLoading(false);
    }
  }

  function openSecurityPrompt(action: SecurityPromptAction, credentialId?: string): void {
    setSecurityPrompt(action);
    setAccountPasskeyPromptId(credentialId || null);
    setSecurityPromptValue('');
  }

  function closeSecurityPrompt(): void {
    if (securityPromptSubmitting) return;
    setSecurityPrompt(null);
    setAccountPasskeyPromptId(null);
    setSecurityPromptValue('');
  }

  async function submitSecurityPrompt(): Promise<void> {
    if (!securityPrompt || securityPromptSubmitting) return;
    // Whatever the dialog collected: the master password, for every action left in this list.
    const promptValue = securityPromptValue;
    setSecurityPromptSubmitting(true);
    try {
      if (securityPrompt === 'recovery') {
        const code = await props.onGetRecoveryCode(promptValue);
        setRecoveryCode(code);
        setRecoveryCodeDialogOpen(true);
        props.onNotify?.('success', t('txt_recovery_code_loaded'));
      } else if (securityPrompt === 'apiKey') {
        const key = await props.onGetApiKey(promptValue);
        setApiKey(key);
        setApiKeyDialogOpen(true);
      } else if (securityPrompt === 'rotateApiKey') {
        const key = await props.onRotateApiKey(promptValue);
        setApiKey(key);
        setApiKeyDialogOpen(true);
        props.onNotify?.('success', t('txt_api_key_rotated'));
      } else if (securityPrompt === 'manageYubiKey') {
        const settings = await props.onGetYubiKeySettings(promptValue);
        setYubiKeyMasterPassword(promptValue);
        applyYubiKeySettings(settings);
        setYubiKeyConfigOpen(false);
        setYubiKeyDialogOpen(true);
      } else if (securityPrompt === 'managePasskey2fa') {
        const settings = await props.onGetTwoFactorPasskeySettings(promptValue);
        setTwoFactorPasskeyMasterPassword(promptValue);
        applyTwoFactorPasskeySettings(settings);
        setTwoFactorPasskeyName(t('txt_passkey'));
        setTwoFactorPasskeyDialogOpen(true);
      } else if (securityPrompt === 'createPasskey') {
        await props.onVerifyMasterPassword(props.profile.email, promptValue);
        setCreatePasskeyMasterPassword(promptValue);
        setCreatePasskeyDialogOpen(true);
      } else if (securityPrompt === 'enablePasskeyDirectUnlock') {
        if (!accountPasskeyPromptId) throw new Error(t('txt_account_passkey_not_found'));
        await props.onEnableAccountPasskeyDirectUnlock(accountPasskeyPromptId, promptValue);
        await refreshAccountPasskeys();
      } else if (securityPrompt === 'deletePasskey') {
        if (!accountPasskeyPromptId) throw new Error(t('txt_account_passkey_not_found'));
        await props.onDeleteAccountPasskey(accountPasskeyPromptId, promptValue);
        await refreshAccountPasskeys();
      }
      setSecurityPrompt(null);
      setAccountPasskeyPromptId(null);
      setSecurityPromptValue('');
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_master_password_is_required_2'));
    } finally {
      setSecurityPromptSubmitting(false);
    }
  }

  const securityPromptTitle =
    securityPrompt === 'recovery'
      ? t('txt_view_recovery_code')
      : securityPrompt === 'rotateApiKey'
        ? t('txt_rotate_api_key')
        : securityPrompt === 'manageYubiKey'
            ? 'YubiKey'
            : securityPrompt === 'managePasskey2fa'
              ? t('txt_two_step_passkeys')
            : securityPrompt === 'createPasskey'
            ? t('txt_add_account_passkey')
            : securityPrompt === 'enablePasskeyDirectUnlock'
              ? t('txt_enable_passkey_direct_unlock')
              : securityPrompt === 'deletePasskey'
                ? t('txt_delete_account_passkey')
                : t('txt_view_api_key');

  function accountPasskeyStatusText(credential: AccountPasskeyCredential): string {
    if (credential.prfStatus === 0) return t('txt_direct_unlock');
    if (credential.prfStatus === 1) return t('txt_login_only');
    return t('txt_prf_not_supported');
  }

  async function changeLocale(next: Locale): Promise<void> {
    if (next === getLocale()) return;
    setSelectedLocale(next);
    await setLocale(next);
    window.location.reload();
  }

  // The single entry point for everything the Authenticator app row offers. It always starts by
  // asking for the master password: that is the proof of "you may change this account's security
  // settings", and it is asked exactly once — no step below asks for it a second time.
  function openTotpManage(): void {
    setTotpNewRecoveryCode('');
    setTotpNewRecoveryCodeConsumed(false);
    resetTotpManageState();
    setTotpManageStep('authenticate');
  }

  function closeTotpManage(): void {
    if (totpManageSubmitting || totpSubmitting) return;
    resetTotpManageState();
  }

  // Nothing the dialog holds is stored server-side, so cancelling simply drops it: an active
  // authenticator keeps working, and a half-finished rotation leaves the current key untouched.
  function resetTotpManageState(): void {
    setTotpManageStep(null);
    setTotpManageOperation(null);
    setTotpManageValue('');
    setTotpSetupKey('');
    setTotpSetupToken('');
    setTotpSetupUserVerificationToken('');
    setTotpSetupRotating(false);
  }

  function chooseTotpOperation(operation: TotpManageOperation): void {
    setTotpManageOperation(operation);
    setTotpManageValue('');
    setTotpManageStep('verifyCurrent');
  }

  // Shows the key the server just handed out. `rotating` only drives the wording: a replacement key
  // is not stored until a code from it is verified, and it is the *new* key that gets committed, so
  // the account never passes through a state without a working authenticator.
  function startTotpSetupStep(settings: TwoFactorAuthenticatorSettings, rotating: boolean): void {
    setTotpSetupKey(settings.key);
    setTotpSetupUserVerificationToken(settings.userVerificationToken);
    setTotpSetupRotating(rotating && settings.rotating);
    setTotpSetupToken('');
    setTotpActive(settings.enabled);
    setTotpManageValue('');
    setTotpManageStep('setup');
  }

  // One dialog, one prompt per step: what it asks for is what the current step actually needs.
  const totpManageDialogTitle =
    totpManageStep === 'choose'
      ? t('txt_manage_authenticator_app')
      : totpManageStep === 'verifyCurrent'
        ? totpManageOperation === 'disable'
          ? t('txt_disable_totp')
          : t('txt_change_authenticator')
        : totpManageStep === 'setup'
          ? totpSetupRotating
            ? t('txt_change_authenticator')
            : t('txt_authenticator_app')
          : totpActive
            ? t('txt_manage_authenticator_app')
            : t('txt_enable_totp');

  const totpManageDialogMessage =
    totpManageStep === 'choose'
      ? t('txt_manage_authenticator_choose_intro')
      : totpManageStep === 'verifyCurrent'
        ? t('txt_verify_current_second_factor_intro')
        : totpManageStep === 'setup'
          ? totpSetupRotating
            ? t('txt_totp_rotate_intro')
            : t('txt_totp_manage_intro')
          : t('txt_enter_master_password_to_continue');

  const totpManageUsesField = totpManageStep === 'authenticate' || totpManageStep === 'verifyCurrent';

  function applyYubiKeySettings(settings: YubiKeyOtpSettings): void {
    setYubiKeyEnabled(settings.enabled);
    setYubiKeyKeys(settings.keys);
    setYubiKeyStoredKeys(settings.keys);
    setYubiKeyNfc(settings.nfc);
    setYubiKeyYubicoConfigured(settings.yubicoConfigured);
    setYubiKeyYubicoCanManage(settings.yubicoCanManage);
    setYubiKeyYubicoClientId(settings.yubicoClientId);
    setYubiKeyYubicoSecretKey(settings.yubicoSecretKey);
  }

  function closeYubiKeyDialog(): void {
    if (yubiKeySubmitting) return;
    setYubiKeyDialogOpen(false);
    setYubiKeyMasterPassword('');
    setYubiKeyKeys(EMPTY_YUBIKEY_KEYS);
    setYubiKeyStoredKeys(EMPTY_YUBIKEY_KEYS);
    setYubiKeyNfc(false);
    setYubiKeyYubicoConfigured(false);
    setYubiKeyYubicoCanManage(false);
    setYubiKeyYubicoClientId('');
    setYubiKeyYubicoSecretKey('');
    setYubiKeyBootstrapOtp('');
    setYubiKeyConfigOpen(false);
  }

  function updateYubiKey(index: number, value: string): void {
    setYubiKeyKeys((current) => {
      const next = [...current] as [string, string, string, string, string];
      next[index] = value;
      return next;
    });
  }

  async function saveYubiKeyDialog(): Promise<void> {
    if (yubiKeySubmitting) return;
    setYubiKeySubmitting(true);
    try {
      const settings = await props.onSaveYubiKeySettings(yubiKeyKeys.map((value) => value.trim()), yubiKeyNfc, yubiKeyMasterPassword);
      applyYubiKeySettings(settings);
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_yubikey_update_failed'));
    } finally {
      setYubiKeySubmitting(false);
    }
  }

  async function bootstrapYubiKeyConfigDialog(): Promise<void> {
    if (yubiKeySubmitting || !yubiKeyBootstrapOtp.trim()) return;
    const bootstrapOtp = yubiKeyBootstrapOtp.trim().toLowerCase();
    setYubiKeySubmitting(true);
    try {
      const settings = await props.onBootstrapYubiKeyApiCredentials(bootstrapOtp, yubiKeyMasterPassword);
      applyYubiKeySettings(settings);
      setYubiKeyKeys(settings.keys);
      setYubiKeyBootstrapOtp('');
      setYubiKeyConfigOpen(false);
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_yubikey_auto_config_failed'));
    } finally {
      setYubiKeySubmitting(false);
    }
  }

  async function saveYubiKeyConfigDialog(): Promise<void> {
    if (yubiKeySubmitting || !yubiKeyYubicoClientId.trim()) return;
    setYubiKeySubmitting(true);
    try {
      const settings = await props.onSaveYubiKeyApiCredentials(yubiKeyYubicoClientId.trim(), yubiKeyYubicoSecretKey.trim(), yubiKeyMasterPassword);
      applyYubiKeySettings(settings);
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_yubikey_config_update_failed'));
    } finally {
      setYubiKeySubmitting(false);
    }
  }

  async function disableYubiKeyDialog(): Promise<void> {
    if (yubiKeySubmitting || !yubiKeyMasterPassword) return;
    setYubiKeySubmitting(true);
    try {
      await props.onDisableYubiKey(yubiKeyMasterPassword);
      setYubiKeyEnabled(false);
      setYubiKeyKeys(EMPTY_YUBIKEY_KEYS);
      setYubiKeyStoredKeys(EMPTY_YUBIKEY_KEYS);
      setYubiKeyNfc(false);
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_disable_yubikey_failed'));
    } finally {
      setYubiKeySubmitting(false);
    }
  }

  function applyTwoFactorPasskeySettings(settings: TwoFactorPasskeySettings): void {
    setTwoFactorPasskeyEnabled(settings.enabled);
    setTwoFactorPasskeys(settings.keys);
  }

  function closeTwoFactorPasskeyDialog(): void {
    if (twoFactorPasskeySubmitting) return;
    setTwoFactorPasskeyDialogOpen(false);
    setTwoFactorPasskeyMasterPassword('');
    setTwoFactorPasskeyName(t('txt_passkey'));
  }

  async function createTwoFactorPasskeyDialog(): Promise<void> {
    if (twoFactorPasskeySubmitting || !twoFactorPasskeyMasterPassword) return;
    setTwoFactorPasskeySubmitting(true);
    try {
      const settings = await props.onCreateTwoFactorPasskey(twoFactorPasskeyName, twoFactorPasskeyMasterPassword);
      applyTwoFactorPasskeySettings(settings);
      setTwoFactorPasskeyName(t('txt_passkey'));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_passkey_setup_failed'));
    } finally {
      setTwoFactorPasskeySubmitting(false);
    }
  }

  async function deleteTwoFactorPasskeyDialog(id: number): Promise<void> {
    if (twoFactorPasskeySubmitting || !twoFactorPasskeyMasterPassword || twoFactorPasskeys.length < 2) return;
    setTwoFactorPasskeySubmitting(true);
    try {
      applyTwoFactorPasskeySettings(await props.onDeleteTwoFactorPasskey(id, twoFactorPasskeyMasterPassword));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_delete_item_failed'));
    } finally {
      setTwoFactorPasskeySubmitting(false);
    }
  }

  async function disableTwoFactorPasskeysDialog(): Promise<void> {
    if (twoFactorPasskeySubmitting || !twoFactorPasskeyMasterPassword || !twoFactorPasskeyEnabled) return;
    setTwoFactorPasskeySubmitting(true);
    try {
      await props.onDisableTwoFactorPasskeys(twoFactorPasskeyMasterPassword);
      applyTwoFactorPasskeySettings({ enabled: false, keys: [] });
      setTwoFactorPasskeyDialogOpen(false);
      setTwoFactorPasskeyMasterPassword('');
      setTwoFactorPasskeyName(t('txt_passkey'));
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_disable_passkey_two_step_failed'));
    } finally {
      setTwoFactorPasskeySubmitting(false);
    }
  }

  async function refreshTwoFactorStatus(): Promise<void> {
    if (twoFactorStatusRefreshing) return;
    setTwoFactorStatusRefreshing(true);
    try {
      await props.onRefreshTwoFactorStatus();
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_load_failed'));
    } finally {
      setTwoFactorStatusRefreshing(false);
    }
  }

  /**
   * Drives the steps that only collect one credential: the master password, and the second factor
   * that is in use right now. This is the only place a rejection becomes visible, which is why each
   * failure produces exactly one message.
   */
  async function submitTotpManageStep(): Promise<void> {
    if (!totpManageStep || totpManageSubmitting) return;
    const value = totpManageValue;
    setTotpManageSubmitting(true);
    try {
      if (totpManageStep === 'authenticate') {
        if (!totpActive) {
          // Nothing to replace yet: this call mints the first key, and the server only does that
          // behind the same master password check, so the dialog goes straight to the setup step.
          startTotpSetupStep(await props.onStartTotpSetup({ masterPassword: value }), false);
          return;
        }
        // Asked once, here. Change and Disable below reuse this session instead of asking again.
        await props.onVerifyMasterPassword(props.profile.email, value);
        setTotpManageValue('');
        setTotpManageStep('choose');
        return;
      }
      if (totpManageStep === 'verifyCurrent') {
        if (totpManageOperation === 'disable') {
          await props.onDisableTotp(value);
          resetTotpManageState();
          return;
        }
        // Rotation is step-up verified: only once the server accepted the current authenticator code
        // (or the recovery code) does it mint a replacement. The key being replaced keeps working
        // until the replacement is verified, so cancelling anywhere leaves it untouched.
        startTotpSetupStep(await props.onStartTotpSetup({ currentToken: value }), true);
      }
    } catch (error) {
      props.onNotify?.(
        'error',
        error instanceof Error
          ? error.message
          : totpManageStep === 'verifyCurrent'
            ? totpManageOperation === 'disable'
              ? t('txt_disable_totp_failed')
              : t('txt_server_error_invalid_authenticator_code')
            : t('txt_master_password_verify_failed')
      );
    } finally {
      setTotpManageSubmitting(false);
    }
  }

  /**
   * Hands the key the server generated back to the server together with a code derived from it. The
   * server stores the key only when that code is valid, so this is the single step that turns a
   * pending key into the active one — whether it is the first setup or a replacement.
   */
  async function submitTotpSetup(): Promise<void> {
    if (totpSubmitting) return;
    const secret = normalizeTotpSecretInput(totpSetupKey);
    if (!secret || !totpSetupToken.trim() || !totpSetupUserVerificationToken) {
      props.onNotify?.('error', t('txt_secret_and_code_are_required'));
      return;
    }
    if (!isValidTotpSecretInput(secret)) {
      props.onNotify?.('error', t('txt_invalid_totp_secret'));
      return;
    }
    setTotpSubmitting(true);
    try {
      const result = await props.onVerifyTotpSetup(
        secret,
        totpSetupToken,
        totpSetupUserVerificationToken,
        totpSetupRotating
      );
      // A change authorized with the recovery code consumed it, and a first enable mints one: either
      // way the server just handed us the new code, so surface it while it is still on screen. The
      // server also reports which of the two happened, so the wording below never has to guess.
      setTotpNewRecoveryCode(result.recoveryCode || '');
      setTotpNewRecoveryCodeConsumed(result.recoveryCodeConsumed);
      setTotpActive(true);
      resetTotpManageState();
    } catch (error) {
      // Keep the dialog and the key on screen so the user can retry with a fresh code; the key
      // currently in use is still untouched.
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_enable_totp_failed'));
    } finally {
      setTotpSubmitting(false);
    }
  }

  function closeCreatePasskeyDialog(): void {
    setCreatePasskeyDialogOpen(false);
    setCreatePasskeyMasterPassword('');
    setAccountPasskeyName(t('txt_account_passkey'));
    setAccountPasskeyDirectUnlock(true);
  }

  async function submitCreatePasskeyDialog(): Promise<void> {
    if (!createPasskeyMasterPassword || securityPromptSubmitting) return;
    setSecurityPromptSubmitting(true);
    try {
      const credential = await props.onCreateAccountPasskey(accountPasskeyName, createPasskeyMasterPassword, accountPasskeyDirectUnlock);
      if (credential) await refreshAccountPasskeys();
      closeCreatePasskeyDialog();
    } catch (error) {
      props.onNotify?.('error', error instanceof Error ? error.message : t('txt_account_passkeys_load_failed'));
    } finally {
      setSecurityPromptSubmitting(false);
    }
  }

  const settingsSections: Array<{ id: SettingsSection; label: string }> = [
    { id: 'appearance', label: t('txt_settings_appearance') },
    { id: 'session', label: t('txt_session_timeout') },
    { id: 'masterPassword', label: t('txt_master_password') },
    { id: 'twoStep', label: t('txt_two_step_login') },
    { id: 'keys', label: t('txt_keys') },
  ];

  return (
    <div className="settings-page-categorized">
      <div className="settings-category-layout">
        <nav className="settings-category-tabs" aria-label={t('nav_account_settings')}>
          {settingsSections.map((section) => (
            <button
              key={section.id}
              type="button"
              className={`settings-category-tab ${activeSection === section.id ? 'active' : ''}`}
              onClick={() => setActiveSection(section.id)}
            >
              {section.label}
            </button>
          ))}
        </nav>

        <section className="settings-category-panel">
          {activeSection === 'appearance' && (
            <div className="settings-section-stack">
              <section className="settings-submodule">
                <label className="field">
                  <span>{t('txt_theme')}</span>
                  <select
                    className="input"
                    value={props.themePreference}
                    onInput={(e) => props.onThemePreferenceChange((e.currentTarget as HTMLSelectElement).value as ThemePreference)}
                  >
                    <option value="system">{t('txt_use_system_theme')}</option>
                    <option value="light">{t('txt_light_theme')}</option>
                    <option value="dark">{t('txt_dark_theme')}</option>
                  </select>
                  <div className="field-help">{t('txt_theme_saved_locally')}</div>
                </label>
              </section>

              <section className="settings-submodule">
                <label className="field">
                  <span>{t('txt_display_language')}</span>
                  <select
                    className="input"
                    value={selectedLocale}
                    onInput={(e) => void changeLocale((e.currentTarget as HTMLSelectElement).value as Locale)}
                  >
                    {AVAILABLE_LOCALES.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  <div className="field-help">{t('txt_display_language_help')}</div>
                </label>
              </section>
            </div>
          )}

          {activeSection === 'session' && (
            <div className="settings-section-stack">
              <section className="settings-submodule">
                <div className="session-timeout-fields">
                  <label className="field">
                    <span>{t('txt_timeout_time')}</span>
                    <select
                      className="input"
                      value={String(props.lockTimeoutMinutes)}
                      onInput={(e) => props.onLockTimeoutChange(Number((e.currentTarget as HTMLSelectElement).value) as 0 | 1 | 5 | 15 | 30)}
                    >
                      {LOCK_TIMEOUT_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>
                          {t(option.labelKey)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>{t('txt_timeout_action')}</span>
                    <select
                      className="input"
                      value={props.sessionTimeoutAction}
                      onInput={(e) => props.onSessionTimeoutActionChange((e.currentTarget as HTMLSelectElement).value === 'logout' ? 'logout' : 'lock')}
                    >
                      <option value="logout">{t('txt_timeout_action_logout')}</option>
                      <option value="lock">{t('txt_timeout_action_lock')}</option>
                    </select>
                  </label>
                </div>
              </section>
            </div>
          )}

          {activeSection === 'masterPassword' && (
            <div className="settings-section-stack">
              <section className="settings-submodule">
                <h3>{t('txt_change_master_password')}</h3>
                <label className="field">
                  <span>{t('txt_current_password')}</span>
                  <input
                    className="input"
                    type="password"
                    value={currentPassword}
                    onInput={(e) => setCurrentPassword((e.currentTarget as HTMLInputElement).value)}
                  />
                </label>
                <div className="settings-vertical-fields">
                  <label className="field">
                    <span>{t('txt_new_password')}</span>
                    <input className="input" type="password" value={newPassword} onInput={(e) => setNewPassword((e.currentTarget as HTMLInputElement).value)} />
                  </label>
                  <label className="field">
                    <span>{t('txt_confirm_password')}</span>
                    <input className="input" type="password" value={newPassword2} onInput={(e) => setNewPassword2((e.currentTarget as HTMLInputElement).value)} />
                  </label>
                </div>
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => void props.onChangePassword(currentPassword, newPassword, newPassword2)}
                >
                  <KeyRound size={14} className="btn-icon" />
                  {t('txt_change_password')}
                </button>
              </section>

              <section className="settings-submodule">
                <label className="field">
                  <span>{t('txt_password_hint_optional')}</span>
                  <input
                    className="input"
                    maxLength={120}
                    value={passwordHint}
                    placeholder={t('txt_password_hint_placeholder')}
                    onInput={(e) => setPasswordHint((e.currentTarget as HTMLInputElement).value)}
                  />
                  <div className="field-help">{t('txt_password_hint_register_help')}</div>
                </label>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => void props.onSavePasswordHint(passwordHint)}
                >
                  {t('txt_save')}
                </button>
              </section>

              <section className="settings-submodule account-passkeys-module">
                <div className="settings-module-head">
                  <h3>{t('txt_account_passkeys')}</h3>
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    disabled={accountPasskeysLoading}
                    title={t('txt_refresh')}
                    aria-label={t('txt_refresh')}
                    onClick={() => void refreshAccountPasskeys()}
                  >
                    <RefreshCw size={14} className="btn-icon" />
                    {t('txt_refresh')}
                  </button>
                </div>
                <p className="muted-inline settings-field-note">{t('txt_account_passkey_login_only_help')}</p>
                <div className="actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={securityPromptSubmitting}
                    onClick={() => openSecurityPrompt('createPasskey')}
                  >
                    <KeyRound size={14} className="btn-icon" />
                    {t('txt_add_account_passkey')}
                  </button>
                </div>
                <div className="account-passkeys-list">
                  {accountPasskeysLoading ? (
                    <div className="settings-module-placeholder">
                      <RefreshCw size={20} />
                      <span>{t('txt_loading')}</span>
                    </div>
                  ) : accountPasskeys.length === 0 ? (
                    <div className="settings-module-placeholder">
                      <KeyRound size={20} />
                      <span>{t('txt_no_account_passkeys')}</span>
                    </div>
                  ) : (
                    accountPasskeys.map((credential) => (
                      <div key={credential.id} className="account-passkey-row">
                        <div className="account-passkey-main">
                          <strong>{credential.name || t('txt_account_passkey')}</strong>
                          <small>{t('txt_created_value', { value: formatDateTime(credential.creationDate) })}</small>
                        </div>
                        <span className={`account-passkey-status account-passkey-status-${credential.prfStatus}`}>
                          {accountPasskeyStatusText(credential)}
                        </span>
                        <div className="actions account-passkey-actions">
                          {credential.prfStatus === 1 && (
                            <button
                              type="button"
                              className="btn btn-secondary small"
                              disabled={securityPromptSubmitting}
                              onClick={() => openSecurityPrompt('enablePasskeyDirectUnlock', credential.id)}
                            >
                              <ShieldCheck size={14} className="btn-icon" />
                              {t('txt_enable_passkey_direct_unlock')}
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-danger small"
                            disabled={securityPromptSubmitting}
                            onClick={() => openSecurityPrompt('deletePasskey', credential.id)}
                          >
                            <Trash2 size={14} className="btn-icon" />
                            {t('txt_delete')}
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </section>
            </div>
          )}

          {activeSection === 'twoStep' && (
            <div className="settings-section-stack">
              <section className="settings-submodule two-step-recovery-warning">
                <div className="two-step-warning-head">
                  <ShieldOff size={16} aria-hidden="true" />
                  <strong>{t('txt_warning')}</strong>
                </div>
                <p>{t('txt_two_step_recovery_code_warning')}</p>
                <button type="button" className="btn btn-danger" onClick={() => openSecurityPrompt('recovery')}>
                  {t('txt_view_recovery_code')}
                </button>
              </section>

              <section className="settings-submodule two-step-providers-module">
                <div className="settings-module-head">
                  <h3>{t('txt_providers')}</h3>
                  <button
                    type="button"
                    className="btn btn-secondary small"
                    disabled={twoFactorStatusRefreshing}
                    onClick={() => void refreshTwoFactorStatus()}
                  >
                    <RefreshCw size={14} className="btn-icon" />
                    {t('txt_refresh_status')}
                  </button>
                </div>
                <div className="two-step-provider-list">
                  <div className="two-step-provider-row">
                    <div className="two-step-provider-icon">
                      <ShieldCheck size={28} />
                    </div>
                    <div className="two-step-provider-copy">
                      <div className="two-step-provider-title">
                        <strong>{t('txt_authenticator_app')}</strong>
                        {totpActive && <span className="two-step-enabled-badge">{t('txt_enabled')}</span>}
                      </div>
                      <span>{t('txt_authenticator_app_help')}</span>
                      {totpNewRecoveryCode && (
                        // A change authorized with the recovery code consumed it, and a first enable
                        // mints one: the server returned the new code, and this is the only place it
                        // can be read. It stays until the next change.
                        <div className="totp-new-recovery-code">
                          <span>
                            {totpNewRecoveryCodeConsumed
                              ? t('txt_totp_recovery_code_consumed_note')
                              : t('txt_totp_recovery_code_generated_note')}
                          </span>
                          <div className="totp-secret-input-wrap">
                            {/* Read-only on purpose: it comes from the server, it is not editable. */}
                            <input className="input totp-secret-input" value={totpNewRecoveryCode} readOnly />
                            <div className="totp-secret-actions">
                              <button
                                type="button"
                                className="btn btn-secondary small totp-secret-icon-btn"
                                title={t('txt_copy_secret')}
                                aria-label={t('txt_copy_secret')}
                                onClick={() => {
                                  void copyTextToClipboard(totpNewRecoveryCode, { successMessage: t('txt_secret_copied') });
                                }}
                              >
                                <Clipboard size={14} className="btn-icon" />
                              </button>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                    <button type="button" className="btn btn-secondary" onClick={openTotpManage}>
                      {t('txt_manage')}
                    </button>
                  </div>

                  <div className="two-step-provider-row">
                    <div className="two-step-provider-icon">
                      <KeyRound size={28} />
                    </div>
                    <div className="two-step-provider-copy">
                      <div className="two-step-provider-title">
                        <strong>{t('txt_passkeys')}</strong>
                        {twoFactorPasskeyEnabled && <span className="two-step-enabled-badge">{t('txt_enabled')}</span>}
                      </div>
                      <span>{t('txt_passkey_provider_help')}</span>
                    </div>
                    <button type="button" className="btn btn-secondary" onClick={() => openSecurityPrompt('managePasskey2fa')}>
                      {t('txt_manage')}
                    </button>
                  </div>

                  <div className="two-step-provider-row">
                    <div className="two-step-provider-icon two-step-provider-yubico">yubico</div>
                    <div className="two-step-provider-copy">
                      <div className="two-step-provider-title">
                        <strong>{t('txt_yubico_otp_security_key')}</strong>
                        {yubiKeyEnabled && <span className="two-step-enabled-badge">{t('txt_enabled')}</span>}
                      </div>
                      <span>{t('txt_yubico_otp_security_key_help')}</span>
                    </div>
                    <button type="button" className="btn btn-secondary" onClick={() => openSecurityPrompt('manageYubiKey')}>
                      {t('txt_manage')}
                    </button>
                  </div>
                </div>
              </section>
            </div>
          )}

          {activeSection === 'keys' && (
            <div className="settings-section-stack">
              <section className="settings-submodule sensitive-action">
                <div>
                  <h3>{t('txt_api_key')}</h3>
                  <p className="muted-inline settings-field-note">{t('txt_api_key_dialog_intro')}</p>
                </div>
                <div className="actions">
                  <button type="button" className="btn btn-secondary" onClick={() => openSecurityPrompt('apiKey')}>
                    <KeyRound size={14} className="btn-icon" />
                    {t('txt_view_api_key')}
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setRotateApiKeyConfirmOpen(true)}
                  >
                    <RefreshCw size={14} className="btn-icon" />
                    {t('txt_rotate_api_key')}
                  </button>
                </div>
              </section>
            </div>
          )}
        </section>
      </div>
      <ConfirmDialog
        open={securityPrompt !== null}
        title={securityPromptTitle}
        message={t('txt_enter_master_password_to_continue')}
        confirmText={t('txt_continue')}
        cancelText={t('txt_cancel')}
        confirmDisabled={securityPromptSubmitting || !securityPromptValue.trim()}
        cancelDisabled={securityPromptSubmitting}
        onConfirm={() => void submitSecurityPrompt()}
        onCancel={closeSecurityPrompt}
      >
        <label className="field">
          <span>{t('txt_master_password')}</span>
          <input
            className="input"
            type="password"
            autoComplete="current-password"
            value={securityPromptValue}
            onInput={(e) => setSecurityPromptValue((e.currentTarget as HTMLInputElement).value)}
          />
        </label>
      </ConfirmDialog>
      <ConfirmDialog
        open={totpManageStep !== null}
        title={totpManageDialogTitle}
        message={totpManageDialogMessage}
        confirmText={t('txt_continue')}
        cancelText={t('txt_cancel')}
        // The steps that collect one credential use the built-in buttons; `choose` and `setup` bring
        // their own, because neither of them is a plain "confirm / cancel".
        hideConfirm={!totpManageUsesField}
        hideCancel={!totpManageUsesField}
        closeButton
        confirmDisabled={totpManageSubmitting || !totpManageValue.trim()}
        cancelDisabled={totpManageSubmitting}
        onConfirm={() => void submitTotpManageStep()}
        onCancel={closeTotpManage}
      >
        {totpManageUsesField && (
          // One field for both credential steps, so switching steps keeps the keyboard focus. The two
          // steps accept different credentials, hence the per-step label and input type: a code from
          // the authenticator in use (or the recovery code) is typed in clear text, the master
          // password is masked. The server tells the two codes apart — a six digit code can never be
          // a recovery code.
          <label className="field">
            <span>{totpManageStep === 'verifyCurrent' ? t('txt_authenticator_code_or_recovery_code') : t('txt_master_password')}</span>
            <input
              className="input"
              type={totpManageStep === 'verifyCurrent' ? 'text' : 'password'}
              autoComplete={totpManageStep === 'verifyCurrent' ? 'one-time-code' : 'current-password'}
              value={totpManageValue}
              onInput={(e) => setTotpManageValue((e.currentTarget as HTMLInputElement).value)}
            />
          </label>
        )}
        {totpManageStep === 'choose' && (
          <div className="actions">
            <button type="button" className="btn btn-primary" onClick={() => chooseTotpOperation('change')}>
              <RefreshCw size={14} className="btn-icon" />
              {t('txt_change_authenticator')}
            </button>
            <button type="button" className="btn btn-danger" onClick={() => chooseTotpOperation('disable')}>
              <ShieldOff size={14} className="btn-icon" />
              {t('txt_disable_totp')}
            </button>
            <button type="button" className="btn btn-secondary" onClick={closeTotpManage}>
              {t('txt_close')}
            </button>
          </div>
        )}
        {totpManageStep === 'setup' && (
          <div className="totp-manage-dialog-body">
            <div className="totp-grid">
              {qrDataUrl && (
                <div className="totp-qr">
                  <img src={qrDataUrl} alt={t('txt_authenticator_app')} />
                </div>
              )}
              <div>
                <label className="field">
                  <span>{t('txt_authenticator_key')}</span>
                  <div className="totp-secret-input-wrap">
                    {/* Editable on purpose: the key starts as the server default, but the user may
                        hand-edit it (for example to reuse an existing authenticator). The QR and the
                        submitted value both follow this input, and the server re-validates it. */}
                    <input
                      className="input totp-secret-input"
                      value={totpSetupKey}
                      spellcheck={false}
                      autoComplete="off"
                      onInput={(e) => setTotpSetupKey((e.currentTarget as HTMLInputElement).value)}
                    />
                    <div className="totp-secret-actions">
                      <button
                        type="button"
                        className="btn btn-secondary small totp-secret-icon-btn"
                        disabled={!normalizeTotpSecretInput(totpSetupKey)}
                        title={t('txt_copy_secret')}
                        aria-label={t('txt_copy_secret')}
                        onClick={() => {
                          void copyTextToClipboard(normalizeTotpSecretInput(totpSetupKey), { successMessage: t('txt_secret_copied') });
                        }}
                      >
                        <Clipboard size={14} className="btn-icon" />
                      </button>
                    </div>
                  </div>
                </label>
                <label className="field">
                  <span>{t('txt_verification_code')}</span>
                  <input
                    className="input"
                    autoComplete="one-time-code"
                    inputMode="numeric"
                    value={totpSetupToken}
                    onInput={(e) => setTotpSetupToken((e.currentTarget as HTMLInputElement).value)}
                  />
                </label>
                <div className="actions">
                  <button
                    type="button"
                    className="btn btn-primary"
                    disabled={totpSubmitting || !totpSetupKey || !totpSetupToken.trim()}
                    onClick={() => void submitTotpSetup()}
                  >
                    <ShieldCheck size={14} className="btn-icon" />
                    {t('txt_verify')}
                  </button>
                  <button type="button" className="btn btn-secondary" disabled={totpSubmitting} onClick={closeTotpManage}>
                    {t('txt_cancel')}
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </ConfirmDialog>
      <ConfirmDialog
        open={yubiKeyDialogOpen}
        title={`${t('txt_two_step_login')} YubiKey`}
        message={!yubiKeyYubicoConfigured ? '' : yubiKeyEnabled ? t('txt_yubikey_enabled') : t('txt_disabled')}
        hideConfirm
        hideCancel
        closeButton
        onConfirm={() => {
          if (yubiKeySubmitting) return;
          if (yubiKeyYubicoConfigured) {
            void saveYubiKeyDialog();
          } else {
            void bootstrapYubiKeyConfigDialog();
          }
        }}
        onCancel={closeYubiKeyDialog}
        afterActions={(
          <>
            {yubiKeyYubicoConfigured && (
              <button type="button" className="btn btn-primary dialog-btn" disabled={yubiKeySubmitting} onClick={() => void saveYubiKeyDialog()}>
                {t('txt_save')}
              </button>
            )}
            {yubiKeyEnabled && (
              <button type="button" className="btn btn-secondary dialog-btn" disabled={yubiKeySubmitting} onClick={() => void disableYubiKeyDialog()}>
                {t('txt_disable_all_keys')}
              </button>
            )}
          </>
        )}
      >
        <div className="yubikey-manage-dialog-body">
          {!yubiKeyYubicoConfigured && (
            <section className="settings-submodule yubikey-config-panel">
              <h3>{t('txt_yubikey_config_required')}</h3>
              <p className="muted-inline settings-field-note">{t('txt_yubikey_config_required_help')}</p>
              <label className="field">
                <span>{t('txt_otp_from_yubikey')}</span>
                <input
                  className="input"
                  type="password"
                  autoComplete="off"
                  autoCapitalize="none"
                  autoCorrect="off"
                  inputMode="verbatim"
                  spellcheck={false}
                  value={yubiKeyBootstrapOtp}
                  onInput={(e) => setYubiKeyBootstrapOtp(normalizeYubiKeyFieldValue((e.currentTarget as HTMLInputElement).value))}
                />
              </label>
              <button type="button" className="btn btn-primary" disabled={yubiKeySubmitting || !yubiKeyBootstrapOtp.trim()} onClick={() => void bootstrapYubiKeyConfigDialog()}>
                {t('txt_yubikey_auto_configure')}
              </button>
            </section>
          )}

          {yubiKeyYubicoConfigured && yubiKeyYubicoCanManage && (
              <section className="settings-submodule yubikey-config-panel">
                <div className="settings-module-head">
                  <h3>{t('txt_yubikey_validation_credentials')}</h3>
                  <button type="button" className="btn btn-secondary small" onClick={() => setYubiKeyConfigOpen((open) => !open)}>
                    {yubiKeyConfigOpen ? t('txt_hide') : t('txt_view')}
                  </button>
                </div>
                {yubiKeyConfigOpen && (
                  <div className="settings-vertical-fields">
                    <label className="field">
                      <span>Client ID</span>
                      <input className="input" value={yubiKeyYubicoClientId} onInput={(e) => setYubiKeyYubicoClientId((e.currentTarget as HTMLInputElement).value)} />
                    </label>
                    <label className="field">
                      <span>Secret key</span>
                      <input className="input" value={yubiKeyYubicoSecretKey} onInput={(e) => setYubiKeyYubicoSecretKey((e.currentTarget as HTMLInputElement).value)} />
                    </label>
                    <label className="field">
                      <span>{t('txt_otp_from_yubikey')}</span>
                      <input
                        className="input"
                        type="password"
                        autoComplete="off"
                        autoCapitalize="none"
                        autoCorrect="off"
                        inputMode="verbatim"
                        spellcheck={false}
                        value={yubiKeyBootstrapOtp}
                        onInput={(e) => setYubiKeyBootstrapOtp(normalizeYubiKeyFieldValue((e.currentTarget as HTMLInputElement).value))}
                      />
                      <div className="field-help">{t('txt_yubikey_reconfigure_help')}</div>
                    </label>
                    <div className="actions">
                      <button type="button" className="btn btn-secondary" disabled={yubiKeySubmitting || !yubiKeyYubicoClientId.trim()} onClick={() => void saveYubiKeyConfigDialog()}>
                        {t('txt_save')}
                      </button>
                      <button type="button" className="btn btn-secondary" disabled={yubiKeySubmitting || !yubiKeyBootstrapOtp.trim()} onClick={() => void bootstrapYubiKeyConfigDialog()}>
                        {t('txt_yubikey_auto_configure_again')}
                      </button>
                    </div>
                  </div>
                )}
              </section>
          )}

          {yubiKeyYubicoConfigured && (
            <>
              <ol className="settings-plain-steps">
                <li>{t('txt_yubikey_plug_in')}</li>
                <li>{t('txt_yubikey_select_empty_field')}</li>
                <li>{t('txt_yubikey_touch_button')}</li>
              </ol>
              <div className="settings-vertical-fields">
                {yubiKeyKeys.map((keyValue, index) => (
                  <label className="field" key={index}>
                    <span>{t('txt_yubikey_x').replace('{index}', String(index + 1))}</span>
                    <div className="yubikey-input-row">
                      {yubiKeyStoredKeys[index] && keyValue === yubiKeyStoredKeys[index] ? (
                        <span className="yubikey-stored-key">{formatStoredYubiKey(keyValue)}</span>
                      ) : (
                        <input
                          className="input"
                          type="password"
                          autoComplete="off"
                          autoCapitalize="none"
                          autoCorrect="off"
                          inputMode="verbatim"
                          spellcheck={false}
                          value={keyValue}
                          onInput={(e) => updateYubiKey(index, normalizeYubiKeyFieldValue((e.currentTarget as HTMLInputElement).value))}
                        />
                      )}
                      {keyValue && (
                        <button
                          type="button"
                          className="btn btn-danger small yubikey-remove-btn"
                          title={t('txt_remove')}
                          aria-label={t('txt_remove')}
                          onClick={() => updateYubiKey(index, '')}
                        >
                          <Trash2 size={14} className="btn-icon" />
                        </button>
                      )}
                    </div>
                  </label>
                ))}
              </div>
              <div className="settings-checkbox-block">
                <strong>{t('txt_nfc_support')}</strong>
                <label className="checkbox-inline">
                  <input type="checkbox" checked={yubiKeyNfc} onInput={(e) => setYubiKeyNfc((e.currentTarget as HTMLInputElement).checked)} />
                  <span>{t('txt_yubikey_supports_nfc')}</span>
                </label>
                {t('txt_yubikey_supports_nfc_desc') && <div className="field-help">{t('txt_yubikey_supports_nfc_desc')}</div>}
              </div>
            </>
          )}
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        open={twoFactorPasskeyDialogOpen}
        title={t('txt_two_step_passkeys')}
        message={t('txt_two_step_passkeys_help')}
        hideConfirm
        hideCancel
        closeButton
        cancelDisabled={twoFactorPasskeySubmitting}
        onConfirm={() => {}}
        onCancel={closeTwoFactorPasskeyDialog}
      >
        <div className="settings-vertical-fields">
          <div className="field">
            <label htmlFor="two-factor-passkey-name">{t('txt_passkey_name')}</label>
            <div className="two-factor-passkey-register-row">
              <input
                id="two-factor-passkey-name"
                className="input"
                maxLength={128}
                value={twoFactorPasskeyName}
                placeholder={t('txt_two_step_passkey_name_placeholder')}
                onInput={(e) => setTwoFactorPasskeyName((e.currentTarget as HTMLInputElement).value)}
              />
              <button
                type="button"
                className="btn btn-primary"
                disabled={twoFactorPasskeySubmitting}
                onClick={() => void createTwoFactorPasskeyDialog()}
              >
                <KeyRound size={14} className="btn-icon" />
                {t('txt_register')}
              </button>
            </div>
          </div>

          <div className="two-factor-passkey-list-block">
            <div className="settings-list-label">{t('txt_key_list')}</div>
            {twoFactorPasskeys.length > 0 ? (
              <div className="account-passkey-list">
                {twoFactorPasskeys.map((credential, index) => (
                  <div key={credential.id} className="account-passkey-row two-factor-passkey-row">
                    <span className="account-passkey-index">{index + 1}</span>
                    <div className="account-passkey-main">
                      <strong>{credential.name || t('txt_dash')}</strong>
                    </div>
                    <button
                      type="button"
                      className="btn btn-danger small"
                      disabled={twoFactorPasskeySubmitting || twoFactorPasskeys.length < 2}
                      title={twoFactorPasskeys.length < 2 ? t('txt_remove_last_passkey_hint') : t('txt_delete')}
                      onClick={() => void deleteTwoFactorPasskeyDialog(credential.id)}
                    >
                      <Trash2 size={14} className="btn-icon" />
                      {t('txt_delete')}
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="muted-inline settings-field-note">{t('txt_no_two_step_passkeys')}</p>
            )}
          </div>

          <div className="actions two-factor-passkey-danger-actions">
            {twoFactorPasskeyEnabled && (
              <button
                type="button"
                className="btn btn-danger"
                disabled={twoFactorPasskeySubmitting}
                onClick={() => void disableTwoFactorPasskeysDialog()}
              >
                {t('txt_disable_all_keys')}
              </button>
            )}
          </div>
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        open={recoveryCodeDialogOpen}
        title={`${t('txt_two_step_login')} ${t('txt_recovery_code')}`}
        message={t('txt_your_two_step_recovery_code')}
        hideConfirm
        hideCancel
        closeButton
        onConfirm={() => {}}
        onCancel={() => setRecoveryCodeDialogOpen(false)}
        afterActions={(
          <button
            type="button"
            className="btn btn-primary dialog-btn"
            disabled={!recoveryCode}
            onClick={() => {
              void copyTextToClipboard(recoveryCode, { successMessage: t('txt_recovery_code_copied') });
            }}
          >
            <Clipboard size={14} className="btn-icon" />
            {t('txt_copy_code')}
          </button>
        )}
      >
        <div className="two-step-recovery-code-dialog-value">{recoveryCode}</div>
      </ConfirmDialog>
      <ConfirmDialog
        open={createPasskeyDialogOpen}
        title={t('txt_add_account_passkey')}
        message={t('txt_name_account_passkey_after_verification')}
        confirmText={t('txt_save')}
        cancelText={t('txt_cancel')}
        confirmDisabled={securityPromptSubmitting}
        cancelDisabled={securityPromptSubmitting}
        onConfirm={() => void submitCreatePasskeyDialog()}
        onCancel={closeCreatePasskeyDialog}
      >
        <label className="field">
          <span>{t('txt_passkey_name')}</span>
          <input
            className="input"
            maxLength={128}
            value={accountPasskeyName}
            placeholder={t('txt_account_passkey_name_placeholder')}
            onInput={(e) => setAccountPasskeyName((e.currentTarget as HTMLInputElement).value)}
          />
          <div className="field-help">{t('txt_account_passkey_name_help')}</div>
        </label>
        <div className="field account-passkey-mode-field">
          <span>{t('txt_account_passkey_mode')}</span>
          <label className="account-passkey-toggle">
            <input
              type="checkbox"
              checked={accountPasskeyDirectUnlock}
              onInput={(e) => setAccountPasskeyDirectUnlock((e.currentTarget as HTMLInputElement).checked)}
            />
            <span>{t('txt_account_passkey_direct_unlock_mode')}</span>
          </label>
          <div className="field-help">
            {accountPasskeyDirectUnlock ? t('txt_account_passkey_direct_unlock_help') : t('txt_account_passkey_login_only_help')}
          </div>
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        open={apiKeyDialogOpen}
        title={t('txt_api_key')}
        message={t('txt_api_key_dialog_intro')}
        hideCancel
        confirmText={t('txt_close')}
        onConfirm={() => setApiKeyDialogOpen(false)}
        onCancel={() => setApiKeyDialogOpen(false)}
      >
        <div className="api-key-warning-panel">
          <div className="api-key-warning-title">{t('txt_warning')}</div>
          <div className="api-key-warning-body">{t('txt_api_key_warning_body')}</div>
        </div>

        <div className="api-key-credentials-panel">
          <div className="api-key-credentials-title">
            <KeyRound size={15} />
            <span>{t('txt_oauth_client_credentials')}</span>
          </div>
          {([
            [t('txt_client_id'), `user.${props.profile.id}`],
            [t('txt_client_secret'), apiKey],
            [t('txt_scope'), 'api'],
            [t('txt_grant_type'), 'client_credentials'],
          ] as [string, string][]).map(([label, value]) => (
            <label key={label} className="field">
              <span>{label}</span>
              <div className="api-key-credential-row">
                <input className="input" readOnly value={value} onFocus={(e) => (e.currentTarget as HTMLInputElement).select()} />
                <button
                  type="button"
                  className="btn btn-secondary small"
                  onClick={() => void copyTextToClipboard(value, { successMessage: t('txt_copied') })}
                >
                  <Clipboard size={14} className="btn-icon" />
                  {t('txt_copy')}
                </button>
              </div>
            </label>
          ))}
        </div>
      </ConfirmDialog>
      <ConfirmDialog
        open={rotateApiKeyConfirmOpen}
        title={t('txt_rotate_api_key')}
        message={t('txt_rotate_api_key_confirm')}
        danger
        onConfirm={() => {
          setRotateApiKeyConfirmOpen(false);
          openSecurityPrompt('rotateApiKey');
        }}
        onCancel={() => setRotateApiKeyConfirmOpen(false)}
      />
    </div>
  );
}
