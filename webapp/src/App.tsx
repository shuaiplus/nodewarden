import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { useLocation } from 'wouter';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import AppAuthenticatedShell from '@/components/AppAuthenticatedShell';
import AppGlobalOverlays, { type AppConfirmState } from '@/components/AppGlobalOverlays';
import AuthRequestApprovalDialog from '@/components/AuthRequestApprovalDialog';
import AuthViews from '@/components/AuthViews';
import NotFoundPage from '@/components/NotFoundPage';
import PublicSendPage from '@/components/PublicSendPage';
import RecoverTwoFactorPage from '@/components/RecoverTwoFactorPage';
import JwtWarningPage from '@/components/JwtWarningPage';
import {
  createAuthedFetch,
  deriveLoginHash,
  getAuthorizedDevices,
  clearProfileSnapshot,
  getCurrentDeviceIdentifier,
  getPasswordHint,
  getProfile,
  loadProfileSnapshot,
  saveProfileSnapshot,
  revokeCurrentSession,
  getTwoFactorProviderStatus,
  getVaultRevisionDate,
  saveSession,
  stripProfileSecrets,
} from '@/lib/api/auth';
import {
  encryptSessionUserKeyForAuthRequest,
  isPendingAuthRequest,
  listPendingAuthRequests,
  respondToAuthRequest,
} from '@/lib/api/auth-requests';
import { clearAuditLogs, getAuditLogSettings, listAdminInvites, listAdminUsers, listAuditLogs, saveAuditLogSettings, type AuditLogFilters } from '@/lib/api/admin';
import { getDomainRules, saveDomainRules } from '@/lib/api/domains';
import { getSendById, getSends } from '@/lib/api/send';
import { getCipherById, getFolderById, repairCipherKeyMismatches, repairCipherUriChecksums } from '@/lib/api/vault';
import { getCachedVaultCoreSnapshot, invalidateVaultCoreSyncSnapshot, loadVaultCoreSyncSnapshot, saveVaultCoreSyncSnapshot } from '@/lib/api/vault-sync';
import { silentlyRepairBackupSettingsIfNeeded } from '@/lib/backup-settings-repair';
import {
  parseSignalRTextFrames,
  readInviteCodeFromUrl,
} from '@/lib/app-support';
import { preloadAuthenticatedWorkspace, preloadDemoExperience } from '@/lib/app-preload';
import {
  bootstrapAppSession,
  type CompletedLogin,
  readInitialAppBootstrapState,
  completePasskeyPasswordLogin,
  performPasswordLogin,
  performPasskeyLogin,
  performRecoverTwoFactorLogin,
  performRegistration,
  performTotpLogin,
  hydrateLockedSession,
  performUnlock,
  type JwtUnsafeReason,
  type PendingPasskeyPassword,
  type PendingTotp,
} from '@/lib/app-auth';
import { assertTwoFactorPasskey } from '@/lib/account-passkeys';
import useAccountSecurityActions from '@/hooks/useAccountSecurityActions';
import useAdminActions from '@/hooks/useAdminActions';
import useBackupActions from '@/hooks/useBackupActions';
import useVaultSendActions from '@/hooks/useVaultSendActions';
import { useToastManager } from '@/hooks/useToastManager';
import { t } from '@/lib/i18n';
import { APP_NOTIFY_EVENT, type AppNotifyDetail } from '@/lib/app-notify';
import { dispatchBackupProgress, type BackupProgressDetail } from '@/lib/backup-restore-progress';
import { clearOfflineUnlockRecord } from '@/lib/offline-auth';
import { decryptSends, decryptVaultCore } from '@/lib/vault-decrypt';
import { decryptSendsInWorker, decryptVaultCoreInWorker } from '@/lib/vault-worker';
import {
  DEMO_CIPHERS,
  DEMO_ADMIN_INVITES,
  DEMO_ADMIN_USERS,
  DEMO_AUTHORIZED_DEVICES,
  DEMO_FOLDERS,
  DEMO_SENDS,
  createDemoBackupSettings,
  IS_DEMO_MODE,
  createDemoCompletedLogin,
  createDemoInitialBootstrapState,
  createDemoMainRoutesProps,
} from '@/lib/demo';
import type { AdminBackupSettings } from '@/lib/api/backup';
import type { AdminInvite, AdminUser, AppPhase, AuditLogSettings, AuthRequest, AuthorizedDevice, Cipher, CustomEquivalentDomain, DomainRules, Folder as VaultFolder, Profile, Send, SessionState } from '@/lib/types';
import type { VaultCoreSnapshot } from '@/lib/vault-cache';

function isBackupProgressDetail(value: unknown): value is BackupProgressDetail {
  if (!value || typeof value !== 'object') return false;
  const detail = value as Record<string, unknown>;
  const operation = detail.operation;
  return (
    (operation === 'backup-restore' || operation === 'backup-export' || operation === 'backup-remote-run')
    && typeof detail.step === 'string'
    && typeof detail.fileName === 'string'
  );
}

const IMPORT_ROUTE = '/backup/import-export';
const IMPORT_ROUTE_PATHS = [IMPORT_ROUTE, '/tools/import', '/tools/import-export', '/tools/import-data', '/import', '/import-export'] as const;
const IMPORT_ROUTE_ALIASES: ReadonlySet<string> = new Set(IMPORT_ROUTE_PATHS.filter((path) => path !== IMPORT_ROUTE));
const SETTINGS_HOME_ROUTE = '/settings';
const SETTINGS_ACCOUNT_ROUTE = '/settings/account';
const SETTINGS_DOMAIN_RULES_ROUTE = '/settings/domain-rules';
const DEVICE_MANAGEMENT_ROUTE = '/settings/security/device-management';
const LEGACY_DEVICE_MANAGEMENT_ROUTE = '/security/devices';
const AUTH_ROUTE_PATHS = ['/', '/login', '/register', '/lock', '/recover-2fa'] as const;
const APP_ROUTE_PATHS = [
  '/',
  '/vault',
  '/vault/totp',
  '/sends',
  '/admin',
  '/logs',
  LEGACY_DEVICE_MANAGEMENT_ROUTE,
  DEVICE_MANAGEMENT_ROUTE,
  '/backup',
  '/settings',
  SETTINGS_ACCOUNT_ROUTE,
  SETTINGS_DOMAIN_RULES_ROUTE,
  '/help',
  ...IMPORT_ROUTE_PATHS,
] as const;
const AUTH_ROUTES: ReadonlySet<string> = new Set(AUTH_ROUTE_PATHS);
const APP_ROUTES: ReadonlySet<string> = new Set(APP_ROUTE_PATHS);

function isAdminProfile(profile: Profile | null): profile is Profile {
  return String(profile?.role || '').toLowerCase() === 'admin';
}

function normalizeRoutePath(path: string): string {
  const pathOnly = String(path || '/').split('?')[0].split('#')[0];
  const normalized = pathOnly.startsWith('/') ? pathOnly : `/${pathOnly}`;
  return normalized.length > 1 ? normalized.replace(/\/+$/, '') : '/';
}
const THEME_STORAGE_KEY = 'nodewarden.theme.preference.v1';
const SIGNALR_RECORD_SEPARATOR = String.fromCharCode(0x1e);
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_UPDATE = 0;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_CREATE = 1;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_DELETE = 3;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHERS = 4;
const SIGNALR_UPDATE_TYPE_SYNC_VAULT = 5;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_CREATE = 7;
const SIGNALR_UPDATE_TYPE_SYNC_FOLDER_UPDATE = 8;
const SIGNALR_UPDATE_TYPE_SYNC_CIPHER_DELETE = 9;
const SIGNALR_UPDATE_TYPE_LOG_OUT = 11;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_CREATE = 12;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_UPDATE = 13;
const SIGNALR_UPDATE_TYPE_SYNC_SEND_DELETE = 14;
const SIGNALR_UPDATE_TYPE_AUTH_REQUEST = 15;
const SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE = 16;
const SIGNALR_UPDATE_TYPE_DEVICE_STATUS = 101;
const SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS = 102;
const TWO_FACTOR_PROVIDER_YUBIKEY = 3;
const TWO_FACTOR_PROVIDER_WEBAUTHN = 7;

type ThemePreference = 'system' | 'light' | 'dark';
type LockTimeoutMinutes = 0 | 1 | 5 | 15 | 30;
type SessionTimeoutAction = 'lock' | 'logout';

const LOCK_TIMEOUT_STORAGE_KEY = 'nodewarden.lock.timeout-minutes.v1';
const SESSION_TIMEOUT_ACTION_STORAGE_KEY = 'nodewarden.session.timeout-action.v1';
const LOCK_TIMEOUT_VALUES = new Set<LockTimeoutMinutes>([0, 1, 5, 15, 30]);
function readThemePreference(): ThemePreference {
  if (typeof window === 'undefined') return 'system';
  const stored = String(window.localStorage.getItem(THEME_STORAGE_KEY) || '').trim();
  if (stored === 'light' || stored === 'dark' || stored === 'system') return stored;
  return 'system';
}

function resolveSystemTheme(): 'light' | 'dark' {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function readLockTimeoutMinutes(): LockTimeoutMinutes {
  if (typeof window === 'undefined') return 15;
  const stored = window.localStorage.getItem(LOCK_TIMEOUT_STORAGE_KEY);
  if (stored === null || stored.trim() === '') return 15;
  const value = Number(stored);
  return LOCK_TIMEOUT_VALUES.has(value as LockTimeoutMinutes) ? (value as LockTimeoutMinutes) : 15;
}

function readSessionTimeoutAction(): SessionTimeoutAction {
  if (typeof window === 'undefined') return 'lock';
  const value = String(window.localStorage.getItem(SESSION_TIMEOUT_ACTION_STORAGE_KEY) || '').trim();
  return value === 'logout' ? 'logout' : 'lock';
}

export default function App() {
  const initialBootstrap = useMemo(
    () => (IS_DEMO_MODE ? createDemoInitialBootstrapState() : readInitialAppBootstrapState()),
    []
  );
  const initialInviteCode = useMemo(() => readInviteCodeFromUrl(), []);
  const initialProfileSnapshot = useMemo(
    () => (IS_DEMO_MODE ? null : loadProfileSnapshot(initialBootstrap.session?.email)),
    [initialBootstrap]
  );
  const queryClient = useQueryClient();
  const [pendingAuthAction, setPendingAuthAction] = useState<'login' | 'passkey' | 'register' | 'unlock' | null>(null);
  const [location, navigate] = useLocation();
  const [phase, setPhase] = useState<AppPhase>(initialBootstrap.phase);
  const [session, setSessionState] = useState<SessionState | null>(initialBootstrap.session);
  const [profile, setProfile] = useState<Profile | null>(initialProfileSnapshot);
  const [defaultKdfIterations, setDefaultKdfIterations] = useState(initialBootstrap.defaultKdfIterations);
  const [registrationInviteRequired, setRegistrationInviteRequired] = useState(initialBootstrap.registrationInviteRequired);
  const [jwtWarning, setJwtWarning] = useState<{ reason: JwtUnsafeReason; minLength: number } | null>(initialBootstrap.jwtWarning);

  const [loginValues, setLoginValues] = useState({ email: '', password: '' });
  const [registerValues, setRegisterValues] = useState({
    name: '',
    email: '',
    password: '',
    password2: '',
    passwordHint: '',
    inviteCode: initialInviteCode,
  });
  const [loginHintState, setLoginHintState] = useState<{
    email: string;
    loading: boolean;
    hint: string | null;
  }>({
    email: '',
    loading: false,
    hint: null,
  });
  const [inviteCodeFromUrl, setInviteCodeFromUrl] = useState(initialInviteCode);
  const [hashPathRaw, setHashPathRaw] = useState(() => (typeof window !== 'undefined' ? window.location.hash || '' : ''));
  const [unlockPassword, setUnlockPassword] = useState('');
  const [pendingTotp, setPendingTotp] = useState<PendingTotp | null>(null);
  const [pendingTotpMode, setPendingTotpMode] = useState<'login' | 'unlock' | null>(null);
  const [pendingPasskeyPassword, setPendingPasskeyPassword] = useState<PendingPasskeyPassword | null>(null);
  const [passkeyPassword, setPasskeyPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [rememberDevice, setRememberDevice] = useState(true);
  const [totpSubmitting, setTotpSubmitting] = useState(false);

  const [disableTotpOpen, setDisableTotpOpen] = useState(false);
  const [disableTotpPassword, setDisableTotpPassword] = useState('');
  const [disableTotpSubmitting, setDisableTotpSubmitting] = useState(false);
  const [authRequestDialogDismissedId, setAuthRequestDialogDismissedId] = useState<string | null>(null);
  const [authRequestDialogSelectedId, setAuthRequestDialogSelectedId] = useState<string | null>(null);
  const [authRequestSubmittingId, setAuthRequestSubmittingId] = useState<string | null>(null);
  const [recoverValues, setRecoverValues] = useState({ email: '', password: '', recoveryCode: '' });
  const [themePreference, setThemePreference] = useState<ThemePreference>(() => readThemePreference());
  const [systemTheme, setSystemTheme] = useState<'light' | 'dark'>(() => resolveSystemTheme());
  const [lockTimeoutMinutes, setLockTimeoutMinutesState] = useState<LockTimeoutMinutes>(() => readLockTimeoutMinutes());
  const [sessionTimeoutAction, setSessionTimeoutActionState] = useState<SessionTimeoutAction>(() => readSessionTimeoutAction());
  const [unlockPreparing, setUnlockPreparing] = useState(() => initialBootstrap.phase === 'locked' && !initialBootstrap.session?.email);

  const [confirm, setConfirm] = useState<AppConfirmState | null>(null);
  const [mobileLayout, setMobileLayout] = useState(false);
  const [mobileSidebarToggleKey, setMobileSidebarToggleKey] = useState(0);
  const [decryptedFolders, setDecryptedFolders] = useState<VaultFolder[]>([]);
  const [decryptedCiphers, setDecryptedCiphers] = useState<Cipher[]>([]);
  const [decryptedSends, setDecryptedSends] = useState<Send[]>([]);
  const [demoUsers, setDemoUsers] = useState<AdminUser[]>(() => DEMO_ADMIN_USERS.map((user) => ({ ...user })));
  const [demoInvites, setDemoInvites] = useState<AdminInvite[]>(() => DEMO_ADMIN_INVITES.map((invite) => ({ ...invite })));
  const [demoAuthorizedDevices, setDemoAuthorizedDevices] = useState<AuthorizedDevice[]>(() => DEMO_AUTHORIZED_DEVICES.map((device) => ({ ...device })));
  const [demoBackupSettings, setDemoBackupSettings] = useState<AdminBackupSettings>(() => createDemoBackupSettings());
  const [cachedVaultCore, setCachedVaultCore] = useState<VaultCoreSnapshot | null>(null);
  const [vaultInitialDecryptDone, setVaultInitialDecryptDone] = useState(false);
  const [vaultDecryptError, setVaultDecryptError] = useState('');
  const [sendsDecryptDone, setSendsDecryptDone] = useState(false);
  const sessionRef = useRef<SessionState | null>(initialBootstrap.session);
  const silentRefreshVaultRef = useRef<() => Promise<void>>(async () => {});
  const refreshAuthorizedDevicesRef = useRef<() => Promise<void>>(async () => {});
  const refreshPendingAuthRequestsRef = useRef<() => Promise<void>>(async () => {});
  const repairAttemptRef = useRef<string>('');
  const loginScopedBackupRepairAuthRef = useRef<{
    accessToken: string;
    masterPasswordHash?: string | null;
    userVerificationToken?: string | null;
  } | null>(null);
  const uriChecksumRepairAttemptRef = useRef<string>('');
  const pendingVaultCoreQueryRefreshRef = useRef<Promise<{ data?: VaultCoreSnapshot } | unknown> | null>(null);
  const pendingVaultCoreRefreshRef = useRef<Promise<unknown> | null>(null);
  const notificationRefreshTimerRef = useRef<number | null>(null);
  const domainRulesSaveSeqRef = useRef(0);
  const loginEmailRef = useRef(loginValues.email);
  const loginHintRequestSeqRef = useRef(0);
  const { toasts, pushToast, removeToast } = useToastManager();

  useEffect(() => {
    const handleAppNotify = (event: Event) => {
      const detail = (event as CustomEvent<AppNotifyDetail>).detail;
      if (!detail?.text) return;
      pushToast(detail.type, detail.text);
    };

    window.addEventListener(APP_NOTIFY_EVENT, handleAppNotify as EventListener);
    return () => window.removeEventListener(APP_NOTIFY_EVENT, handleAppNotify as EventListener);
  }, [pushToast]);

  useEffect(() => {
    const syncUrlState = () => {
      setInviteCodeFromUrl(readInviteCodeFromUrl());
      setHashPathRaw(window.location.hash || '');
    };
    syncUrlState();
    window.addEventListener('hashchange', syncUrlState);
    window.addEventListener('popstate', syncUrlState);
    return () => {
      window.removeEventListener('hashchange', syncUrlState);
      window.removeEventListener('popstate', syncUrlState);
    };
  }, []);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    setRegisterValues((prev) => (prev.inviteCode === inviteCodeFromUrl ? prev : { ...prev, inviteCode: inviteCodeFromUrl }));
  }, [inviteCodeFromUrl]);

  useEffect(() => {
    loginEmailRef.current = loginValues.email;
    const normalizedEmail = loginValues.email.trim().toLowerCase();
    setLoginHintState((prev) => (
      prev.email && prev.email !== normalizedEmail
        ? { email: '', loading: false, hint: null }
        : prev
    ));
  }, [loginValues.email]);

  useEffect(() => {
    if (!inviteCodeFromUrl) return;
    if (phase === 'locked' || phase === 'app') return;
    setPhase('register');
    if (location !== '/register') navigate('/register');
    if (typeof window !== 'undefined' && typeof window.history?.replaceState === 'function') {
      window.history.replaceState(null, '', '/register');
    }
    setInviteCodeFromUrl('');
  }, [inviteCodeFromUrl, phase, location, navigate]);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(max-width: 1180px)');
    const sync = () => setMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia('(prefers-color-scheme: dark)');
    const sync = () => setSystemTheme(media.matches ? 'dark' : 'light');
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  const resolvedTheme = themePreference === 'system' ? systemTheme : themePreference;

  useEffect(() => {
    if (typeof document === 'undefined') return;
    document.documentElement.dataset.theme = resolvedTheme;
    document.documentElement.style.colorScheme = resolvedTheme;
  }, [resolvedTheme]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(THEME_STORAGE_KEY, themePreference);
  }, [themePreference]);

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    saveProfileSnapshot(profile);
  }, [profile]);

  useEffect(() => {
    if (phase === 'locked' && session?.email) {
      setUnlockPreparing(false);
    }
  }, [phase, profile, session]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(LOCK_TIMEOUT_STORAGE_KEY, String(lockTimeoutMinutes));
  }, [lockTimeoutMinutes]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    window.localStorage.setItem(SESSION_TIMEOUT_ACTION_STORAGE_KEY, sessionTimeoutAction);
  }, [sessionTimeoutAction]);

  function handleToggleTheme() {
    setThemePreference((prev) => {
      const current = prev === 'system' ? systemTheme : prev;
      return current === 'dark' ? 'light' : 'dark';
    });
  }

  function setSession(next: SessionState | null) {
    sessionRef.current = next;
    setSessionState(next);
    saveSession(next);
  }

  function setLockTimeoutMinutes(next: LockTimeoutMinutes) {
    setLockTimeoutMinutesState(next);
    pushToast('success', t('txt_session_timeout_updated'));
  }

  function setSessionTimeoutAction(next: SessionTimeoutAction) {
    setSessionTimeoutActionState(next);
    pushToast('success', t('txt_session_timeout_updated'));
  }

  const authedFetch = useMemo(
    () =>
      createAuthedFetch(
        () => session,
        (next) => {
          setSession(next);
          if (!next) {
            setProfile(null);
            setPhase('login');
          }
        }
      ),
    [session]
  );
  const importAuthedFetch = useMemo(
    () => async (input: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers || {});
      headers.set('X-NodeWarden-Import', '1');
      return authedFetch(input, { ...init, headers });
    },
    [authedFetch]
  );
  const vaultCacheKey = String(profile?.id || session?.email || '').trim();
  const backupActions = useBackupActions({
    authedFetch,
    onImported: () => {
      window.setTimeout(() => {
        logoutNow();
      }, 200);
    },
    onRestored: () => {
      window.setTimeout(() => {
        logoutNow();
      }, 200);
    },
  });

  useEffect(() => {
    if (IS_DEMO_MODE) {
      const currentHashPath = typeof window !== 'undefined'
        ? (window.location.hash || '').replace(/^#/, '').split('?')[0].split('#')[0]
        : '';
      const normalizedCurrentHashPath = currentHashPath.replace(/^\/+/, '').replace(/\/+$/, '');
      const isDemoPublicSendRoute = /^send\/[^/]+(?:\/[^/]+)?$/i.test(normalizedCurrentHashPath);
      setDefaultKdfIterations(initialBootstrap.defaultKdfIterations);
      setRegistrationInviteRequired(initialBootstrap.registrationInviteRequired);
      setJwtWarning(null);
      setSession(null);
      setProfile(null);
      setPhase('login');
      setUnlockPreparing(false);
      if (!isDemoPublicSendRoute && location !== '/login') navigate('/login');
      return;
    }

    let mounted = true;
    (async () => {
      const boot = await bootstrapAppSession(initialBootstrap);
      if (!mounted) return;
      if (sessionRef.current?.symEncKey || sessionRef.current?.symMacKey) return;
      setDefaultKdfIterations(boot.defaultKdfIterations);
      setRegistrationInviteRequired(boot.registrationInviteRequired);
      setJwtWarning(boot.jwtWarning);
      setSession(boot.session);
      setProfile(boot.profile);
      setPhase(boot.phase);
      setUnlockPreparing(boot.phase === 'locked' && !boot.session?.email);
    })();

    return () => {
      mounted = false;
    };
  }, [initialBootstrap]);

  useEffect(() => {
    if (phase !== 'locked' || !session) return;
    if (IS_DEMO_MODE) return;
    let cancelled = false;
    void (async () => {
      const result = await hydrateLockedSession(session, profile);
      if (cancelled) return;
      if (!result.session) {
        setSession(null);
        setProfile(null);
        setUnlockPreparing(false);
        setPhase('login');
        if (location !== '/login') navigate('/login');
        return;
      }
      setSession(result.session);
      if (result.profile) {
        setProfile(stripProfileSecrets(result.profile));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [phase, session?.email, location, navigate]);

  async function finalizeLogin(login: CompletedLogin) {
    loginScopedBackupRepairAuthRef.current =
      login.session.accessToken && (login.freshMasterPasswordHash || login.freshUserVerificationToken)
        ? {
            accessToken: login.session.accessToken,
            masterPasswordHash: login.freshMasterPasswordHash || null,
            userVerificationToken: login.freshUserVerificationToken || null,
          }
        : null;
    setSession(login.session);
    setProfile(login.profile);
    setUnlockPreparing(false);
    setPendingTotp(null);
    setPendingTotpMode(null);
    setPendingPasskeyPassword(null);
    setTotpCode('');
    setPasskeyPassword('');
    setUnlockPassword('');
    setPhase('app');
    if (location === '/' || location === '/login' || location === '/register' || location === '/lock') {
      navigate('/vault');
    }
    void (async () => {
      try {
        const hydratedProfile = await login.profilePromise;
        if (sessionRef.current?.accessToken !== login.session.accessToken) return;
        setProfile(hydratedProfile);
      } catch {
        // Keep the in-memory transient profile for the current session.
      }
    })();
  }

  async function handleLogin() {
    if (pendingAuthAction) return;
    if (IS_DEMO_MODE) {
      setPendingAuthAction('login');
      try {
        await finalizeLogin(createDemoCompletedLogin(loginValues.email));
      } finally {
        setPendingAuthAction(null);
      }
      return;
    }
    if (!loginValues.email || !loginValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    setPendingAuthAction('login');
    try {
      const result = await performPasswordLogin(loginValues.email, loginValues.password, defaultKdfIterations);
      if (result.kind === 'success') {
        await finalizeLogin(result.login);
        return;
      }
      if (result.kind === 'totp') {
        setPendingTotp(result.pendingTotp);
        setPendingTotpMode('login');
        setTotpCode('');
        setRememberDevice(true);
        return;
      }
      pushToast('error', result.message || t('txt_login_failed'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_login_failed'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  async function handlePasskeyLogin() {
    if (pendingAuthAction) return;
    if (IS_DEMO_MODE) {
      pushToast('warning', t('txt_demo_readonly_message'));
      return;
    }
    setPendingAuthAction('passkey');
    try {
      const result = await performPasskeyLogin(defaultKdfIterations);
      if (result.kind === 'success') {
        await finalizeLogin(result.login);
        return;
      }
      if (result.kind === 'password') {
        setPendingPasskeyPassword(result.pendingPasskeyPassword);
        setLoginValues({ email: result.pendingPasskeyPassword.email, password: '' });
        setPasskeyPassword('');
        pushToast('warning', t('txt_passkey_requires_master_password'));
        return;
      }
      pushToast('error', result.message || t('txt_login_failed'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_login_failed'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  async function handlePasskeyUnlock() {
    if (pendingAuthAction) return;
    const expectedEmail = (profile?.email || session?.email || '').trim().toLowerCase();
    if (!expectedEmail) return;
    if (IS_DEMO_MODE) {
      pushToast('warning', t('txt_demo_readonly_message'));
      return;
    }
    setPendingAuthAction('passkey');
    try {
      const result = await performPasskeyLogin(defaultKdfIterations, expectedEmail);
      if (result.kind === 'success') {
        await finalizeLogin(result.login);
        return;
      }
      if (result.kind === 'password') {
        pushToast('error', t('txt_account_passkey_direct_unlock_unavailable_error'));
        return;
      }
      pushToast('error', result.message || t('txt_unlock_failed_master_password_is_incorrect'));
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_unlock_failed_master_password_is_incorrect'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  async function handlePasskeyPasswordLogin() {
    if (pendingAuthAction || !pendingPasskeyPassword) return;
    if (!passkeyPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    setPendingAuthAction('login');
    try {
      const login = await completePasskeyPasswordLogin(pendingPasskeyPassword, passkeyPassword);
      await finalizeLogin(login);
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_unlock_failed_master_password_is_incorrect'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  function handleSelectTotpProvider(providerType: number) {
    if (totpSubmitting) return;
    setPendingTotp((current) => {
      if (!current || current.providerType === providerType) return current;
      const canUseProvider = current.availableProviders.includes(providerType);
      if (!canUseProvider) return current;
      return {
        ...current,
        providerType,
        providerData: current.providerDataByType[providerType],
      };
    });
    setTotpCode('');
  }

  async function handleTotpVerify() {
    if (totpSubmitting) return;
    if (!pendingTotp) return;
    const isPasskeyTwoFactor = pendingTotp.providerType === TWO_FACTOR_PROVIDER_WEBAUTHN;
    if (!isPasskeyTwoFactor && !totpCode.trim()) {
      pushToast('error', pendingTotp.providerType === TWO_FACTOR_PROVIDER_YUBIKEY ? t('txt_please_input_yubikey_otp') : t('txt_please_input_totp_code'));
      return;
    }
    setTotpSubmitting(true);
    try {
      const token = isPasskeyTwoFactor
        ? await assertTwoFactorPasskey(pendingTotp.providerData)
        : totpCode;
      const login = await performTotpLogin(pendingTotp, token, rememberDevice);
      await finalizeLogin(login);
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : pendingTotp.providerType === 3 ? t('txt_yubikey_verify_failed') : isPasskeyTwoFactor ? t('txt_passkey_verification_failed') : t('txt_totp_verify_failed'));
    } finally {
      setTotpSubmitting(false);
    }
  }

  async function handleRecoverTwoFactorSubmit() {
    const email = recoverValues.email.trim().toLowerCase();
    const password = recoverValues.password;
    const recoveryCode = recoverValues.recoveryCode.trim();
    if (!email || !password || !recoveryCode) {
      pushToast('error', t('txt_email_password_and_recovery_code_are_required'));
      return;
    }
    try {
      const recovered = await performRecoverTwoFactorLogin(email, password, recoveryCode, defaultKdfIterations);
      if (recovered.login) {
        await finalizeLogin(recovered.login);
        if (recovered.newRecoveryCode) {
          pushToast('success', t('txt_text_2fa_recovered_new_recovery_code_code', { code: recovered.newRecoveryCode }));
        } else {
          pushToast('success', t('txt_text_2fa_recovered'));
        }
        return;
      }
      pushToast('error', t('txt_recovered_but_auto_login_failed_please_sign_in'));
      navigate('/login');
    } catch (error) {
      pushToast('error', error instanceof Error ? error.message : t('txt_recover_2fa_failed'));
    }
  }

  async function handleRegister() {
    if (pendingAuthAction) return;
    if (IS_DEMO_MODE) {
      pushToast('warning', t('txt_demo_readonly_message'));
      setPhase('login');
      navigate('/login');
      return;
    }
    if (!registerValues.email || !registerValues.password) {
      pushToast('error', t('txt_please_input_email_and_password'));
      return;
    }
    if (registerValues.password.length < 12) {
      pushToast('error', t('txt_master_password_must_be_at_least_12_chars'));
      return;
    }
    if (registerValues.password !== registerValues.password2) {
      pushToast('error', t('txt_passwords_do_not_match'));
      return;
    }
    setPendingAuthAction('register');
    try {
      const resp = await performRegistration({
        email: registerValues.email,
        name: registerValues.name,
        password: registerValues.password,
        masterPasswordHint: registerValues.passwordHint,
        inviteCode: registerValues.inviteCode,
        fallbackIterations: defaultKdfIterations,
      });
      if (!resp.ok) {
        pushToast('error', resp.message);
        return;
      }
      setLoginValues({ email: registerValues.email.toLowerCase(), password: '' });
      setPhase('login');
      navigate('/login');
      pushToast('success', t('txt_registration_succeeded_please_sign_in'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  function openPasswordHintDialog(hint: string | null) {
    setConfirm({
      title: t('txt_password_hint'),
      message: hint || t('txt_password_hint_not_set'),
      showIcon: false,
      confirmText: t('txt_close'),
      hideCancel: true,
      onConfirm: () => setConfirm(null),
    });
  }

  async function handleTogglePasswordHint() {
    if (pendingAuthAction) return;
    if (IS_DEMO_MODE) {
      openPasswordHintDialog(t('txt_demo_master_password_hint'));
      return;
    }
    const email = loginValues.email.trim().toLowerCase();
    if (!email) return;

    if (loginHintState.email === email && !loginHintState.loading) {
      openPasswordHintDialog(loginHintState.hint);
      return;
    }

    const requestSeq = ++loginHintRequestSeqRef.current;
    setLoginHintState({
      email,
      loading: true,
      hint: null,
    });

    try {
      const result = await getPasswordHint(email);
      if (loginHintRequestSeqRef.current !== requestSeq || loginEmailRef.current.trim().toLowerCase() !== email) return;
      openPasswordHintDialog(result.masterPasswordHint);
      setLoginHintState({
        email,
        loading: false,
        hint: result.masterPasswordHint,
      });
    } catch (error) {
      if (loginHintRequestSeqRef.current !== requestSeq || loginEmailRef.current.trim().toLowerCase() !== email) return;
      setLoginHintState({
        email: '',
        loading: false,
        hint: null,
      });
      pushToast('error', error instanceof Error ? error.message : t('txt_password_hint_load_failed'));
    }
  }

  function handleShowLockedPasswordHint() {
    if (pendingAuthAction) return;
    openPasswordHintDialog((IS_DEMO_MODE ? t('txt_demo_master_password_hint') : profile?.masterPasswordHint) ?? null);
  }

  async function handleUnlock() {
    if (pendingAuthAction) return;
    if (!session?.email) return;
    if (IS_DEMO_MODE) {
      setPendingAuthAction('unlock');
      try {
        await finalizeLogin(createDemoCompletedLogin(session.email));
      } finally {
        setPendingAuthAction(null);
      }
      return;
    }
    if (!unlockPassword) {
      pushToast('error', t('txt_please_input_master_password'));
      return;
    }
    setPendingAuthAction('unlock');
    try {
      const result = await performUnlock(session, profile, unlockPassword, defaultKdfIterations);
      if (result.kind === 'success') {
        await finalizeLogin(result.login);
        return;
      }
      if (result.kind === 'totp') {
        setPendingTotp(result.pendingTotp);
        setPendingTotpMode('unlock');
        setTotpCode('');
        setRememberDevice(true);
        return;
      }
      pushToast('error', result.message || t('txt_unlock_failed_master_password_is_incorrect'));
    } catch {
      pushToast('error', t('txt_unlock_failed_master_password_is_incorrect'));
    } finally {
      setPendingAuthAction(null);
    }
  }

  function lockCurrentSession() {
    const currentSession = sessionRef.current;
    if (!currentSession) return;
    const nextSession = { ...currentSession };
    delete nextSession.symEncKey;
    delete nextSession.symMacKey;
    setSession(nextSession);
    setProfile((prev) => stripProfileSecrets(prev));
    setDecryptedFolders([]);
    setDecryptedCiphers([]);
    setDecryptedSends([]);
    setUnlockPassword('');
    setPendingTotp(null);
    setPendingTotpMode(null);
    setTotpCode('');
    setUnlockPreparing(false);
    setPhase('locked');
    navigate('/lock');
  }

  function handleLock() {
    lockCurrentSession();
  }

  function logoutNow() {
    if (!IS_DEMO_MODE) {
      void revokeCurrentSession(sessionRef.current);
    }
    setConfirm(null);
    setSession(null);
    clearProfileSnapshot();
    clearOfflineUnlockRecord();
    setProfile(null);
    setUnlockPreparing(false);
    setPendingTotp(null);
    setPendingTotpMode(null);
    setPhase('login');
    navigate('/login');
  }

  function handleLogout() {
    setConfirm({
      title: t('txt_log_out'),
      message: t('txt_are_you_sure_you_want_to_log_out'),
      showIcon: false,
      onConfirm: () => {
        logoutNow();
      },
    });
  }

  useEffect(() => {
    if (phase !== 'app' || lockTimeoutMinutes === 0) return;
    if (typeof window === 'undefined') return;

    let timerId: number | null = null;
    let lastActivityAt = 0;
    const timeoutMs = lockTimeoutMinutes * 60 * 1000;

    const clearTimer = () => {
      if (timerId !== null) {
        window.clearTimeout(timerId);
        timerId = null;
      }
    };
    const runTimeoutAction = () => {
      if (sessionTimeoutAction === 'logout') {
        logoutNow();
        return;
      }
      if (sessionRef.current?.symEncKey || sessionRef.current?.symMacKey) {
        lockCurrentSession();
      }
    };
    const scheduleTimeout = () => {
      clearTimer();
      timerId = window.setTimeout(() => {
        runTimeoutAction();
      }, timeoutMs);
    };
    const markActivity = () => {
      const now = Date.now();
      if (now - lastActivityAt < 1000) return;
      lastActivityAt = now;
      scheduleTimeout();
    };
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible') markActivity();
    };

    scheduleTimeout();
    window.addEventListener('pointerdown', markActivity, { passive: true });
    window.addEventListener('keydown', markActivity);
    window.addEventListener('scroll', markActivity, { passive: true });
    window.addEventListener('touchstart', markActivity, { passive: true });
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearTimer();
      window.removeEventListener('pointerdown', markActivity);
      window.removeEventListener('keydown', markActivity);
      window.removeEventListener('scroll', markActivity);
      window.removeEventListener('touchstart', markActivity);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [phase, lockTimeoutMinutes, sessionTimeoutAction]);

  function renderPassiveOverlays() {
    return (
      <AppGlobalOverlays
        toasts={toasts}
        onCloseToast={removeToast}
        confirm={null}
        onCancelConfirm={() => {}}
        pendingTotpOpen={false}
        pendingTotpProviderType={0}
        pendingTotpAvailableProviders={[]}
        totpCode=""
        rememberDevice={false}
        onTotpCodeChange={() => {}}
        onRememberDeviceChange={() => {}}
        onConfirmTotp={() => {}}
        onSelectTotpProvider={() => {}}
        onCancelTotp={() => {}}
        onUseRecoveryCode={() => {}}
        totpSubmitting={false}
        disableTotpOpen={false}
        disableTotpPassword=""
        onDisableTotpPasswordChange={() => {}}
        onConfirmDisableTotp={() => {}}
        onCancelDisableTotp={() => {}}
        disableTotpSubmitting={false}
      />
    );
  }

  useEffect(() => {
    if (!IS_DEMO_MODE) return;
    if (phase !== 'app') {
      setDecryptedFolders([]);
      setDecryptedCiphers([]);
      setDecryptedSends([]);
      setDemoUsers(DEMO_ADMIN_USERS.map((user) => ({ ...user })));
      setDemoInvites(DEMO_ADMIN_INVITES.map((invite) => ({ ...invite })));
      setDemoAuthorizedDevices(DEMO_AUTHORIZED_DEVICES.map((device) => ({ ...device })));
      setDemoBackupSettings(createDemoBackupSettings());
      setVaultInitialDecryptDone(false);
      setSendsDecryptDone(false);
      return;
    }
    setDecryptedFolders(DEMO_FOLDERS.map((folder) => ({ ...folder })));
    setDecryptedCiphers(DEMO_CIPHERS.map((cipher) => ({ ...cipher })));
    setDecryptedSends(DEMO_SENDS.map((send) => ({ ...send })));
    setDemoUsers(DEMO_ADMIN_USERS.map((user) => ({ ...user })));
    setDemoInvites(DEMO_ADMIN_INVITES.map((invite) => ({ ...invite })));
    setDemoAuthorizedDevices(DEMO_AUTHORIZED_DEVICES.map((device) => ({ ...device })));
    setDemoBackupSettings(createDemoBackupSettings());
    setVaultDecryptError('');
    setVaultInitialDecryptDone(true);
    setSendsDecryptDone(true);
  }, [phase]);

  useEffect(() => {
    if (IS_DEMO_MODE) {
      setCachedVaultCore(null);
      return;
    }
    let cancelled = false;
    if (phase !== 'app' || !session?.symEncKey || !session?.symMacKey || !vaultCacheKey) {
      setCachedVaultCore(null);
      return;
    }
    void (async () => {
      const snapshot = await getCachedVaultCoreSnapshot(vaultCacheKey);
      if (!cancelled) {
        setCachedVaultCore(snapshot);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [phase, session?.symEncKey, session?.symMacKey, vaultCacheKey]);

  async function refetchVaultCoreData() {
    if (pendingVaultCoreQueryRefreshRef.current) {
      return pendingVaultCoreQueryRefreshRef.current;
    }
    const request = vaultCoreQuery.refetch().finally(() => {
      if (pendingVaultCoreQueryRefreshRef.current === request) {
        pendingVaultCoreQueryRefreshRef.current = null;
      }
    });
    pendingVaultCoreQueryRefreshRef.current = request;
    return request;
  }

  const vaultCoreQuery = useQuery({
    queryKey: ['vault-core', vaultCacheKey],
    queryFn: () => loadVaultCoreSyncSnapshot(authedFetch, vaultCacheKey),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && !!session?.symEncKey && !!session?.symMacKey && !!vaultCacheKey,
    staleTime: 30_000,
  });
  const encryptedVaultCore = vaultCoreQuery.data || cachedVaultCore;
  const encryptedFolders = encryptedVaultCore?.folders;
  const encryptedCiphers = encryptedVaultCore?.ciphers;
  const encryptedSendsFromSync = encryptedVaultCore?.sends;
  const sendsQueryKey = useMemo(() => ['sends', vaultCacheKey || session?.email] as const, [vaultCacheKey, session?.email]);
  const sendsQuery = useQuery({
    queryKey: sendsQueryKey,
    queryFn: () => getSends(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && !!session?.symEncKey && !!session?.symMacKey && location === '/sends' && !encryptedSendsFromSync,
    staleTime: 30_000,
  });
  const encryptedSends = sendsQuery.data || encryptedSendsFromSync;
  async function refetchSendsFromVaultCore() {
    const result = await refetchVaultCoreData() as { data?: VaultCoreSnapshot };
    const sends = Array.isArray(result.data?.sends) ? result.data.sends : [];
    queryClient.setQueryData(sendsQueryKey, sends);
    return { data: sends };
  }
  useEffect(() => {
    if (!Array.isArray(encryptedSendsFromSync)) return;
    queryClient.setQueryData(sendsQueryKey, encryptedSendsFromSync);
  }, [queryClient, sendsQueryKey, encryptedSendsFromSync]);
  const profileQuery = useQuery({
    queryKey: ['profile', vaultCacheKey || session?.email],
    queryFn: () => getProfile(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken,
    staleTime: 30_000,
  });
  useEffect(() => {
    if (!profileQuery.data) return;
    setProfile(profileQuery.data);
  }, [profileQuery.data]);

  const isAdmin = isAdminProfile(profile);
  const usersQuery = useQuery({
    queryKey: ['admin-users', vaultCacheKey],
    queryFn: () => listAdminUsers(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && isAdmin && vaultInitialDecryptDone,
    staleTime: 30_000,
  });
  const invitesQuery = useQuery({
    queryKey: ['admin-invites', vaultCacheKey],
    queryFn: () => listAdminInvites(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && isAdmin && vaultInitialDecryptDone,
    staleTime: 30_000,
  });
  const twoFactorStatusQuery = useQuery({
    queryKey: ['two-factor-status', vaultCacheKey || session?.email],
    queryFn: () => getTwoFactorProviderStatus(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && vaultInitialDecryptDone,
    staleTime: 30_000,
  });
  const authorizedDevicesQuery = useQuery({
    queryKey: ['authorized-devices', vaultCacheKey || session?.email],
    queryFn: () => getAuthorizedDevices(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && vaultInitialDecryptDone,
    staleTime: 30_000,
  });
  const domainRulesQueryKey = useMemo(() => ['domain-rules', vaultCacheKey || session?.email] as const, [vaultCacheKey, session?.email]);
  const domainRulesQuery = useQuery({
    queryKey: domainRulesQueryKey,
    queryFn: () => getDomainRules(authedFetch),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && vaultInitialDecryptDone,
    staleTime: 30_000,
  });

  async function deriveCurrentMasterPasswordHash(masterPassword: string): Promise<string> {
    const email = String(profile?.email || session?.email || '').trim().toLowerCase();
    if (!email) throw new Error(t('txt_profile_unavailable'));
    const normalizedPassword = String(masterPassword || '');
    if (!normalizedPassword) throw new Error(t('txt_master_password_is_required'));
    const derived = await deriveLoginHash(email, normalizedPassword, defaultKdfIterations);
    return derived.hash;
  }
  const pendingAuthRequestsQueryKey = useMemo(() => ['auth-requests-pending', vaultCacheKey || session?.email] as const, [vaultCacheKey, session?.email]);
  const pendingAuthRequestsQuery = useQuery({
    queryKey: pendingAuthRequestsQueryKey,
    queryFn: () => listPendingAuthRequests(authedFetch, profile?.email || session?.email || ''),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && !!session?.symEncKey && !!session?.symMacKey && !!(profile?.email || session?.email),
    staleTime: 5_000,
  });
  const pendingAuthRequests = (pendingAuthRequestsQuery.data || []).filter(isPendingAuthRequest);
  const latestPendingAuthRequest = pendingAuthRequests[0] || null;
  const selectedPendingAuthRequest = authRequestDialogSelectedId
    ? pendingAuthRequests.find((request) => request.id === authRequestDialogSelectedId) || null
    : null;
  const authRequestDialogRequest = selectedPendingAuthRequest || (
    latestPendingAuthRequest && latestPendingAuthRequest.id !== authRequestDialogDismissedId
      ? latestPendingAuthRequest
      : null
  );
  const authRequestDialogOpen = !!authRequestDialogRequest;

  async function beginApproveAuthRequest(authRequest: AuthRequest): Promise<void> {
    setAuthRequestDialogSelectedId(authRequest.id);
    setAuthRequestDialogDismissedId(null);
  }

  async function approveAuthRequest(authRequest: AuthRequest): Promise<void> {
    if (!session) throw new Error(t('txt_vault_key_unavailable'));
    setAuthRequestSubmittingId(authRequest.id);
    try {
      const key = await encryptSessionUserKeyForAuthRequest(session, authRequest);
      await respondToAuthRequest(authedFetch, authRequest.id, {
        key,
        deviceIdentifier: getCurrentDeviceIdentifier(),
        requestApproved: true,
      });
      setAuthRequestDialogDismissedId(null);
      setAuthRequestDialogSelectedId(null);
      pushToast('success', t('txt_auth_request_approved'));
      await pendingAuthRequestsQuery.refetch();
    } finally {
      setAuthRequestSubmittingId(null);
    }
  }

  async function denyAuthRequest(authRequest: AuthRequest): Promise<void> {
    setAuthRequestSubmittingId(authRequest.id);
    try {
      await respondToAuthRequest(authedFetch, authRequest.id, {
        deviceIdentifier: getCurrentDeviceIdentifier(),
        requestApproved: false,
      });
      setAuthRequestDialogDismissedId(null);
      setAuthRequestDialogSelectedId(null);
      pushToast('success', t('txt_auth_request_denied'));
      await pendingAuthRequestsQuery.refetch();
    } finally {
      setAuthRequestSubmittingId(null);
    }
  }

  function handleSaveDomainRules(customEquivalentDomains: CustomEquivalentDomain[], excludedGlobalEquivalentDomains: number[]): Promise<void> {
    const equivalentDomains = customEquivalentDomains.filter((rule) => !rule.excluded).map((rule) => rule.domains);
    const excludedGlobalTypes = new Set(excludedGlobalEquivalentDomains);
    const currentRules = queryClient.getQueryData<DomainRules>(domainRulesQueryKey) || domainRulesQuery.data;
    const optimisticRules: DomainRules = {
      object: 'domains',
      equivalentDomains,
      customEquivalentDomains,
      globalEquivalentDomains: (currentRules?.globalEquivalentDomains || []).map((rule) => ({
        ...rule,
        excluded: excludedGlobalTypes.has(rule.type),
      })),
    };
    const saveSeq = ++domainRulesSaveSeqRef.current;
    queryClient.setQueryData(domainRulesQueryKey, optimisticRules);

    void saveDomainRules(authedFetch, {
      customEquivalentDomains,
      equivalentDomains,
      excludedGlobalEquivalentDomains,
    }).then((updated) => {
      if (domainRulesSaveSeqRef.current !== saveSeq) return;
      queryClient.setQueryData(domainRulesQueryKey, updated);
      void queryClient.invalidateQueries({ queryKey: ['vault-core', vaultCacheKey] });
    }).catch((error) => {
      if (domainRulesSaveSeqRef.current !== saveSeq) return;
      pushToast('error', error instanceof Error ? error.message : t('txt_domain_rules_save_failed'));
      void domainRulesQuery.refetch();
    });

    return Promise.resolve();
  }
  useQuery({
    queryKey: ['admin-backup-settings', vaultCacheKey],
    queryFn: () => backupActions.loadSettings(),
    enabled: !IS_DEMO_MODE && phase === 'app' && !!session?.accessToken && isAdmin && vaultInitialDecryptDone,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (!IS_DEMO_MODE) return;
    return preloadDemoExperience();
  }, []);

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    if (phase !== 'app' || !vaultInitialDecryptDone) return;
    void preloadAuthenticatedWorkspace(isAdmin);
  }, [phase, vaultInitialDecryptDone, isAdmin]);

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    if (phase !== 'app' || !session?.accessToken || !session?.symEncKey || !session?.symMacKey) return;
    if (!vaultInitialDecryptDone) return;
    if (!isAdminProfile(profile)) return;
    if (repairAttemptRef.current === session.accessToken) return;

    const loginScopedRepairAuth = loginScopedBackupRepairAuthRef.current?.accessToken === session.accessToken
      ? loginScopedBackupRepairAuthRef.current
      : null;
    repairAttemptRef.current = session.accessToken;
    void (async () => {
      try {
        await silentlyRepairBackupSettingsIfNeeded(session, profile, loginScopedRepairAuth);
      } finally {
        if (loginScopedBackupRepairAuthRef.current?.accessToken === session.accessToken) {
          loginScopedBackupRepairAuthRef.current = null;
        }
      }
    })();
  }, [phase, session?.accessToken, session?.symEncKey, session?.symMacKey, profile, vaultInitialDecryptDone]);

  useEffect(() => {
    if (session?.accessToken) return;
    repairAttemptRef.current = '';
    loginScopedBackupRepairAuthRef.current = null;
    uriChecksumRepairAttemptRef.current = '';
  }, [session?.accessToken]);

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    if (!session?.symEncKey || !session?.symMacKey) {
      setDecryptedFolders([]);
      setDecryptedCiphers([]);
      setDecryptedSends([]);
      setVaultInitialDecryptDone(false);
      setVaultDecryptError('');
      setSendsDecryptDone(false);
      return;
    }
    if (!encryptedFolders || !encryptedCiphers) return;

    let active = true;
    (async () => {
      try {
        setVaultDecryptError('');
        let result;
        try {
          result = await decryptVaultCoreInWorker({
            folders: encryptedFolders,
            ciphers: encryptedCiphers,
            symEncKeyB64: session.symEncKey!,
            symMacKeyB64: session.symMacKey!,
          });
        } catch {
          result = await decryptVaultCore({
            folders: encryptedFolders,
            ciphers: encryptedCiphers,
            symEncKeyB64: session.symEncKey!,
            symMacKeyB64: session.symMacKey!,
          });
        }

        if (!active) return;
        setDecryptedFolders(result.folders);
        setDecryptedCiphers(result.ciphers);
        setVaultInitialDecryptDone(true);
        if (!session.accessToken) return;
        const repairKey = `${session.accessToken}:${encryptedCiphers.map((cipher) => `${cipher.id}:${cipher.revisionDate || ''}`).join(',')}`;
        if (uriChecksumRepairAttemptRef.current !== repairKey) {
          uriChecksumRepairAttemptRef.current = repairKey;
          void repairCipherKeyMismatches(authedFetch, session, result.ciphers)
            .then(async (keyMismatchCount) => {
              if (keyMismatchCount > 0) {
                await invalidateVaultCoreSyncSnapshot(vaultCacheKey);
                void refetchVaultCoreData();
                return;
              }
              const uriChecksumCount = await repairCipherUriChecksums(authedFetch, session, result.ciphers);
              if (uriChecksumCount > 0) {
                await invalidateVaultCoreSyncSnapshot(vaultCacheKey);
                void refetchVaultCoreData();
              }
            })
            .catch(() => {
              // Best-effort compatibility repair must not interrupt normal vault loading.
            });
        }
      } catch (error) {
        if (!active) return;
        const message = error instanceof Error ? error.message : t('txt_decrypt_failed_2');
        setVaultDecryptError(message);
        setVaultInitialDecryptDone(true);
        pushToast('error', message);
      }
    })();

    return () => {
      active = false;
    };
  }, [session?.symEncKey, session?.symMacKey, vaultCacheKey, encryptedFolders, encryptedCiphers]);

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    if (!session?.symEncKey || !session?.symMacKey) {
      setDecryptedSends([]);
      setSendsDecryptDone(false);
      return;
    }
    if (!encryptedSends) {
      setSendsDecryptDone(false);
      return;
    }
    if (!encryptedSends.length) {
      setDecryptedSends([]);
      setSendsDecryptDone(true);
      return;
    }

    let active = true;
    setSendsDecryptDone(false);
    (async () => {
      try {
        let sends;
        try {
          sends = await decryptSendsInWorker({
            sends: encryptedSends,
            symEncKeyB64: session.symEncKey!,
            symMacKeyB64: session.symMacKey!,
            origin: window.location.origin,
          });
        } catch {
          sends = await decryptSends({
            sends: encryptedSends,
            symEncKeyB64: session.symEncKey!,
            symMacKeyB64: session.symMacKey!,
            origin: window.location.origin,
          });
        }

        if (!active) return;
        setDecryptedSends(sends);
        setSendsDecryptDone(true);
      } catch (error) {
        if (!active) return;
        setSendsDecryptDone(true);
        pushToast('error', error instanceof Error ? error.message : t('txt_decrypt_failed_2'));
      }
    })();

    return () => {
      active = false;
    };
  }, [session?.symEncKey, session?.symMacKey, encryptedSends]);

  async function refreshVaultSilently() {
    if (pendingVaultCoreRefreshRef.current) {
      await pendingVaultCoreRefreshRef.current;
      return;
    }
    const request = refetchVaultCoreData().finally(() => {
      if (pendingVaultCoreRefreshRef.current === request) {
        pendingVaultCoreRefreshRef.current = null;
      }
    });
    pendingVaultCoreRefreshRef.current = request;
    await request;
  }

  silentRefreshVaultRef.current = refreshVaultSilently;

  function normalizeVaultCoreSnapshot(snapshot?: Partial<VaultCoreSnapshot> | null): VaultCoreSnapshot {
    return {
      ciphers: Array.isArray(snapshot?.ciphers) ? snapshot.ciphers : [],
      folders: Array.isArray(snapshot?.folders) ? snapshot.folders : [],
      sends: Array.isArray(snapshot?.sends) ? snapshot.sends : [],
    };
  }

  function upsertById<T extends { id: string }>(items: T[], nextItem: T): T[] {
    const nextId = String(nextItem.id || '').trim();
    if (!nextId) return items;
    const index = items.findIndex((item) => String(item.id || '').trim() === nextId);
    if (index < 0) return [...items, nextItem];
    const next = items.slice();
    next[index] = nextItem;
    return next;
  }

  function removeById<T extends { id: string }>(items: T[], id: string): T[] {
    const normalizedId = String(id || '').trim();
    if (!normalizedId) return items;
    return items.filter((item) => String(item.id || '').trim() !== normalizedId);
  }

  function revisionStampFromIso(value: unknown): number | null {
    const stamp = new Date(String(value || '').trim()).getTime();
    return Number.isFinite(stamp) && stamp > 0 ? stamp : null;
  }

  function patchVaultCoreSnapshot(
    updater: (snapshot: VaultCoreSnapshot) => VaultCoreSnapshot,
    options?: { revisionStamp?: number | null }
  ): void {
    if (!vaultCacheKey) return;
    let nextSnapshot: VaultCoreSnapshot | null = null;
    queryClient.setQueryData(['vault-core', vaultCacheKey], (previous?: VaultCoreSnapshot) => {
      const base = normalizeVaultCoreSnapshot(previous || cachedVaultCore);
      nextSnapshot = updater(base);
      return nextSnapshot;
    });
    if (nextSnapshot) {
      setCachedVaultCore(nextSnapshot);
      void saveVaultCoreSyncSnapshot(vaultCacheKey, nextSnapshot, options?.revisionStamp ?? null);
    }
  }

  async function refreshVaultCoreRevisionStamp(): Promise<void> {
    if (!vaultCacheKey || !session?.accessToken) return;
    try {
      const revisionStamp = await getVaultRevisionDate(authedFetch);
      const currentSnapshot = normalizeVaultCoreSnapshot(
        queryClient.getQueryData<VaultCoreSnapshot>(['vault-core', vaultCacheKey]) || cachedVaultCore
      );
      await saveVaultCoreSyncSnapshot(vaultCacheKey, currentSnapshot, revisionStamp);
    } catch {
      // A stale revision stamp only affects the next cache validation; the local resource patch remains valid.
    }
  }

  function upsertEncryptedCipher(cipher: Cipher, revisionStamp?: number | null): void {
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      ciphers: upsertById(snapshot.ciphers, cipher),
    }), { revisionStamp: revisionStamp ?? revisionStampFromIso(cipher.revisionDate) });
  }

  function deleteCipherLocally(cipherId: string, revisionStamp?: number | null): void {
    const id = String(cipherId || '').trim();
    if (!id) return;
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      ciphers: removeById(snapshot.ciphers, id),
    }), { revisionStamp });
    setDecryptedCiphers((current) => removeById(current, id));
  }

  function upsertEncryptedFolder(folder: VaultFolder, revisionStamp?: number | null): void {
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      folders: upsertById(snapshot.folders, folder),
    }), { revisionStamp: revisionStamp ?? revisionStampFromIso(folder.revisionDate) });
  }

  function deleteFolderLocally(folderId: string, revisionStamp?: number | null): void {
    const id = String(folderId || '').trim();
    if (!id) return;
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      folders: removeById(snapshot.folders, id),
      ciphers: snapshot.ciphers.map((cipher) => (
        String(cipher.folderId || '').trim() === id ? { ...cipher, folderId: null } : cipher
      )),
    }), { revisionStamp });
    setDecryptedFolders((current) => removeById(current, id));
    setDecryptedCiphers((current) => current.map((cipher) => (
      String(cipher.folderId || '').trim() === id ? { ...cipher, folderId: null } : cipher
    )));
  }

  function upsertEncryptedSend(send: Send, revisionStamp?: number | null): void {
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      sends: upsertById(snapshot.sends, send),
    }), { revisionStamp: revisionStamp ?? revisionStampFromIso(send.revisionDate) });
    queryClient.setQueryData(sendsQueryKey, (previous?: Send[]) => upsertById(Array.isArray(previous) ? previous : [], send));
  }

  function deleteSendLocally(sendId: string, revisionStamp?: number | null): void {
    const id = String(sendId || '').trim();
    if (!id) return;
    patchVaultCoreSnapshot((snapshot) => ({
      ...snapshot,
      sends: removeById(snapshot.sends, id),
    }), { revisionStamp });
    queryClient.setQueryData(sendsQueryKey, (previous?: Send[]) => removeById(Array.isArray(previous) ? previous : [], id));
    setDecryptedSends((current) => removeById(current, id));
  }

  async function upsertCipherFromNotification(cipherId: string, revisionStamp?: number | null): Promise<void> {
    const id = String(cipherId || '').trim();
    if (!id || !session?.symEncKey || !session?.symMacKey) return;
    try {
      const encrypted = await getCipherById(authedFetch, id);
      upsertEncryptedCipher(encrypted, revisionStamp);
      const result = await decryptVaultCore({
        folders: [],
        ciphers: [encrypted],
        symEncKeyB64: session.symEncKey,
        symMacKeyB64: session.symMacKey,
      });
      const decrypted = result.ciphers[0];
      if (decrypted) setDecryptedCiphers((current) => upsertById(current, decrypted));
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        deleteCipherLocally(id);
        return;
      }
      console.warn('Failed to upsert cipher from notification:', error);
    }
  }

  async function upsertFolderFromNotification(folderId: string, revisionStamp?: number | null): Promise<void> {
    const id = String(folderId || '').trim();
    if (!id || !session?.symEncKey || !session?.symMacKey) return;
    try {
      const encrypted = await getFolderById(authedFetch, id);
      upsertEncryptedFolder(encrypted, revisionStamp);
      const result = await decryptVaultCore({
        folders: [encrypted],
        ciphers: [],
        symEncKeyB64: session.symEncKey,
        symMacKeyB64: session.symMacKey,
      });
      const decrypted = result.folders[0];
      if (decrypted) setDecryptedFolders((current) => upsertById(current, decrypted));
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        deleteFolderLocally(id);
        return;
      }
      console.warn('Failed to upsert folder from notification:', error);
    }
  }

  async function upsertSendFromNotification(sendId: string, revisionStamp?: number | null): Promise<void> {
    const id = String(sendId || '').trim();
    if (!id || !session?.symEncKey || !session?.symMacKey) return;
    try {
      const encrypted = await getSendById(authedFetch, id);
      upsertEncryptedSend(encrypted, revisionStamp);
      const sends = await decryptSends({
        sends: [encrypted],
        symEncKeyB64: session.symEncKey,
        symMacKeyB64: session.symMacKey,
        origin: window.location.origin,
      });
      const decrypted = sends[0];
      if (decrypted) setDecryptedSends((current) => upsertById(current, decrypted));
    } catch (error) {
      if ((error as { status?: number }).status === 404) {
        deleteSendLocally(id);
        return;
      }
      console.warn('Failed to upsert send from notification:', error);
    }
  }

  useEffect(() => {
    if (IS_DEMO_MODE) return;
    if (phase !== 'app' || !session?.accessToken || !session?.symEncKey || !session?.symMacKey || !vaultInitialDecryptDone) return;

    let disposed = false;
    let socket: WebSocket | null = null;
    let reconnectTimer: number | null = null;
    let reconnectAttempts = 0;

    const clearReconnectTimer = () => {
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
    };

    const scheduleReconnect = () => {
      if (disposed) return;
      clearReconnectTimer();
      const delay = Math.min(10000, 1000 * Math.max(1, reconnectAttempts + 1));
      reconnectAttempts += 1;
      reconnectTimer = window.setTimeout(() => {
        reconnectTimer = null;
        connect();
      }, delay);
    };

    const connect = () => {
      if (disposed) return;
      const accessToken = session.accessToken;
      if (!accessToken) return;
      try {
        const hubUrl = new URL('/notifications/hub', window.location.origin);
        hubUrl.searchParams.set('access_token', accessToken);
        hubUrl.protocol = hubUrl.protocol === 'https:' ? 'wss:' : 'ws:';
        socket = new WebSocket(hubUrl.toString());
      } catch {
        scheduleReconnect();
        return;
      }

      let pingTimer: number | null = null;

      const clearPingTimer = () => {
        if (pingTimer !== null) {
          window.clearInterval(pingTimer);
          pingTimer = null;
        }
      };

      socket.addEventListener('open', () => {
        reconnectAttempts = 0;
        void refreshAuthorizedDevicesRef.current();
        try {
          socket?.send(`{"protocol":"json","version":1}${SIGNALR_RECORD_SEPARATOR}`);
        } catch {
          socket?.close();
          return;
        }
        clearPingTimer();
        pingTimer = window.setInterval(() => {
          try {
            socket?.send(`{"type":6}${SIGNALR_RECORD_SEPARATOR}`);
          } catch {
            // send failure will trigger close event
          }
        }, 15_000);
      });

      socket.addEventListener('message', (event) => {
        if (disposed) return;
        if (typeof event.data !== 'string') return;

        const frames = parseSignalRTextFrames(event.data);
        for (const frame of frames) {
          if (frame.type !== 1 || frame.target !== 'ReceiveMessage') continue;
          const message = frame.arguments?.[0] as Record<string, unknown> | undefined;
          const updateType = Number(message?.Type || 0);
          const contextId = String(message?.ContextId || '').trim();
          const payload = message?.Payload;
          const payloadRecord = payload && typeof payload === 'object' ? payload as Record<string, unknown> : null;
          const resourceId = String(payloadRecord?.Id || payloadRecord?.id || '').trim();
          const revisionStamp = revisionStampFromIso(
            payloadRecord?.RevisionDate
            || payloadRecord?.revisionDate
            || message?.Date
            || message?.date
          );
          if (updateType === SIGNALR_UPDATE_TYPE_LOG_OUT) {
            logoutNow();
            return;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_DEVICE_STATUS) {
            void refreshAuthorizedDevicesRef.current();
            continue;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_AUTH_REQUEST || updateType === SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE) {
            void refreshPendingAuthRequestsRef.current();
            continue;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS) {
            if (isBackupProgressDetail(payload)) dispatchBackupProgress(payload);
            continue;
          }
          if (contextId && contextId === getCurrentDeviceIdentifier()) continue;
          if (updateType === SIGNALR_UPDATE_TYPE_SYNC_CIPHERS || updateType === SIGNALR_UPDATE_TYPE_SYNC_VAULT) {
            if (notificationRefreshTimerRef.current !== null) {
              window.clearTimeout(notificationRefreshTimerRef.current);
            }
            notificationRefreshTimerRef.current = window.setTimeout(() => {
              notificationRefreshTimerRef.current = null;
              void silentRefreshVaultRef.current();
            }, 250);
            continue;
          }
          if ((updateType === SIGNALR_UPDATE_TYPE_SYNC_CIPHER_CREATE || updateType === SIGNALR_UPDATE_TYPE_SYNC_CIPHER_UPDATE) && resourceId) {
            void upsertCipherFromNotification(resourceId, revisionStamp);
            continue;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_SYNC_CIPHER_DELETE && resourceId) {
            deleteCipherLocally(resourceId, revisionStamp);
            continue;
          }
          if ((updateType === SIGNALR_UPDATE_TYPE_SYNC_FOLDER_CREATE || updateType === SIGNALR_UPDATE_TYPE_SYNC_FOLDER_UPDATE) && resourceId) {
            void upsertFolderFromNotification(resourceId, revisionStamp);
            continue;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_SYNC_FOLDER_DELETE && resourceId) {
            deleteFolderLocally(resourceId, revisionStamp);
            continue;
          }
          if ((updateType === SIGNALR_UPDATE_TYPE_SYNC_SEND_CREATE || updateType === SIGNALR_UPDATE_TYPE_SYNC_SEND_UPDATE) && resourceId) {
            void upsertSendFromNotification(resourceId, revisionStamp);
            continue;
          }
          if (updateType === SIGNALR_UPDATE_TYPE_SYNC_SEND_DELETE && resourceId) {
            deleteSendLocally(resourceId, revisionStamp);
            continue;
          }
        }
      });

      socket.addEventListener('close', () => {
        socket = null;
        clearPingTimer();
        void refreshAuthorizedDevicesRef.current();
        scheduleReconnect();
      });

      socket.addEventListener('error', () => {
        try {
          socket?.close();
        } catch {
          // ignore close races
        }
      });
    };

    connect();

    return () => {
      disposed = true;
      if (notificationRefreshTimerRef.current !== null) {
        window.clearTimeout(notificationRefreshTimerRef.current);
        notificationRefreshTimerRef.current = null;
      }
      clearReconnectTimer();
      if (socket) {
        const s = socket;
        socket = null;
        try {
          s.close();
        } catch {
          // ignore close races
        }
      }
    };
  }, [phase, session?.accessToken, session?.symEncKey, session?.symMacKey, vaultInitialDecryptDone]);

  const vaultSendActions = useVaultSendActions({
    authedFetch,
    importAuthedFetch,
    session,
    profile,
    defaultKdfIterations,
    encryptedCiphers,
    encryptedFolders,
    refetchCiphers: async () => {
      const result = await refetchVaultCoreData() as { data?: VaultCoreSnapshot };
      return { data: result.data?.ciphers };
    },
    refetchFolders: async () => {
      const result = await refetchVaultCoreData() as { data?: VaultCoreSnapshot };
      return { data: result.data?.folders };
    },
    refetchSends: refetchSendsFromVaultCore,
    onNotify: pushToast,
    patchEncryptedCiphers: (updater) => {
      patchVaultCoreSnapshot((snapshot) => ({
        ...snapshot,
        ciphers: updater(snapshot.ciphers),
      }));
    },
    patchEncryptedFolders: (updater) => {
      patchVaultCoreSnapshot((snapshot) => ({
        ...snapshot,
        folders: updater(snapshot.folders),
      }));
    },
    patchEncryptedSends: (updater) => {
      let nextSends: Send[] = [];
      patchVaultCoreSnapshot((snapshot) => {
        nextSends = updater(snapshot.sends);
        return {
          ...snapshot,
          sends: nextSends,
        };
      });
      queryClient.setQueryData(sendsQueryKey, nextSends);
    },
    patchDecryptedCiphers: setDecryptedCiphers,
    patchDecryptedFolders: setDecryptedFolders,
    patchDecryptedSends: setDecryptedSends,
    refreshVaultRevisionStamp: refreshVaultCoreRevisionStamp,
  });
  const accountSecurityActions = useAccountSecurityActions({
    authedFetch,
    profile,
    session,
    defaultKdfIterations,
    disableTotpPassword,
    clearDisableTotpDialog: () => {
      setDisableTotpOpen(false);
      setDisableTotpPassword('');
    },
    onLogoutNow: logoutNow,
    onNotify: pushToast,
    onProfileUpdated: setProfile,
    onSetConfirm: setConfirm,
    refetchTwoFactorStatus: twoFactorStatusQuery.refetch,
    refetchAuthorizedDevices: authorizedDevicesQuery.refetch,
  });
  const adminActions = useAdminActions({
    authedFetch,
    onNotify: pushToast,
    onSetConfirm: setConfirm,
    refetchUsers: usersQuery.refetch,
    refetchInvites: invitesQuery.refetch,
  });

  refreshAuthorizedDevicesRef.current = async () => {
    if (!vaultInitialDecryptDone) return;
    await authorizedDevicesQuery.refetch();
  };
  refreshPendingAuthRequestsRef.current = async () => {
    if (!vaultInitialDecryptDone || !(profile?.email || session?.email)) return;
    setAuthRequestDialogDismissedId(null);
    await pendingAuthRequestsQuery.refetch();
  };

  const hashPath = hashPathRaw.startsWith('#') ? hashPathRaw.slice(1) : hashPathRaw;
  const hashPathOnly = String(hashPath || '').split('?')[0].split('#')[0];
  const trimmedHashPath = hashPathOnly.replace(/^\/+/, '').replace(/\/+$/, '');
  const normalizedHashPath = trimmedHashPath ? `/${trimmedHashPath}` : '/';
  const isImportHashRoute = IMPORT_ROUTE_ALIASES.has(normalizedHashPath);
  const normalizedLocation = normalizeRoutePath(location);
  const routeLocation = hashPath.startsWith('/') ? normalizedHashPath : normalizedLocation;
  const effectiveLocation = routeLocation;
  const publicSendMatch = effectiveLocation.match(/^\/send\/([^/]+)(?:\/([^/]+))?\/?$/i);
  const isRecoverTwoFactorRoute = effectiveLocation === '/recover-2fa';
  const isPublicSendRoute = !!publicSendMatch;
  const isMalformedSendRoute = /^\/send(?:\/|$)/i.test(effectiveLocation) && !publicSendMatch;
  const isKnownAuthRoute = AUTH_ROUTES.has(routeLocation) || isPublicSendRoute || isRecoverTwoFactorRoute;
  const isKnownAppRoute = APP_ROUTES.has(routeLocation) || isPublicSendRoute || isImportHashRoute;
  const isUnknownRoute = isMalformedSendRoute || (phase === 'app' ? !isKnownAppRoute : !isKnownAuthRoute && !APP_ROUTES.has(routeLocation));
  const isImportRoute = routeLocation === IMPORT_ROUTE || IMPORT_ROUTE_ALIASES.has(routeLocation);
  const showSidebarToggle = mobileLayout && location === '/sends';
  const sidebarToggleTitle = location === '/vault' ? t('txt_folders') : t('txt_type');
  const demoDomainRules = useMemo<DomainRules>(() => ({
    equivalentDomains: [
      ['nodewarden.example', 'nw.example'],
      ['staging.nodewarden.example', 'preview.nodewarden.example'],
    ],
    customEquivalentDomains: [
      { id: 'demo-custom-1', domains: ['nodewarden.example', 'nw.example'], excluded: false },
      { id: 'demo-custom-2', domains: ['staging.nodewarden.example', 'preview.nodewarden.example'], excluded: false },
    ],
    globalEquivalentDomains: [
      { type: 0, domains: ['youtube.com', 'google.com', 'gmail.com'], excluded: false },
      { type: 1, domains: ['apple.com', 'icloud.com'], excluded: false },
      { type: 10, domains: ['microsoft.com', 'office.com', 'xbox.com'], excluded: true },
      { type: -10001, domains: ['nodewarden.example', 'nw.example'], excluded: false },
    ],
    object: 'domains',
  }), []);
  const mobilePrimaryRoute =
    location === '/sends'
      ? '/sends'
      : location === '/vault/totp'
        ? '/vault/totp'
        : location === '/vault'
          ? '/vault'
          : '/settings';
  const currentPageTitle = (() => {
    if (location === '/vault/totp') return t('txt_verification_code');
    if (location === '/sends') return t('nav_sends');
    if (location === '/admin') return t('nav_admin_panel');
    if (location === '/logs') return t('nav_log_center');
    if (location === LEGACY_DEVICE_MANAGEMENT_ROUTE || location === DEVICE_MANAGEMENT_ROUTE) return t('nav_device_management');
    if (location === SETTINGS_DOMAIN_RULES_ROUTE) return t('nav_domain_rules');
    if (location === '/backup') return t('nav_backup_strategy');
    if (isImportRoute) return t('nav_import_export');
    if (location === SETTINGS_ACCOUNT_ROUTE) return t('nav_account_settings');
    if (location === SETTINGS_HOME_ROUTE) return t('txt_settings');
    return t('nav_my_vault');
  })();

  useEffect(() => {
    if (phase !== 'app') return;
    if (!hashPath.startsWith('/')) return;
    if (normalizedHashPath !== DEVICE_MANAGEMENT_ROUTE && normalizedHashPath !== LEGACY_DEVICE_MANAGEMENT_ROUTE) return;
    if (typeof window !== 'undefined' && typeof window.history?.replaceState === 'function') {
      window.history.replaceState(null, '', DEVICE_MANAGEMENT_ROUTE);
    }
    if (location !== DEVICE_MANAGEMENT_ROUTE) navigate(DEVICE_MANAGEMENT_ROUTE);
  }, [phase, hashPath, normalizedHashPath, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && location === '/' && !isPublicSendRoute) navigate('/vault');
  }, [phase, location, isPublicSendRoute, navigate]);

  useEffect(() => {
    if (phase === 'register' && (location === '/' || location === '/login') && !isPublicSendRoute) {
      navigate('/register');
    }
  }, [phase, location, isPublicSendRoute, navigate]);

  useEffect(() => {
    if (phase === 'app' && isImportHashRoute && location !== IMPORT_ROUTE) {
      navigate(IMPORT_ROUTE);
    }
  }, [phase, isImportHashRoute, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && !isAdminProfile(profile) && (location === '/backup' || location === '/logs') && !profileQuery.isFetching) {
      navigate('/vault');
    }
  }, [phase, profile?.role, profileQuery.isFetching, location, navigate]);

  useEffect(() => {
    if (phase === 'app' && !mobileLayout && location === SETTINGS_HOME_ROUTE) {
      navigate(SETTINGS_ACCOUNT_ROUTE);
    }
  }, [phase, mobileLayout, location, navigate]);

  const mainRoutesProps = {
    profile,
    profileLoading: profileQuery.isFetching && !profile,
    session,
    mobileLayout,
    mobileSidebarToggleKey,
    themePreference,
    importRoute: IMPORT_ROUTE,
    settingsHomeRoute: SETTINGS_HOME_ROUTE,
    settingsAccountRoute: SETTINGS_ACCOUNT_ROUTE,
    decryptedCiphers,
    decryptedFolders,
    decryptedSends,
    vaultError: vaultCoreQuery.isError && !encryptedVaultCore ? t('txt_load_vault_failed') : vaultDecryptError,
    ciphersLoading: !(vaultCoreQuery.isError && !encryptedVaultCore) && !vaultDecryptError && !vaultInitialDecryptDone,
    foldersLoading: !(vaultCoreQuery.isError && !encryptedVaultCore) && !vaultDecryptError && !vaultInitialDecryptDone,
    sendsLoading: (sendsQuery.isFetching && !encryptedSends) || (!!encryptedSends && !sendsDecryptDone),
    users: usersQuery.data || [],
    invites: invitesQuery.data || [],
    adminLoading: (usersQuery.isFetching && !usersQuery.data) || (invitesQuery.isFetching && !invitesQuery.data),
    adminError: usersQuery.isError || invitesQuery.isError ? t('txt_load_admin_data_failed') : '',
    totpEnabled: !!twoFactorStatusQuery.data?.totpEnabled,
    yubikeyEnabled: !!twoFactorStatusQuery.data?.yubikeyEnabled,
    passkey2faEnabled: !!twoFactorStatusQuery.data?.passkeyEnabled,
    lockTimeoutMinutes,
    sessionTimeoutAction,
    authorizedDevices: authorizedDevicesQuery.data || [],
    currentDeviceIdentifier: getCurrentDeviceIdentifier(),
    authorizedDevicesLoading: authorizedDevicesQuery.isFetching,
    authorizedDevicesError: authorizedDevicesQuery.isError && !authorizedDevicesQuery.data ? t('txt_load_devices_failed') : '',
    domainRules: IS_DEMO_MODE ? demoDomainRules : domainRulesQuery.data || null,
    domainRulesLoading: domainRulesQuery.isFetching && !domainRulesQuery.data,
    domainRulesError: domainRulesQuery.isError && !domainRulesQuery.data ? t('txt_domain_rules_load_failed') : '',
    onNavigate: navigate,
    onLogout: handleLogout,
    onNotify: pushToast,
    onThemePreferenceChange: setThemePreference,
    onImport: vaultSendActions.importVault,
    onImportEncryptedRaw: vaultSendActions.importEncryptedRaw,
    onExport: vaultSendActions.exportVault,
    onCreateVaultItem: vaultSendActions.createVaultItem,
    onUpdateVaultItem: vaultSendActions.updateVaultItem,
    onDeleteVaultItem: vaultSendActions.deleteVaultItem,
    onArchiveVaultItem: vaultSendActions.archiveVaultItem,
    onUnarchiveVaultItem: vaultSendActions.unarchiveVaultItem,
    onRestoreVaultItems: vaultSendActions.bulkRestoreVaultItems,
    onBulkDeleteVaultItems: vaultSendActions.bulkDeleteVaultItems,
    onBulkPermanentDeleteVaultItems: vaultSendActions.bulkPermanentDeleteVaultItems,
    onBulkRestoreVaultItems: vaultSendActions.bulkRestoreVaultItems,
    onBulkArchiveVaultItems: vaultSendActions.bulkArchiveVaultItems,
    onBulkUnarchiveVaultItems: vaultSendActions.bulkUnarchiveVaultItems,
    onBulkMoveVaultItems: vaultSendActions.bulkMoveVaultItems,
    onVerifyMasterPassword: vaultSendActions.verifyMasterPassword,
    onCreateFolder: vaultSendActions.createFolder,
    onRenameFolder: vaultSendActions.renameFolder,
    onDeleteFolder: vaultSendActions.deleteFolder,
    onBulkDeleteFolders: vaultSendActions.bulkDeleteFolders,
    onDownloadVaultAttachment: vaultSendActions.downloadVaultAttachment,
    downloadingAttachmentKey: vaultSendActions.downloadingAttachmentKey,
    attachmentDownloadPercent: vaultSendActions.attachmentDownloadPercent,
    uploadingAttachmentName: vaultSendActions.uploadingAttachmentName,
    attachmentUploadPercent: vaultSendActions.attachmentUploadPercent,
    onRefreshVault: vaultSendActions.refreshVault,
    onCreateSend: vaultSendActions.createSend,
    onUpdateSend: vaultSendActions.updateSend,
    onDeleteSend: vaultSendActions.deleteSend,
    onBulkDeleteSends: vaultSendActions.bulkDeleteSends,
    uploadingSendFileName: vaultSendActions.uploadingSendFileName,
    sendUploadPercent: vaultSendActions.sendUploadPercent,
    onChangePassword: accountSecurityActions.changePassword,
    onSavePasswordHint: accountSecurityActions.savePasswordHint,
    onEnableTotp: async (secret: string, token: string, masterPassword: string) => {
      await accountSecurityActions.enableTotp(secret, token, masterPassword);
      await twoFactorStatusQuery.refetch();
    },
    onOpenDisableTotp: () => setDisableTotpOpen(true),
    onGetYubiKeySettings: accountSecurityActions.getYubiKeySettings,
    onSaveYubiKeySettings: accountSecurityActions.saveYubiKeySettings,
    onSaveYubiKeyApiCredentials: accountSecurityActions.saveYubiKeyApiCredentials,
    onBootstrapYubiKeyApiCredentials: accountSecurityActions.bootstrapYubiKeyApiCredentials,
    onDisableYubiKey: accountSecurityActions.disableYubiKey,
    onGetTwoFactorPasskeySettings: accountSecurityActions.getTwoFactorPasskeySettings,
    onCreateTwoFactorPasskey: accountSecurityActions.createTwoFactorPasskey,
    onDeleteTwoFactorPasskey: accountSecurityActions.deleteTwoFactorPasskey,
    onDisableTwoFactorPasskeys: accountSecurityActions.disableTwoFactorPasskeys,
    onGetRecoveryCode: accountSecurityActions.getRecoveryCode,
    onGetApiKey: accountSecurityActions.getApiKey,
    onRotateApiKey: accountSecurityActions.rotateApiKey,
    onListAccountPasskeys: accountSecurityActions.listAccountPasskeys,
    onCreateAccountPasskey: accountSecurityActions.createAccountPasskey,
    onEnableAccountPasskeyDirectUnlock: accountSecurityActions.enableAccountPasskeyDirectUnlock,
    onDeleteAccountPasskey: accountSecurityActions.deleteAccountPasskey,
    onRefreshTwoFactorStatus: async () => {
      await twoFactorStatusQuery.refetch();
    },
    pendingAuthRequests,
    pendingAuthRequestsLoading: pendingAuthRequestsQuery.isLoading,
    pendingAuthRequestsRefreshing: pendingAuthRequestsQuery.isFetching && !pendingAuthRequestsQuery.isLoading,
    onRefreshPendingAuthRequests: async () => {
      await pendingAuthRequestsQuery.refetch();
    },
    onApproveAuthRequest: beginApproveAuthRequest,
    onDenyAuthRequest: denyAuthRequest,
    onLockTimeoutChange: setLockTimeoutMinutes,
    onSessionTimeoutActionChange: setSessionTimeoutAction,
    onRefreshAuthorizedDevices: accountSecurityActions.refreshAuthorizedDevices,
    onRefreshDomainRules: () => {
      void domainRulesQuery.refetch();
    },
    onSaveDomainRules: handleSaveDomainRules,
    onRenameAuthorizedDevice: accountSecurityActions.renameAuthorizedDevice,
    onRevokeDeviceTrust: accountSecurityActions.openRevokeDeviceTrust,
    onTrustDevicePermanently: accountSecurityActions.openTrustDevicePermanently,
    onRemoveDevice: accountSecurityActions.openRemoveDevice,
    onRemoveSelectedDevices: accountSecurityActions.openRemoveSelectedDevices,
    onRevokeAllDeviceTrust: accountSecurityActions.openRevokeAllDeviceTrust,
    onRemoveAllDevices: accountSecurityActions.openRemoveAllDevices,
    onRefreshAdmin: adminActions.refreshAdmin,
    onCreateInvite: adminActions.createInvite,
    onDeleteInvalidInvites: adminActions.deleteInvalidInvites,
    onDeleteAllInvites: adminActions.deleteAllInvites,
    onToggleUserStatus: adminActions.toggleUserStatus,
    onDeleteUser: adminActions.deleteUser,
    onDeleteInvite: adminActions.deleteInvite,
    onLoadAuditLogs: (filters: AuditLogFilters) => listAuditLogs(authedFetch, filters),
    onLoadAuditLogSettings: () => getAuditLogSettings(authedFetch),
    onSaveAuditLogSettings: (settings: AuditLogSettings) => saveAuditLogSettings(authedFetch, settings),
    onClearAuditLogs: () => clearAuditLogs(authedFetch),
    onExportBackup: async (masterPassword: string, includeAttachments?: boolean) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.exportBackup(hash, includeAttachments);
    },
    onImportBackup: async (masterPassword: string, file: File, replaceExisting?: boolean) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.importBackup(hash, file, replaceExisting);
    },
    onImportBackupAllowingChecksumMismatch: async (masterPassword: string, file: File, replaceExisting?: boolean) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.importBackupAllowingChecksumMismatch(hash, file, replaceExisting);
    },
    onLoadBackupSettings: () => queryClient.ensureQueryData({
      queryKey: ['admin-backup-settings', vaultCacheKey],
      queryFn: () => backupActions.loadSettings(),
      staleTime: 30_000,
    }),
    onSaveBackupSettings: async (masterPassword: string, settings: AdminBackupSettings) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      const saved = await backupActions.saveSettings(hash, settings);
      queryClient.setQueryData(['admin-backup-settings', vaultCacheKey], saved);
      return saved;
    },
    onRunRemoteBackup: async (masterPassword: string, destinationId?: string | null) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      const result = await backupActions.runRemoteBackup(hash, destinationId);
      queryClient.setQueryData(['admin-backup-settings', vaultCacheKey], result.settings);
      return result;
    },
    onListRemoteBackups: backupActions.listRemoteBackups,
    onDownloadRemoteBackup: async (masterPassword: string, destinationId: string, path: string, onProgress?: (percent: number | null) => void) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.downloadRemoteBackup(hash, destinationId, path, onProgress);
    },
    onInspectRemoteBackup: async (masterPassword: string, destinationId: string, path: string) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.inspectRemoteBackup(hash, destinationId, path);
    },
    onDeleteRemoteBackup: async (masterPassword: string, destinationId: string, path: string) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.deleteRemoteBackup(hash, destinationId, path);
    },
    onRestoreRemoteBackup: async (masterPassword: string, destinationId: string, path: string, replaceExisting?: boolean) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.restoreRemoteBackup(hash, destinationId, path, replaceExisting);
    },
    onRestoreRemoteBackupAllowingChecksumMismatch: async (masterPassword: string, destinationId: string, path: string, replaceExisting?: boolean) => {
      const hash = await deriveCurrentMasterPasswordHash(masterPassword);
      return backupActions.restoreRemoteBackupAllowingChecksumMismatch(hash, destinationId, path, replaceExisting);
    },
  };
  const effectiveMainRoutesProps = IS_DEMO_MODE
    ? createDemoMainRoutesProps(mainRoutesProps, pushToast, {
        ciphers: decryptedCiphers,
        folders: decryptedFolders,
        sends: decryptedSends,
        users: demoUsers,
        invites: demoInvites,
        authorizedDevices: demoAuthorizedDevices,
        backupSettings: demoBackupSettings,
        setCiphers: setDecryptedCiphers,
        setFolders: setDecryptedFolders,
        setSends: setDecryptedSends,
        setUsers: setDemoUsers,
        setInvites: setDemoInvites,
        setAuthorizedDevices: setDemoAuthorizedDevices,
        setBackupSettings: setDemoBackupSettings,
      })
    : mainRoutesProps;

  if (jwtWarning) {
    return <JwtWarningPage reason={jwtWarning.reason} minLength={jwtWarning.minLength} />;
  }

  if (publicSendMatch) {
    return (
      <>
        <PublicSendPage accessId={decodeURIComponent(publicSendMatch[1])} keyPart={publicSendMatch[2] ? decodeURIComponent(publicSendMatch[2]) : null} />
        {renderPassiveOverlays()}
      </>
    );
  }

  if (isUnknownRoute) {
    return (
      <>
        <NotFoundPage />
        {renderPassiveOverlays()}
      </>
    );
  }

  if (isRecoverTwoFactorRoute && phase !== 'app') {
    return (
      <>
        <RecoverTwoFactorPage
          values={recoverValues}
          onChange={setRecoverValues}
          onSubmit={() => void handleRecoverTwoFactorSubmit()}
          onCancel={() => {
            setRecoverValues({ email: '', password: '', recoveryCode: '' });
            navigate('/login');
          }}
        />
        {renderPassiveOverlays()}
      </>
    );
  }

  if (phase === 'register' || phase === 'login' || phase === 'locked') {
    return (
      <>
        <AuthViews
          mode={phase}
          pendingAction={pendingAuthAction}
          relaxedLoginInput={IS_DEMO_MODE}
          authPlaceholder={IS_DEMO_MODE ? t('txt_demo_auth_placeholder') : undefined}
          unlockPlaceholder={IS_DEMO_MODE ? t('txt_demo_unlock_placeholder') : undefined}
          unlockReady={!!session?.email}
          unlockPreparing={unlockPreparing}
          loginValues={loginValues}
          pendingPasskeyPasswordEmail={pendingPasskeyPassword?.email || null}
          passkeyPassword={passkeyPassword}
          registerValues={registerValues}
          registrationInviteRequired={registrationInviteRequired}
          unlockPassword={unlockPassword}
          emailForLock={profile?.email || session?.email || ''}
          loginHintLoading={loginHintState.loading}
          onChangeLogin={setLoginValues}
          onChangePasskeyPassword={setPasskeyPassword}
          onChangeRegister={setRegisterValues}
          onChangeUnlock={setUnlockPassword}
          onSubmitLogin={() => void handleLogin()}
          onSubmitPasskey={() => void handlePasskeyLogin()}
          onSubmitPasskeyUnlock={() => void handlePasskeyUnlock()}
          onSubmitPasskeyPassword={() => void handlePasskeyPasswordLogin()}
          onSubmitRegister={() => void handleRegister()}
          onSubmitUnlock={() => void handleUnlock()}
          onGotoLogin={() => {
            setPendingPasskeyPassword(null);
            setPasskeyPassword('');
            setPhase('login');
            navigate('/login');
          }}
          onGotoRegister={() => {
            if (IS_DEMO_MODE) {
              pushToast('warning', t('txt_demo_readonly_message'));
              return;
            }
            if (inviteCodeFromUrl) {
              setRegisterValues((prev) => ({ ...prev, inviteCode: inviteCodeFromUrl }));
            }
            setPendingPasskeyPassword(null);
            setPasskeyPassword('');
            setPhase('register');
            navigate('/register');
          }}
          onLogout={logoutNow}
          onTogglePasswordHint={() => void handleTogglePasswordHint()}
          onShowLockedPasswordHint={handleShowLockedPasswordHint}
        />
        <AppGlobalOverlays
          toasts={toasts}
          onCloseToast={removeToast}
          confirm={confirm}
          onCancelConfirm={() => setConfirm(null)}
          pendingTotpOpen={!!pendingTotp}
          pendingTotpProviderType={pendingTotp?.providerType ?? 0}
          pendingTotpAvailableProviders={pendingTotp?.availableProviders ?? []}
          totpCode={totpCode}
          rememberDevice={rememberDevice}
          onTotpCodeChange={setTotpCode}
          onRememberDeviceChange={setRememberDevice}
          onConfirmTotp={() => void handleTotpVerify()}
          onSelectTotpProvider={handleSelectTotpProvider}
          onCancelTotp={() => {
            if (totpSubmitting) return;
            setPendingTotp(null);
            setPendingTotpMode(null);
            setTotpCode('');
            setRememberDevice(true);
          }}
          onUseRecoveryCode={() => {
            if (totpSubmitting) return;
            setPendingTotp(null);
            setPendingTotpMode(null);
            setTotpCode('');
            setRememberDevice(true);
            navigate('/recover-2fa');
          }}
          totpSubmitting={totpSubmitting}
          disableTotpOpen={false}
          disableTotpPassword=""
          onDisableTotpPasswordChange={() => {}}
          onConfirmDisableTotp={() => {}}
          onCancelDisableTotp={() => {}}
          disableTotpSubmitting={false}
        />
      </>
    );
  }

  return (
    <>
      <AppAuthenticatedShell
        profile={profile}
        location={location}
        mobilePrimaryRoute={mobilePrimaryRoute}
        currentPageTitle={currentPageTitle}
        showSidebarToggle={showSidebarToggle}
        sidebarToggleTitle={sidebarToggleTitle}
        settingsAccountRoute={SETTINGS_ACCOUNT_ROUTE}
        importRoute={IMPORT_ROUTE}
        isImportRoute={isImportRoute}
        darkMode={resolvedTheme === 'dark'}
        themeToggleTitle={resolvedTheme === 'dark' ? t('txt_switch_to_light_mode') : t('txt_switch_to_dark_mode')}
        onLock={handleLock}
        onLogout={handleLogout}
        onToggleTheme={handleToggleTheme}
        onToggleMobileSidebar={() => setMobileSidebarToggleKey((key) => key + 1)}
        mainRoutesProps={effectiveMainRoutesProps}
      />

      <AppGlobalOverlays
        toasts={toasts}
        onCloseToast={removeToast}
        confirm={confirm}
        onCancelConfirm={() => setConfirm(null)}
        pendingTotpOpen={false}
        pendingTotpProviderType={0}
        pendingTotpAvailableProviders={[]}
        totpCode=""
        rememberDevice={false}
        onTotpCodeChange={() => {}}
        onRememberDeviceChange={() => {}}
        onConfirmTotp={() => {}}
        onSelectTotpProvider={() => {}}
        onCancelTotp={() => {}}
        onUseRecoveryCode={() => {}}
        totpSubmitting={false}
        disableTotpOpen={disableTotpOpen}
        disableTotpPassword={disableTotpPassword}
        onDisableTotpPasswordChange={setDisableTotpPassword}
        onConfirmDisableTotp={() => {
          if (disableTotpSubmitting) return;
          void (async () => {
            setDisableTotpSubmitting(true);
            try {
              await accountSecurityActions.disableTotp();
            } finally {
              setDisableTotpSubmitting(false);
            }
          })();
        }}
        onCancelDisableTotp={() => {
          if (disableTotpSubmitting) return;
          setDisableTotpOpen(false);
          setDisableTotpPassword('');
        }}
        disableTotpSubmitting={disableTotpSubmitting}
      />
      <AuthRequestApprovalDialog
        open={authRequestDialogOpen}
        authRequest={authRequestDialogRequest}
        submitting={!!authRequestSubmittingId}
        onApprove={() => {
          if (!authRequestDialogRequest) return;
          void approveAuthRequest(authRequestDialogRequest).catch((error) => {
            pushToast('error', error instanceof Error ? error.message : t('txt_auth_request_update_failed'));
          });
        }}
        onDeny={() => {
          if (!authRequestDialogRequest) return;
          void denyAuthRequest(authRequestDialogRequest).catch((error) => {
            pushToast('error', error instanceof Error ? error.message : t('txt_auth_request_update_failed'));
          });
        }}
        onClose={() => {
          setAuthRequestDialogSelectedId(null);
          setAuthRequestDialogDismissedId(authRequestDialogRequest?.id || null);
        }}
      />
    </>
  );
}
