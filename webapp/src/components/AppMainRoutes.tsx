import { lazy, Suspense } from 'preact/compat';
import { useEffect } from 'preact/hooks';
import { Link, Route, Switch } from 'wouter';
import { ArrowUpDown, Cloud, FileClock, Globe2, LogOut, Settings as SettingsIcon, Shield, ShieldUser } from 'lucide-preact';
import type { ImportAttachmentFile, ImportResultSummary } from '@/components/ImportPage';
import LoadingState from '@/components/LoadingState';
import type { AdminBackupImportResponse, AdminBackupRunResponse, AdminBackupSettings, RemoteBackupBrowserResponse } from '@/lib/api/backup';
import type { AuditLogFilters } from '@/lib/api/admin';
import type { CiphersImportPayload } from '@/lib/api/vault';
import { t } from '@/lib/i18n';
import type { AccountPasskeyCredential, AdminInvite, AdminUser, AuditLogListResult, AuditLogSettings, AuthRequest, AuthorizedDevice, Cipher, CustomEquivalentDomain, DomainRules, Folder as VaultFolder, Profile, Send, SendDraft, SessionState, TwoFactorPasskeySettings, VaultDraft, YubiKeyOtpSettings } from '@/lib/types';
import type { ExportRequest } from '@/lib/export-formats';

const VaultPage = lazy(() => import('@/components/VaultPage'));
const SendsPage = lazy(() => import('@/components/SendsPage'));
const TotpCodesPage = lazy(() => import('@/components/TotpCodesPage'));
const SettingsPage = lazy(() => import('@/components/SettingsPage'));
const DomainRulesPage = lazy(() => import('@/components/DomainRulesPage'));
const SecurityDevicesPage = lazy(() => import('@/components/SecurityDevicesPage'));
const AdminPage = lazy(() => import('@/components/AdminPage'));
const LogCenterPage = lazy(() => import('@/components/LogCenterPage'));
const BackupCenterPage = lazy(() => import('@/components/BackupCenterPage'));
const ImportPage = lazy(() => import('@/components/ImportPage'));

function RouteContentFallback() {
  return <LoadingState card lines={5} />;
}

function LegacyBackupRedirect(props: { onNavigate: (path: string) => void }) {
  useEffect(() => {
    props.onNavigate('/backup');
  }, [props]);
  return null;
}

export interface AppMainRoutesProps {
  profile: Profile | null;
  profileLoading: boolean;
  session: SessionState | null;
  mobileLayout: boolean;
  mobileSidebarToggleKey: number;
  themePreference: 'system' | 'light' | 'dark';
  importRoute: string;
  settingsHomeRoute: string;
  settingsAccountRoute: string;
  decryptedCiphers: Cipher[];
  decryptedFolders: VaultFolder[];
  decryptedSends: Send[];
  vaultError: string;
  ciphersLoading: boolean;
  foldersLoading: boolean;
  sendsLoading: boolean;
  users: AdminUser[];
  invites: AdminInvite[];
  adminLoading: boolean;
  adminError: string;
  totpEnabled: boolean;
  yubikeyEnabled: boolean;
  passkey2faEnabled: boolean;
  lockTimeoutMinutes: 0 | 1 | 5 | 15 | 30;
  sessionTimeoutAction: 'lock' | 'logout';
  authorizedDevices: AuthorizedDevice[];
  currentDeviceIdentifier: string;
  authorizedDevicesLoading: boolean;
  authorizedDevicesError: string;
  domainRules: DomainRules | null;
  domainRulesLoading: boolean;
  domainRulesError: string;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onThemePreferenceChange: (preference: 'system' | 'light' | 'dark') => void;
  onImport: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  onImportEncryptedRaw: (
    payload: CiphersImportPayload,
    options: { folderMode: 'original' | 'none' | 'target'; targetFolderId: string | null },
    attachments?: ImportAttachmentFile[]
  ) => Promise<ImportResultSummary>;
  onExport: (request: ExportRequest) => Promise<void>;
  onCreateVaultItem: (draft: VaultDraft, attachments?: File[]) => Promise<void>;
  onUpdateVaultItem: (cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) => Promise<void>;
  onDeleteVaultItem: (cipher: Cipher) => Promise<void>;
  onArchiveVaultItem: (cipher: Cipher) => Promise<void>;
  onUnarchiveVaultItem: (cipher: Cipher) => Promise<void>;
  onRestoreVaultItems: (ids: string[]) => Promise<void>;
  onBulkDeleteVaultItems: (ids: string[]) => Promise<void>;
  onBulkPermanentDeleteVaultItems: (ids: string[]) => Promise<void>;
  onBulkRestoreVaultItems: (ids: string[]) => Promise<void>;
  onBulkArchiveVaultItems: (ids: string[]) => Promise<void>;
  onBulkUnarchiveVaultItems: (ids: string[]) => Promise<void>;
  onBulkMoveVaultItems: (ids: string[], folderId: string | null) => Promise<void>;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onCreateFolder: (name: string) => Promise<void>;
  onRenameFolder: (folderId: string, name: string) => Promise<void>;
  onDeleteFolder: (folderId: string) => Promise<void>;
  onBulkDeleteFolders: (folderIds: string[]) => Promise<void>;
  onDownloadVaultAttachment: (cipher: Cipher, attachmentId: string) => Promise<void>;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
  onRefreshVault: () => Promise<void>;
  onCreateSend: (draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onUpdateSend: (send: Send, draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onDeleteSend: (send: Send) => Promise<void>;
  onBulkDeleteSends: (ids: string[]) => Promise<void>;
  uploadingSendFileName: string;
  sendUploadPercent: number | null;
  onChangePassword: (currentPassword: string, nextPassword: string, nextPassword2: string) => Promise<void>;
  onSavePasswordHint: (masterPasswordHint: string) => Promise<void>;
  onEnableTotp: (secret: string, token: string, masterPassword: string) => Promise<void>;
  onOpenDisableTotp: () => void;
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
  pendingAuthRequests: AuthRequest[];
  pendingAuthRequestsLoading: boolean;
  pendingAuthRequestsRefreshing: boolean;
  onRefreshPendingAuthRequests: () => Promise<void>;
  onApproveAuthRequest: (request: AuthRequest) => Promise<void>;
  onDenyAuthRequest: (request: AuthRequest) => Promise<void>;
  onLockTimeoutChange: (minutes: 0 | 1 | 5 | 15 | 30) => void;
  onSessionTimeoutActionChange: (action: 'lock' | 'logout') => void;
  onRefreshAuthorizedDevices: () => Promise<void>;
  onRefreshDomainRules: () => void;
  onSaveDomainRules: (customEquivalentDomains: CustomEquivalentDomain[], excludedGlobalEquivalentDomains: number[]) => Promise<void>;
  onRenameAuthorizedDevice: (device: AuthorizedDevice, name: string) => Promise<void>;
  onRevokeDeviceTrust: (device: AuthorizedDevice) => void;
  onTrustDevicePermanently: (device: AuthorizedDevice) => void;
  onRemoveDevice: (device: AuthorizedDevice) => void;
  onRemoveSelectedDevices: (devices: AuthorizedDevice[]) => void;
  onRevokeAllDeviceTrust: () => void;
  onRemoveAllDevices: () => void;
  onCreateInvite: (hours: number) => Promise<void>;
  onRefreshAdmin: () => void;
  onDeleteInvalidInvites: () => Promise<void>;
  onDeleteAllInvites: () => Promise<void>;
  onToggleUserStatus: (userId: string, status: 'active' | 'banned') => Promise<void>;
  onDeleteUser: (userId: string) => Promise<void>;
  onDeleteInvite: (code: string) => Promise<void>;
  onLoadAuditLogs: (filters: AuditLogFilters) => Promise<AuditLogListResult>;
  onLoadAuditLogSettings: () => Promise<AuditLogSettings>;
  onSaveAuditLogSettings: (settings: AuditLogSettings) => Promise<AuditLogSettings>;
  onClearAuditLogs: () => Promise<number>;
  onExportBackup: (masterPassword: string, includeAttachments?: boolean) => Promise<void>;
  onImportBackup: (masterPassword: string, file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onImportBackupAllowingChecksumMismatch: (masterPassword: string, file: File, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onLoadBackupSettings: () => Promise<AdminBackupSettings>;
  onSaveBackupSettings: (masterPassword: string, settings: AdminBackupSettings) => Promise<AdminBackupSettings>;
  onRunRemoteBackup: (masterPassword: string, destinationId?: string | null) => Promise<AdminBackupRunResponse>;
  onListRemoteBackups: (destinationId: string, path: string) => Promise<RemoteBackupBrowserResponse>;
  onDownloadRemoteBackup: (masterPassword: string, destinationId: string, path: string, onProgress?: (percent: number | null) => void) => Promise<void>;
  onInspectRemoteBackup: (masterPassword: string, destinationId: string, path: string) => Promise<{ object: 'backup-remote-integrity'; destinationId: string; path: string; fileName: string; integrity: { hasChecksumPrefix: boolean; expectedPrefix: string | null; actualPrefix: string; matches: boolean } }>;
  onDeleteRemoteBackup: (masterPassword: string, destinationId: string, path: string) => Promise<void>;
  onRestoreRemoteBackup: (masterPassword: string, destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
  onRestoreRemoteBackupAllowingChecksumMismatch: (masterPassword: string, destinationId: string, path: string, replaceExisting?: boolean) => Promise<AdminBackupImportResponse>;
}

export default function AppMainRoutes(props: AppMainRoutesProps) {
  const importRoutePaths = [props.importRoute, '/tools/import', '/tools/import-export', '/tools/import-data', '/import', '/import-export'] as const;
  const deviceManagementRoutePaths = ['/security/devices', '/settings/security/device-management'] as const;
  const isAdmin = String(props.profile?.role || '').toLowerCase() === 'admin';
  const importPageContent = (
    <Suspense fallback={<RouteContentFallback />}>
      <ImportPage
        onImport={props.onImport}
        onImportEncryptedRaw={props.onImportEncryptedRaw}
        accountKeys={props.session?.symEncKey && props.session?.symMacKey ? { encB64: props.session.symEncKey, macB64: props.session.symMacKey } : null}
        onNotify={props.onNotify}
        folders={props.decryptedFolders}
        onExport={props.onExport}
      />
    </Suspense>
  );

  const renderImportPageRoute = () => (
    <div className="stack">
      {props.mobileLayout && (
        <div className="mobile-settings-subhead">
          <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
            <span className="btn-icon" aria-hidden="true">{"<"}</span>
            {t('txt_back')}
          </button>
        </div>
      )}
      {importPageContent}
    </div>
  );

  return (
    <Switch>
      <Route path="/sends">
        <Suspense fallback={<RouteContentFallback />}>
          <SendsPage
            sends={props.decryptedSends}
            loading={props.sendsLoading}
            onRefresh={props.onRefreshVault}
            onCreate={props.onCreateSend}
            onUpdate={props.onUpdateSend}
            onDelete={props.onDeleteSend}
            onBulkDelete={props.onBulkDeleteSends}
            uploadingSendFileName={props.uploadingSendFileName}
            sendUploadPercent={props.sendUploadPercent}
            mobileSidebarToggleKey={props.mobileSidebarToggleKey}
            onNotify={props.onNotify}
          />
        </Suspense>
      </Route>
      <Route path="/vault/totp">
        <Suspense fallback={<RouteContentFallback />}>
          <TotpCodesPage ciphers={props.decryptedCiphers} loading={props.ciphersLoading} onNotify={props.onNotify} />
        </Suspense>
      </Route>
      <Route path="/vault">
        <Suspense fallback={<RouteContentFallback />}>
          <VaultPage
            ciphers={props.decryptedCiphers}
            folders={props.decryptedFolders}
            loading={props.ciphersLoading || props.foldersLoading}
            error={props.vaultError}
            emailForReprompt={props.profile?.email || props.session?.email || ''}
            onRefresh={props.onRefreshVault}
            onCreate={props.onCreateVaultItem}
            onUpdate={props.onUpdateVaultItem}
            onDelete={props.onDeleteVaultItem}
            onArchive={props.onArchiveVaultItem}
            onUnarchive={props.onUnarchiveVaultItem}
            onRestore={props.onRestoreVaultItems}
            onBulkDelete={props.onBulkDeleteVaultItems}
            onBulkPermanentDelete={props.onBulkPermanentDeleteVaultItems}
            onBulkRestore={props.onBulkRestoreVaultItems}
            onBulkArchive={props.onBulkArchiveVaultItems}
            onBulkUnarchive={props.onBulkUnarchiveVaultItems}
            onBulkMove={props.onBulkMoveVaultItems}
            onVerifyMasterPassword={props.onVerifyMasterPassword}
            onNotify={props.onNotify}
            onCreateFolder={props.onCreateFolder}
            onRenameFolder={props.onRenameFolder}
            onDeleteFolder={props.onDeleteFolder}
            onBulkDeleteFolders={props.onBulkDeleteFolders}
            onDownloadAttachment={props.onDownloadVaultAttachment}
            downloadingAttachmentKey={props.downloadingAttachmentKey}
            attachmentDownloadPercent={props.attachmentDownloadPercent}
            uploadingAttachmentName={props.uploadingAttachmentName}
            attachmentUploadPercent={props.attachmentUploadPercent}
            mobileSidebarToggleKey={props.mobileSidebarToggleKey}
          />
        </Suspense>
      </Route>
      <Route path={props.settingsAccountRoute}>
        {props.profile ? (
          <div className="stack">
            {props.mobileLayout && (
              <div className="mobile-settings-subhead">
                <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                  <span className="btn-icon" aria-hidden="true">{"<"}</span>
                  {t('txt_back')}
                </button>
              </div>
            )}
            <Suspense fallback={<RouteContentFallback />}>
              <SettingsPage
                profile={props.profile}
                totpEnabled={props.totpEnabled}
                yubikeyEnabled={props.yubikeyEnabled}
                passkey2faEnabled={props.passkey2faEnabled}
                themePreference={props.themePreference}
                lockTimeoutMinutes={props.lockTimeoutMinutes}
                sessionTimeoutAction={props.sessionTimeoutAction}
                onThemePreferenceChange={props.onThemePreferenceChange}
                onVerifyMasterPassword={props.onVerifyMasterPassword}
                onChangePassword={props.onChangePassword}
                onSavePasswordHint={props.onSavePasswordHint}
                onEnableTotp={props.onEnableTotp}
                onOpenDisableTotp={props.onOpenDisableTotp}
                onGetYubiKeySettings={props.onGetYubiKeySettings}
                onSaveYubiKeySettings={props.onSaveYubiKeySettings}
                onSaveYubiKeyApiCredentials={props.onSaveYubiKeyApiCredentials}
                onBootstrapYubiKeyApiCredentials={props.onBootstrapYubiKeyApiCredentials}
                onDisableYubiKey={props.onDisableYubiKey}
                onGetTwoFactorPasskeySettings={props.onGetTwoFactorPasskeySettings}
                onCreateTwoFactorPasskey={props.onCreateTwoFactorPasskey}
                onDeleteTwoFactorPasskey={props.onDeleteTwoFactorPasskey}
                onDisableTwoFactorPasskeys={props.onDisableTwoFactorPasskeys}
                onGetRecoveryCode={props.onGetRecoveryCode}
                onGetApiKey={props.onGetApiKey}
                onRotateApiKey={props.onRotateApiKey}
                onListAccountPasskeys={props.onListAccountPasskeys}
                onCreateAccountPasskey={props.onCreateAccountPasskey}
                onEnableAccountPasskeyDirectUnlock={props.onEnableAccountPasskeyDirectUnlock}
                onDeleteAccountPasskey={props.onDeleteAccountPasskey}
                onRefreshTwoFactorStatus={props.onRefreshTwoFactorStatus}
                onLockTimeoutChange={props.onLockTimeoutChange}
                onSessionTimeoutActionChange={props.onSessionTimeoutActionChange}
                onNotify={props.onNotify}
              />
            </Suspense>
          </div>
        ) : props.profileLoading ? (
          <LoadingState card lines={5} />
        ) : null}
      </Route>
      <Route path="/settings">
        {props.profile ? (
          <section className="card mobile-settings-card settings-home-card">
            <div className="settings-home-section">
              <h3>{t('txt_settings')}</h3>
              <div className="mobile-settings-links">
                <Link href={props.settingsAccountRoute} className="mobile-settings-link">
                  <SettingsIcon size={18} />
                  <span>{t('nav_account_settings')}</span>
                </Link>
                <Link href="/settings/security/device-management" className="mobile-settings-link">
                  <Shield size={18} />
                  <span>{t('nav_device_management')}</span>
                </Link>
                <Link href="/settings/domain-rules" className="mobile-settings-link">
                  <Globe2 size={18} />
                  <span>{t('nav_domain_rules')}</span>
                </Link>
              </div>
            </div>
            <div className="settings-home-section">
              <h3>{t('nav_group_data_backup')}</h3>
              <div className="mobile-settings-links">
                <Link href={props.importRoute} className="mobile-settings-link">
                  <ArrowUpDown size={18} />
                  <span>{t('nav_import_export')}</span>
                </Link>
                {isAdmin && (
                  <Link href="/backup" className="mobile-settings-link">
                    <Cloud size={18} />
                    <span>{t('nav_backup_strategy')}</span>
                  </Link>
                )}
              </div>
            </div>
            {isAdmin && (
              <div className="settings-home-section">
                <h3>{t('nav_group_management')}</h3>
                <div className="mobile-settings-links">
                  <Link href="/admin" className="mobile-settings-link">
                    <ShieldUser size={18} />
                    <span>{t('nav_admin_panel')}</span>
                  </Link>
                  <Link href="/logs" className="mobile-settings-link">
                    <FileClock size={18} />
                    <span>{t('nav_log_center')}</span>
                  </Link>
                </div>
              </div>
            )}
            <div className="settings-home-spacer" />
            <button type="button" className="btn btn-secondary mobile-settings-logout" onClick={props.onLogout}>
              <LogOut size={14} className="btn-icon" />
              {t('txt_sign_out')}
            </button>
          </section>
        ) : props.profileLoading ? (
          <LoadingState card lines={4} />
        ) : null}
      </Route>
      {deviceManagementRoutePaths.map((path) => (
        <Route key={path} path={path}>
          <div className="stack">
            {props.mobileLayout && (
              <div className="mobile-settings-subhead">
                <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                  <span className="btn-icon" aria-hidden="true">{"<"}</span>
                  {t('txt_back')}
                </button>
              </div>
            )}
            <Suspense fallback={<RouteContentFallback />}>
              <SecurityDevicesPage
                devices={props.authorizedDevices}
                currentDeviceIdentifier={props.currentDeviceIdentifier}
                loading={props.authorizedDevicesLoading}
                error={props.authorizedDevicesError}
                pendingAuthRequests={props.pendingAuthRequests}
                pendingAuthRequestsLoading={props.pendingAuthRequestsLoading}
                pendingAuthRequestsRefreshing={props.pendingAuthRequestsRefreshing}
                onRefresh={() => void props.onRefreshAuthorizedDevices()}
                onRefreshPendingAuthRequests={props.onRefreshPendingAuthRequests}
                onApproveAuthRequest={props.onApproveAuthRequest}
                onDenyAuthRequest={props.onDenyAuthRequest}
                onRenameDevice={props.onRenameAuthorizedDevice}
                onRevokeTrust={props.onRevokeDeviceTrust}
                onTrustPermanently={props.onTrustDevicePermanently}
                onRemoveDevice={props.onRemoveDevice}
                onRemoveSelectedDevices={props.onRemoveSelectedDevices}
                onRevokeAll={props.onRevokeAllDeviceTrust}
                onRemoveAll={props.onRemoveAllDevices}
              />
            </Suspense>
          </div>
        </Route>
      ))}
      <Route path="/settings/domain-rules">
        <div className="stack domain-rules-route">
          {props.mobileLayout && (
            <div className="mobile-settings-subhead">
              <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                <span className="btn-icon" aria-hidden="true">{"<"}</span>
                {t('txt_back')}
              </button>
            </div>
          )}
          <Suspense fallback={<RouteContentFallback />}>
            <DomainRulesPage
              rules={props.domainRules}
              loading={props.domainRulesLoading}
              error={props.domainRulesError}
              onRefresh={props.onRefreshDomainRules}
              onSave={props.onSaveDomainRules}
              onNotify={props.onNotify}
            />
          </Suspense>
        </div>
      </Route>
      <Route path="/admin">
        <div className="stack">
          {props.mobileLayout && (
            <div className="mobile-settings-subhead">
              <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                <span className="btn-icon" aria-hidden="true">{"<"}</span>
                {t('txt_back')}
              </button>
            </div>
          )}
          <Suspense fallback={<RouteContentFallback />}>
            <AdminPage
              currentUserId={props.profile?.id || ''}
              users={props.users}
              invites={props.invites}
              loading={props.adminLoading}
              error={props.adminError}
              onRefresh={props.onRefreshAdmin}
              onCreateInvite={props.onCreateInvite}
              onDeleteInvalidInvites={props.onDeleteInvalidInvites}
              onDeleteAllInvites={props.onDeleteAllInvites}
              onToggleUserStatus={props.onToggleUserStatus}
              onDeleteUser={props.onDeleteUser}
              onDeleteInvite={props.onDeleteInvite}
            />
          </Suspense>
        </div>
      </Route>
      <Route path="/logs">
        {isAdmin ? (
          <div className="stack">
            <Suspense fallback={<RouteContentFallback />}>
              <LogCenterPage
                onLoadLogs={props.onLoadAuditLogs}
                onLoadSettings={props.onLoadAuditLogSettings}
                onSaveSettings={props.onSaveAuditLogSettings}
                onClearLogs={props.onClearAuditLogs}
                onNotify={props.onNotify}
                mobileLayout={props.mobileLayout}
                onMobileBack={() => props.onNavigate(props.settingsHomeRoute)}
              />
            </Suspense>
          </div>
        ) : null}
      </Route>
      {importRoutePaths.map((path) => (
        <Route key={path} path={path}>
          {renderImportPageRoute()}
        </Route>
      ))}
      <Route path="/help">
        <LegacyBackupRedirect onNavigate={props.onNavigate} />
      </Route>
      <Route path="/backup">
        {isAdmin ? (
          <div className="stack">
            {props.mobileLayout && (
              <div className="mobile-settings-subhead">
                <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={() => props.onNavigate(props.settingsHomeRoute)}>
                  <span className="btn-icon" aria-hidden="true">{"<"}</span>
                  {t('txt_back')}
                </button>
              </div>
            )}
            <Suspense fallback={<RouteContentFallback />}>
              <BackupCenterPage
                currentUserId={props.profile?.id || null}
                onExport={props.onExportBackup}
                onImport={props.onImportBackup}
                onImportAllowingChecksumMismatch={props.onImportBackupAllowingChecksumMismatch}
                onLoadSettings={props.onLoadBackupSettings}
                onListRemoteBackups={props.onListRemoteBackups}
                onDownloadRemoteBackup={props.onDownloadRemoteBackup}
                onInspectRemoteBackup={props.onInspectRemoteBackup}
                onDeleteRemoteBackup={props.onDeleteRemoteBackup}
                onRestoreRemoteBackup={props.onRestoreRemoteBackup}
                onRestoreRemoteBackupAllowingChecksumMismatch={props.onRestoreRemoteBackupAllowingChecksumMismatch}
                onSaveSettings={props.onSaveBackupSettings}
                onRunRemoteBackup={props.onRunRemoteBackup}
                onNotify={props.onNotify}
              />
            </Suspense>
          </div>
        ) : null}
      </Route>
    </Switch>
  );
}
