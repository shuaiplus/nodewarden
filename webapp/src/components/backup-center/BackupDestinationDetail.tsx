import { CloudUpload, Save, Trash2 } from 'lucide-preact';
import type {
  BackupDestinationRecord,
  RemoteBackupBrowserResponse,
  S3BackupAddressingStyle,
  S3BackupDestination,
  WebDavBackupDestination,
} from '@/lib/api/backup';
import { COMMON_TIME_ZONES, getDestinationTypeLabel } from '@/lib/backup-center';
import type { RecommendedProvider } from '@/lib/backup-recommendations';
import { RemoteBackupBrowser } from './RemoteBackupBrowser';
import { t } from '@/lib/i18n';
import { BackupIncludeAttachmentsField } from './BackupIncludeAttachmentsField';

const INTERVAL_HOUR_PRESETS = [1, 6, 12, 24];

interface BackupDestinationDetailProps {
  selectedRecommendedProvider: RecommendedProvider | null;
  selectedDestination: BackupDestinationRecord | null;
  selectedDestinationIsSaved: boolean;
  canRunSelectedDestination: boolean;
  canBrowseSelectedDestination: boolean;
  disableWhileBusy: boolean;
  loadingSettings: boolean;
  savingSettings: boolean;
  runningRemoteBackup: boolean;
  availableTimeZones: string[];
  remoteBrowser: RemoteBackupBrowserResponse | null;
  remoteBrowserVisibleItems: RemoteBackupBrowserResponse['items'];
  remoteBrowserCurrentPage: number;
  remoteBrowserTotalPages: number;
  loadingRemoteBrowser: boolean;
  downloadingRemotePath: string;
  downloadingRemotePercent: number | null;
  restoringRemotePath: string;
  deletingRemotePath: string;
  onSaveSettings: () => void;
  onToggleSchedule: () => void;
  onRunRemoteBackup: () => void;
  onPromptDeleteDestination: () => void;
  onUpdateDestination: (mutator: (destination: BackupDestinationRecord) => BackupDestinationRecord) => void;
  onRefreshRemoteBrowser: () => void;
  onShowRemoteBrowserPath: (path: string) => void;
  onDownloadRemoteBackup: (path: string) => void;
  onRestoreRemoteBackup: (path: string) => void;
  onPromptDeleteRemoteBackup: (path: string) => void;
  onChangeRemoteBrowserPage: (page: number) => void;
}

function renderRecommendedProviderDetails(provider: RecommendedProvider) {
  switch (provider.id) {
    case 'koofr':
      return (
        <>
          <div className="backup-recommendation-steps">
            <div className="backup-recommendation-step">
              <strong>1.</strong> {t('txt_backup_recommend_koofr_step_2_prefix')}{' '}
              <a href={provider.passwordUrl} target="_blank" rel="noreferrer">{t('txt_backup_recommend_koofr_password_link')}</a>
              {t('txt_backup_recommend_koofr_step_2_suffix')}
            </div>
            <div className="backup-recommendation-step">
              <strong>2.</strong> {t('txt_backup_recommend_koofr_step_3')}
            </div>
            <div className="backup-recommendation-step">
              <strong>3.</strong> {t('txt_backup_recommend_koofr_step_4')}
            </div>
            <div className="backup-recommendation-step">
              <strong>4.</strong> {t('txt_backup_recommend_koofr_step_5_prefix')}{' '}
              <a href={provider.storageUrl} target="_blank" rel="noreferrer">{t('txt_backup_recommend_koofr_storage_link')}</a>
              {t('txt_backup_recommend_koofr_step_5_suffix')}
            </div>
          </div>
          <div className="backup-recommendation-inline-note">{t('txt_backup_recommend_koofr_dav_intro')}</div>
          <div className="backup-recommendation-dav-list">
            <div className="backup-recommendation-dav-item">
              <strong>{t('txt_backup_recommend_koofr_dav_self')}</strong>
              <code>https://app.koofr.net/dav/Koofr</code>
            </div>
            <div className="backup-recommendation-dav-item">
              <strong>Google Drive</strong>
              <code>https://app.koofr.net/dav/Google Drive</code>
            </div>
            <div className="backup-recommendation-dav-item">
              <strong>OneDrive</strong>
              <code>https://app.koofr.net/dav/OneDrive</code>
            </div>
            <div className="backup-recommendation-dav-item">
              <strong>Dropbox</strong>
              <code>https://app.koofr.net/dav/Dropbox</code>
            </div>
          </div>
        </>
      );
    case 'pcloud':
      return (
        <div className="backup-recommendation-steps">
          <div className="backup-recommendation-step">
            <strong>1.</strong> {t('txt_backup_recommend_pcloud_step_2')}
          </div>
          <div className="backup-recommendation-step">
            <strong>2.</strong> {t('txt_backup_recommend_pcloud_step_3')}
          </div>
        </div>
      );
    case 'infinicloud':
      return (
        <div className="backup-recommendation-steps">
          <div className="backup-recommendation-step">
            <strong>1.</strong> {t('txt_backup_recommend_infinicloud_step_2_prefix')}{' '}
            <a href="https://infini-cloud.net/en/modules/mypage/usage/" target="_blank" rel="noreferrer">My Page</a>
            {t('txt_backup_recommend_infinicloud_step_2_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>2.</strong> {t('txt_backup_recommend_infinicloud_step_3')}
          </div>
          <div className="backup-recommendation-step">
            <strong>3.</strong> {t('txt_backup_recommend_infinicloud_step_4')}
          </div>
        </div>
      );
    case 'backblaze-b2':
      return (
        <div className="backup-recommendation-steps">
          <div className="backup-recommendation-step">
            <strong>1.</strong> {t('txt_backup_recommend_backblaze_step_2_prefix')}{' '}
            <a href={provider.bucketsUrl} target="_blank" rel="noreferrer">Buckets</a>
            {t('txt_backup_recommend_backblaze_step_2_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>2.</strong> {t('txt_backup_recommend_backblaze_step_3')}
          </div>
          <div className="backup-recommendation-step">
            <strong>3.</strong> {t('txt_backup_recommend_backblaze_step_4_prefix')}{' '}
            <a href={provider.applicationKeysUrl} target="_blank" rel="noreferrer">Application Keys</a>
            {t('txt_backup_recommend_backblaze_step_4_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>4.</strong> {t('txt_backup_recommend_backblaze_step_5')}
          </div>
          <div className="backup-recommendation-step">
            <strong>5.</strong> {t('txt_backup_recommend_s3_path_prefix_step')}
          </div>
        </div>
      );
    case 'cloudflare-r2':
      return (
        <div className="backup-recommendation-steps">
          <div className="backup-recommendation-step">
            <strong>1.</strong> {t('txt_backup_recommend_cloudflare_r2_step_1_prefix')}{' '}
            <a href={provider.bucketUrl} target="_blank" rel="noreferrer">{t('txt_backup_recommend_cloudflare_r2_bucket_link')}</a>
            {t('txt_backup_recommend_cloudflare_r2_step_1_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>2.</strong> {t('txt_backup_recommend_cloudflare_r2_step_2_prefix')}{' '}
            <a href={provider.apiTokenUrl} target="_blank" rel="noreferrer">{t('txt_backup_recommend_cloudflare_r2_api_link')}</a>
            {t('txt_backup_recommend_cloudflare_r2_step_2_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>3.</strong> {t('txt_backup_recommend_cloudflare_r2_step_3')}
          </div>
          <div className="backup-recommendation-step">
            <strong>4.</strong> {t('txt_backup_recommend_cloudflare_r2_step_4')}
          </div>
          <div className="backup-recommendation-step">
            <strong>5.</strong> {t('txt_backup_recommend_cloudflare_r2_step_5')}
          </div>
        </div>
      );
    case 'tigris':
      return (
        <div className="backup-recommendation-steps">
          <div className="backup-recommendation-step">
            <strong>1.</strong> {t('txt_backup_recommend_tigris_step_2_prefix')}{' '}
            <a href={provider.bucketUrl} target="_blank" rel="noreferrer">Create Bucket</a>
            {t('txt_backup_recommend_tigris_step_2_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>2.</strong> {t('txt_backup_recommend_tigris_step_3_prefix')}{' '}
            <a href={provider.accessKeyUrl} target="_blank" rel="noreferrer">{t('txt_backup_recommend_tigris_access_key_link')}</a>
            {t('txt_backup_recommend_tigris_step_3_suffix')}
          </div>
          <div className="backup-recommendation-step">
            <strong>3.</strong> {t('txt_backup_recommend_tigris_step_4')}
          </div>
          <div className="backup-recommendation-step">
            <strong>4.</strong> {t('txt_backup_recommend_tigris_step_5')}
          </div>
          <div className="backup-recommendation-step">
            <strong>5.</strong> {t('txt_backup_recommend_s3_path_prefix_step')}
          </div>
        </div>
      );
  }
}

export function BackupDestinationDetail(props: BackupDestinationDetailProps) {
  const timeZones = Array.from(new Set([
    ...COMMON_TIME_ZONES,
    ...props.availableTimeZones,
  ]));
  const selectedIntervalHours = props.selectedDestination?.schedule.intervalHours ?? 24;

  if (props.selectedRecommendedProvider) {
    return (
      <section className="backup-detail-panel">
        <div className="backup-recommendation-card">
          <div className="backup-recommendation-header">
            <div>
              <strong>{props.selectedRecommendedProvider.name}</strong>
              <div className="backup-inline-note">
                {props.selectedRecommendedProvider.id === 'infinicloud' ? t('txt_backup_recommend_infinicloud_summary')
                  : props.selectedRecommendedProvider.id === 'koofr' ? t('txt_backup_recommend_koofr_summary')
                    : props.selectedRecommendedProvider.id === 'backblaze-b2' ? t('txt_backup_recommend_backblaze_summary')
                      : props.selectedRecommendedProvider.id === 'cloudflare-r2' ? t('txt_backup_recommend_cloudflare_r2_summary')
                        : props.selectedRecommendedProvider.id === 'tigris' ? t('txt_backup_recommend_tigris_summary')
                    : t('txt_backup_recommend_pcloud_summary')}
              </div>
            </div>
            <span className="backup-destination-type">{props.selectedRecommendedProvider.capacity}</span>
          </div>
          <div className="backup-recommendation-actions">
            <a className="btn btn-primary small" href={props.selectedRecommendedProvider.signupUrl} target="_blank" rel="noreferrer">
              {props.selectedRecommendedProvider.hasAffiliateLink ? t('txt_backup_recommend_open_signup_aff') : t('txt_backup_recommend_open_signup')}
            </a>
          </div>
          {renderRecommendedProviderDetails(props.selectedRecommendedProvider)}
        </div>
      </section>
    );
  }

  return (
    <section className="backup-detail-panel">
      <div className="section-head">
        <h3>{t('txt_backup_destination_detail_title')}</h3>
        {props.selectedDestination ? (
          <div className="actions">
            <button type="button" className="btn btn-primary small" disabled={props.loadingSettings || props.disableWhileBusy} onClick={props.onSaveSettings}>
              <Save size={14} className="btn-icon" />
              {props.savingSettings ? t('txt_backup_saving') : t('txt_backup_save_settings')}
            </button>
            <button type="button" className="btn btn-secondary small" disabled={props.loadingSettings || props.disableWhileBusy} onClick={props.onToggleSchedule}>
              {props.selectedDestination.schedule.enabled ? t('txt_backup_disable_action') : t('txt_backup_enable_action')}
            </button>
            <button type="button" className="btn btn-secondary small" disabled={props.disableWhileBusy || !props.canRunSelectedDestination} onClick={props.onRunRemoteBackup}>
              <CloudUpload size={14} className="btn-icon" />
              {props.runningRemoteBackup ? t('txt_backup_running_now') : t('txt_backup_run_manual')}
            </button>
            <button type="button" className="btn btn-danger small" disabled={props.loadingSettings || props.disableWhileBusy} onClick={props.onPromptDeleteDestination}>
              <Trash2 size={14} className="btn-icon" />
              {t('txt_backup_delete_destination')}
            </button>
          </div>
        ) : null}
      </div>

      {!props.selectedDestination ? (
        <div className="backup-browser-empty">{t('txt_backup_select_destination')}</div>
      ) : (
        <>
          <div className="backup-name-row">
            <label className="field backup-name-field">
              <span>{t('txt_backup_destination_name')}</span>
              <input
                className="input"
                value={props.selectedDestination.name}
                disabled={props.loadingSettings || props.disableWhileBusy}
                onInput={(event) => props.onUpdateDestination((destination) => ({ ...destination, name: (event.currentTarget as HTMLInputElement).value }))}
              />
            </label>
            <label className="field backup-type-field">
              <span>{t('txt_backup_type')}</span>
              <input className="input" value={getDestinationTypeLabel(props.selectedDestination.type)} disabled />
            </label>
          </div>

          <div className="field-grid backup-detail-schedule-grid">
            <label className="field">
              <span>{t('txt_backup_interval_hours')}</span>
              <div className="backup-interval-row">
                <div className="backup-inline-suffix-wrap">
                  <input
                    className="input backup-inline-suffix-input"
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    value={String(selectedIntervalHours)}
                    disabled={props.loadingSettings || props.disableWhileBusy}
                    onInput={(event) => {
                      const raw = (event.currentTarget as HTMLInputElement).value.replace(/[^\d]/g, '');
                      const value = Math.min(99, Math.max(1, Number(raw || 1)));
                      props.onUpdateDestination((destination) => ({
                        ...destination,
                        schedule: {
                          ...destination.schedule,
                          intervalHours: value,
                        },
                      }));
                    }}
                  />
                  <span className="backup-inline-suffix">{t('txt_backup_interval_hours_suffix')}</span>
                </div>
                <div className="backup-interval-presets" aria-label={t('txt_backup_interval_hours_presets')}>
                  {INTERVAL_HOUR_PRESETS.map((preset) => {
                    const active = preset === selectedIntervalHours;
                    return (
                      <button
                        key={preset}
                        type="button"
                        className={`backup-interval-preset${active ? ' active' : ''}`}
                        disabled={props.loadingSettings || props.disableWhileBusy}
                        onClick={() => props.onUpdateDestination((destination) => ({
                          ...destination,
                          schedule: {
                            ...destination.schedule,
                            intervalHours: preset,
                          },
                        }))}
                      >
                        {preset}
                      </button>
                    );
                  })}
                </div>
              </div>
            </label>
            <label className="field">
              <span>{t('txt_backup_start_time')}</span>
              <input
                className="input"
                type="time"
                step={300}
                value={props.selectedDestination.schedule.startTime || '03:00'}
                disabled={props.loadingSettings || props.disableWhileBusy}
                onInput={(event) => props.onUpdateDestination((destination) => ({
                  ...destination,
                  schedule: {
                    ...destination.schedule,
                    startTime: (event.currentTarget as HTMLInputElement).value || '03:00',
                  },
                }))}
              />
            </label>
            <label className="field">
              <span>{t('txt_backup_timezone')}</span>
              <select
                className="input"
                value={props.selectedDestination.schedule.timezone}
                disabled={props.loadingSettings || props.disableWhileBusy}
                onChange={(event) => props.onUpdateDestination((destination) => ({
                  ...destination,
                  schedule: {
                    ...destination.schedule,
                    timezone: (event.currentTarget as HTMLSelectElement).value,
                  },
                }))}
              >
                {timeZones.map((timezone) => (
                  <option key={timezone} value={timezone}>{timezone}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>{t('txt_backup_retention_count')}</span>
              <div className="backup-inline-suffix-wrap">
                <input
                  className="input backup-inline-suffix-input"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={props.selectedDestination.schedule.retentionCount === null ? '' : String(props.selectedDestination.schedule.retentionCount)}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder="30"
                  onInput={(event) => {
                    const nextValue = (event.currentTarget as HTMLInputElement).value.replace(/[^\d]/g, '').trim();
                    props.onUpdateDestination((destination) => ({
                      ...destination,
                      schedule: {
                        ...destination.schedule,
                        retentionCount: nextValue ? Number(nextValue) : null,
                      },
                    }));
                  }}
                />
                <span className="backup-inline-suffix">{t('txt_backup_retention_count_suffix')}</span>
              </div>
            </label>
          </div>

          <div className="backup-schedule-attachments-row">
            <BackupIncludeAttachmentsField
              checked={props.selectedDestination.includeAttachments}
              disabled={props.loadingSettings || props.disableWhileBusy}
              onChange={(checked) => props.onUpdateDestination((destination) => ({
                ...destination,
                includeAttachments: checked,
              }))}
            />
          </div>

          {props.selectedDestination.type === 'webdav' ? (
            <div className="field-grid">
              <label className="field field-span-2">
                <span>{t('txt_backup_webdav_url')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as WebDavBackupDestination).baseUrl}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder="https://dav.example.com/remote.php/dav/files/admin"
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as WebDavBackupDestination),
                      baseUrl: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_webdav_username')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as WebDavBackupDestination).username}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as WebDavBackupDestination),
                      username: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_webdav_password')}</span>
                <input
                  className="input"
                  type="password"
                  value={(props.selectedDestination.destination as WebDavBackupDestination).password}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as WebDavBackupDestination),
                      password: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field field-span-2">
                <span>{t('txt_backup_webdav_path')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as WebDavBackupDestination).remotePath}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder="nodewarden"
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as WebDavBackupDestination),
                      remotePath: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
            </div>
          ) : null}

          {props.selectedDestination.type === 's3' ? (
            <div className="field-grid">
              <label className="field">
                <span>{t('txt_backup_s3_endpoint')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).endpoint}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder="https://s3.example.com"
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      endpoint: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_s3_addressing_style')}</span>
                <select
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).addressingStyle || 'path-style'}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onChange={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      addressingStyle: (event.currentTarget as HTMLSelectElement).value as S3BackupAddressingStyle,
                    },
                  }))}
                >
                  <option value="path-style">{t('txt_backup_s3_addressing_path_style')}</option>
                  <option value="virtual-hosted-style">{t('txt_backup_s3_addressing_virtual_hosted_style')}</option>
                </select>
              </label>
              <label className="field">
                <span>{t('txt_backup_s3_bucket')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).bucket}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      bucket: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_s3_region')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).region}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder="auto"
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      region: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_s3_access_key')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).accessKeyId}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      accessKeyId: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field">
                <span>{t('txt_backup_s3_secret_key')}</span>
                <input
                  className="input"
                  type="password"
                  value={(props.selectedDestination.destination as S3BackupDestination).secretAccessKey}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      secretAccessKey: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
              <label className="field field-span-2">
                <span>{t('txt_backup_s3_path')}</span>
                <input
                  className="input"
                  value={(props.selectedDestination.destination as S3BackupDestination).rootPath}
                  disabled={props.loadingSettings || props.disableWhileBusy}
                  placeholder=""
                  onInput={(event) => props.onUpdateDestination((destination) => ({
                    ...destination,
                    destination: {
                      ...(destination.destination as S3BackupDestination),
                      rootPath: (event.currentTarget as HTMLInputElement).value,
                    },
                  }))}
                />
              </label>
            </div>
          ) : null}

          <RemoteBackupBrowser
            canBrowse={props.canBrowseSelectedDestination}
            destinationIsSaved={props.selectedDestinationIsSaved}
            disableWhileBusy={props.disableWhileBusy}
            loadingRemoteBrowser={props.loadingRemoteBrowser}
            remoteBrowser={props.remoteBrowser}
            visibleItems={props.remoteBrowserVisibleItems}
            currentPage={props.remoteBrowserCurrentPage}
            totalPages={props.remoteBrowserTotalPages}
            downloadingRemotePath={props.downloadingRemotePath}
            downloadingRemotePercent={props.downloadingRemotePercent}
            restoringRemotePath={props.restoringRemotePath}
            deletingRemotePath={props.deletingRemotePath}
            onRefresh={props.onRefreshRemoteBrowser}
            onShowPath={props.onShowRemoteBrowserPath}
            onDownload={props.onDownloadRemoteBackup}
            onRestore={props.onRestoreRemoteBackup}
            onPromptDelete={props.onPromptDeleteRemoteBackup}
            onChangePage={props.onChangeRemoteBrowserPage}
          />
        </>
      )}
    </section>
  );
}
