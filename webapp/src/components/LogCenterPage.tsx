import { useCallback, useEffect, useMemo, useState } from 'preact/hooks';
import { ChevronLeft, ChevronRight, Database, RefreshCw, Save, Search, Server, Settings2, ShieldAlert, Smartphone, Trash2, UserRound } from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import type { AuditLogFilters } from '@/lib/api/admin';
import { t } from '@/lib/i18n';
import type { AuditLogCategory, AuditLogEntry, AuditLogLevel, AuditLogListResult, AuditLogSettings } from '@/lib/types';

interface LogCenterPageProps {
  onLoadLogs: (filters: AuditLogFilters) => Promise<AuditLogListResult>;
  onLoadSettings: () => Promise<AuditLogSettings>;
  onSaveSettings: (settings: AuditLogSettings) => Promise<AuditLogSettings>;
  onClearLogs: () => Promise<number>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  mobileLayout?: boolean;
  onMobileBack?: () => void;
}

type TimeRange = '24h' | '7d' | '30d' | 'all';
type FilterCategory = AuditLogCategory | 'all';
type FilterLevel = AuditLogLevel | 'all';
type RetentionMode = 'days' | 'entries';

const PAGE_SIZE = 50;
const CATEGORY_OPTIONS: Array<{ value: FilterCategory; labelKey: string }> = [
  { value: 'all', labelKey: 'txt_all_logs' },
  { value: 'auth', labelKey: 'txt_log_category_auth' },
  { value: 'security', labelKey: 'txt_log_category_security' },
  { value: 'device', labelKey: 'txt_log_category_device' },
  { value: 'data', labelKey: 'txt_log_category_data' },
  { value: 'system', labelKey: 'txt_log_category_system' },
];
const LEVEL_OPTIONS: Array<{ value: FilterLevel; labelKey: string }> = [
  { value: 'all', labelKey: 'txt_all_levels' },
  { value: 'info', labelKey: 'txt_log_level_info' },
  { value: 'warn', labelKey: 'txt_log_level_warn' },
  { value: 'error', labelKey: 'txt_log_level_error' },
  { value: 'security', labelKey: 'txt_log_level_security' },
];
const RANGE_OPTIONS: Array<{ value: TimeRange; labelKey: string }> = [
  { value: '24h', labelKey: 'txt_last_24_hours' },
  { value: '7d', labelKey: 'txt_last_7_days' },
  { value: '30d', labelKey: 'txt_last_30_days' },
  { value: 'all', labelKey: 'txt_all_time' },
];
const RETENTION_OPTIONS: Array<{ value: string; labelKey: string }> = [
  { value: '7', labelKey: 'txt_log_retention_7d' },
  { value: '30', labelKey: 'txt_log_retention_30d' },
  { value: '90', labelKey: 'txt_log_retention_90d' },
  { value: '180', labelKey: 'txt_log_retention_180d' },
  { value: '365', labelKey: 'txt_log_retention_365d' },
  { value: '0', labelKey: 'txt_log_retention_forever' },
];
const MAX_ENTRY_OPTIONS: Array<{ value: string; labelKey: string }> = [
  { value: '1000', labelKey: 'txt_log_max_1000' },
  { value: '5000', labelKey: 'txt_log_max_5000' },
  { value: '10000', labelKey: 'txt_log_max_10000' },
  { value: '50000', labelKey: 'txt_log_max_50000' },
  { value: '0', labelKey: 'txt_log_max_unlimited' },
];

function parseMetadata(log: AuditLogEntry): Record<string, unknown> {
  if (!log.metadata) return {};
  try {
    const parsed = JSON.parse(log.metadata);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : {};
  } catch {
    return { raw: log.metadata };
  }
}

function inferCategory(log: AuditLogEntry, metadata: Record<string, unknown>): AuditLogCategory {
  if (log.category === 'auth' || log.category === 'security' || log.category === 'device' || log.category === 'data' || log.category === 'system') {
    return log.category;
  }
  const category = metadata.category;
  if (category === 'auth' || category === 'security' || category === 'device' || category === 'data' || category === 'system') {
    return category;
  }
  if (log.action.startsWith('auth.')) return 'auth';
  if (log.action.startsWith('device.')) return 'device';
  if (log.action.startsWith('admin.backup.')) return 'data';
  if (log.action.startsWith('account.') || log.action.startsWith('user.password.') || log.action.startsWith('user.register.') || log.action.startsWith('admin.user.')) return 'security';
  return 'system';
}

function inferLevel(log: AuditLogEntry, metadata: Record<string, unknown>): AuditLogLevel {
  if (log.level === 'info' || log.level === 'warn' || log.level === 'error' || log.level === 'security') {
    return log.level;
  }
  const level = metadata.level;
  if (level === 'info' || level === 'warn' || level === 'error' || level === 'security') return level;
  if (log.action.includes('.failed') || log.action.includes('.error')) return 'error';
  if (log.action.includes('password') || log.action.includes('totp') || log.action.includes('delete') || log.action.includes('ban')) return 'security';
  return 'info';
}

function humanizeIdentifier(value: string): string {
  return value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split('.')
    .flatMap((part) => part.split('_'))
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' / ');
}

function keyFor(prefix: string, value: string): string {
  return `${prefix}${value.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[^A-Za-z0-9]+/g, '_').toLowerCase()}`;
}

function translatedOrHumanized(key: string, fallback: string): string {
  const translated = t(key);
  return translated === key ? humanizeIdentifier(fallback) : translated;
}

function formatAction(action: string): string {
  if (action.startsWith('auth.refresh.failed.')) {
    const reason = formatReason(action.slice('auth.refresh.failed.'.length));
    return t('txt_log_action_auth_refresh_failed', { reason });
  }
  return translatedOrHumanized(keyFor('txt_log_action_', action), action);
}

function formatMetaKey(key: string): string {
  return translatedOrHumanized(keyFor('txt_log_meta_', key), key);
}

function formatReason(reason: string): string {
  return translatedOrHumanized(keyFor('txt_log_reason_', reason), reason);
}

function formatTargetType(type: string): string {
  return translatedOrHumanized(keyFor('txt_log_target_type_', type), type);
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function formatMetaValue(value: unknown): string {
  if (value === null || value === undefined || value === '') return t('txt_dash');
  if (typeof value === 'boolean') return value ? t('txt_yes') : t('txt_no');
  if (typeof value === 'string') return value;
  if (typeof value === 'number') return String(value);
  return JSON.stringify(value);
}

function formatMetaValueForKey(key: string, value: unknown): string {
  if (key === 'reason' && typeof value === 'string') return formatReason(value);
  if (key === 'trigger' && typeof value === 'string') {
    return translatedOrHumanized(keyFor('txt_log_trigger_', value), value);
  }
  if (key === 'type' && typeof value === 'string') {
    return formatTargetType(value);
  }
  return formatMetaValue(value);
}

function formatLogTarget(log: AuditLogEntry, metadata: Record<string, unknown>): string {
  const targetEmail = typeof metadata.targetEmail === 'string' ? metadata.targetEmail : '';
  return log.targetUserEmail || targetEmail || log.targetId || (log.targetType ? formatTargetType(log.targetType) : t('txt_dash'));
}

function iconForCategory(category: AuditLogCategory) {
  if (category === 'auth') return <ShieldAlert size={16} />;
  if (category === 'security') return <UserRound size={16} />;
  if (category === 'device') return <Smartphone size={16} />;
  if (category === 'data') return <Database size={16} />;
  return <Server size={16} />;
}

function buildRange(range: TimeRange): { from?: string; to?: string } {
  if (range === 'all') return {};
  const now = Date.now();
  const hours = range === '24h' ? 24 : range === '7d' ? 24 * 7 : 24 * 30;
  return {
    from: new Date(now - hours * 60 * 60 * 1000).toISOString(),
    to: new Date(now).toISOString(),
  };
}

function inferRetentionMode(settings: AuditLogSettings): RetentionMode {
  return settings.retentionDays === null && settings.maxEntries !== null ? 'entries' : 'days';
}

export default function LogCenterPage(props: LogCenterPageProps) {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [hasMore, setHasMore] = useState(false);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<FilterCategory>('all');
  const [level, setLevel] = useState<FilterLevel>('all');
  const [range, setRange] = useState<TimeRange>('7d');
  const [loading, setLoading] = useState(false);
  const [settingsLoading, setSettingsLoading] = useState(false);
  const [settingsSaving, setSettingsSaving] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [clearConfirmOpen, setClearConfirmOpen] = useState(false);
  const [retentionMode, setRetentionMode] = useState<RetentionMode>('days');
  const [settings, setSettings] = useState<AuditLogSettings>({ retentionDays: 90, maxEntries: null });
  const [error, setError] = useState('');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [mobileDetailOpen, setMobileDetailOpen] = useState(false);

  const selectedLog = useMemo(() => logs.find((log) => log.id === selectedId) || logs[0] || null, [logs, selectedId]);
  const selectedMetadata = useMemo(() => selectedLog ? parseMetadata(selectedLog) : {}, [selectedLog]);
  const selectedCategory = selectedLog ? inferCategory(selectedLog, selectedMetadata) : 'system';
  const selectedLevel = selectedLog ? inferLevel(selectedLog, selectedMetadata) : 'info';
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  const load = useCallback(async (nextOffset = offset) => {
    setLoading(true);
    setError('');
    try {
      const rangeFilter = buildRange(range);
      const result = await props.onLoadLogs({
        limit: PAGE_SIZE,
        offset: nextOffset,
        category,
        level,
        q: search,
        ...rangeFilter,
      });
      setLogs(result.logs);
      setTotal(result.total);
      setHasMore(result.hasMore);
      setOffset(result.offset);
      setSelectedId((current) => current && result.logs.some((log) => log.id === current) ? current : result.logs[0]?.id || null);
      setMobileDetailOpen(false);
    } catch {
      setError(t('txt_load_logs_failed'));
      props.onNotify('error', t('txt_load_logs_failed'));
    } finally {
      setLoading(false);
    }
  }, [category, level, offset, props, range, search]);

  useEffect(() => {
    void load(0);
  }, [category, level, range]);

  useEffect(() => {
    let cancelled = false;
    setSettingsLoading(true);
    props.onLoadSettings()
      .then((next) => {
        if (!cancelled) {
          setSettings(next);
          setRetentionMode(inferRetentionMode(next));
        }
      })
      .catch(() => {
        if (!cancelled) props.onNotify('error', t('txt_load_log_settings_failed'));
      })
      .finally(() => {
        if (!cancelled) setSettingsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  function submitFilters(event: Event): void {
    event.preventDefault();
    void load(0);
  }

  async function saveSettings(): Promise<void> {
    setSettingsSaving(true);
    try {
      const next = await props.onSaveSettings(settings);
      setSettings(next);
      setRetentionMode(inferRetentionMode(next));
      setSettingsOpen(false);
      setClearConfirmOpen(false);
      props.onNotify('success', t('txt_log_settings_saved'));
      void load(0);
    } catch {
      props.onNotify('error', t('txt_log_settings_save_failed'));
    } finally {
      setSettingsSaving(false);
    }
  }

  async function clearLogs(): Promise<void> {
    setSettingsSaving(true);
    try {
      await props.onClearLogs();
      setLogs([]);
      setTotal(0);
      setHasMore(false);
      setOffset(0);
      setSelectedId(null);
      setMobileDetailOpen(false);
      setClearConfirmOpen(false);
      setSettingsOpen(false);
      props.onNotify('success', t('txt_logs_cleared'));
    } catch {
      props.onNotify('error', t('txt_clear_logs_failed'));
    } finally {
      setSettingsSaving(false);
    }
  }

  function selectRetentionMode(nextMode: RetentionMode): void {
    setRetentionMode(nextMode);
    setSettings((current) => nextMode === 'days'
      ? { retentionDays: current.retentionDays ?? 90, maxEntries: null }
      : { retentionDays: null, maxEntries: current.maxEntries ?? 10_000 });
  }

  const visibleMetaEntries = selectedLog
    ? Object.entries(selectedMetadata).filter(([key]) => key !== 'category' && key !== 'level')
    : [];

  function selectLog(logId: string): void {
    setSelectedId(logId);
    setSettingsOpen(false);
    setClearConfirmOpen(false);
    setMobileDetailOpen(true);
  }

  function handleMobileBack(): void {
    if (mobileDetailOpen) {
      setMobileDetailOpen(false);
      return;
    }
    props.onMobileBack?.();
  }

  return (
    <div className={`log-center-page ${mobileDetailOpen ? 'log-mobile-detail-open' : ''}`}>
      {props.mobileLayout && (
      <div className="log-mobile-subhead">
        <button type="button" className="btn btn-secondary small mobile-settings-back" onClick={handleMobileBack}>
          <ChevronLeft size={14} className="btn-icon" />
          {t('txt_back')}
        </button>
        <button
          type="button"
          className={`btn btn-secondary log-mobile-settings-trigger ${settingsOpen ? 'active' : ''}`}
          aria-label={t('txt_log_settings')}
          title={t('txt_log_settings')}
          aria-expanded={settingsOpen}
          onClick={() => {
            setSettingsOpen((open) => !open);
            setClearConfirmOpen(false);
          }}
        >
          <Settings2 size={18} />
        </button>
      </div>
      )}
      <section className="card log-center-toolbar">
        <form className="log-filter-form" onSubmit={submitFilters}>
          <label className="field log-search-field">
            <span>{t('txt_search')}</span>
            <div className="input-action-wrap">
              <Search size={15} className="input-leading-icon" />
              <input
                className="input log-search-input"
                value={search}
                placeholder={t('txt_log_search_placeholder')}
                onInput={(event) => setSearch((event.currentTarget as HTMLInputElement).value)}
              />
            </div>
          </label>
          <label className="field">
            <span>{t('txt_log_category')}</span>
            <select className="input" value={category} onChange={(event) => setCategory((event.currentTarget as HTMLSelectElement).value as FilterCategory)}>
              {CATEGORY_OPTIONS.map((option) => <option key={option.value} value={option.value}>{t(option.labelKey)}</option>)}
            </select>
          </label>
          <label className="field">
            <span>{t('txt_log_level')}</span>
            <select className="input" value={level} onChange={(event) => setLevel((event.currentTarget as HTMLSelectElement).value as FilterLevel)}>
              {LEVEL_OPTIONS.map((option) => <option key={option.value} value={option.value}>{t(option.labelKey)}</option>)}
            </select>
          </label>
          <label className="field">
            <span>{t('txt_time_range')}</span>
            <select className="input" value={range} onChange={(event) => setRange((event.currentTarget as HTMLSelectElement).value as TimeRange)}>
              {RANGE_OPTIONS.map((option) => <option key={option.value} value={option.value}>{t(option.labelKey)}</option>)}
            </select>
          </label>
          <div className="actions log-filter-actions">
            <button type="button" className="btn btn-secondary" disabled={loading} onClick={() => void load(offset)}>
              <RefreshCw size={14} className="btn-icon" />
              {t('txt_refresh')}
            </button>
            <button
              type="button"
              className={`btn btn-secondary ${settingsOpen ? 'active' : ''}`}
              aria-expanded={settingsOpen}
              onClick={() => {
                setSettingsOpen((open) => !open);
                setClearConfirmOpen(false);
              }}
            >
              <Settings2 size={14} className="btn-icon" />
              {t('txt_log_settings')}
            </button>
          </div>
        </form>

        {settingsOpen && (
          <div className="log-settings-popover">
            <div className="section-head log-settings-popover-head">
              <h3>{t('txt_log_retention_settings')}</h3>
            </div>
            <div className="log-settings-mode" role="group" aria-label={t('txt_log_retention_mode')}>
              <button
                type="button"
                className={`log-mode-option ${retentionMode === 'days' ? 'active' : ''}`}
                disabled={settingsLoading || settingsSaving}
                onClick={() => selectRetentionMode('days')}
              >
                {t('txt_log_retention_mode_days')}
              </button>
              <button
                type="button"
                className={`log-mode-option ${retentionMode === 'entries' ? 'active' : ''}`}
                disabled={settingsLoading || settingsSaving}
                onClick={() => selectRetentionMode('entries')}
              >
                {t('txt_log_retention_mode_entries')}
              </button>
            </div>
            {retentionMode === 'days' ? (
              <div className="log-settings-retention-block">
                <label className="log-settings-label" htmlFor="log-retention-days-select">{t('txt_log_retention_days')}</label>
                <div className="log-settings-retention-row">
                  <select
                    id="log-retention-days-select"
                    className="input"
                    value={String(settings.retentionDays ?? 0)}
                    disabled={settingsLoading || settingsSaving}
                    onChange={(event) => setSettings({
                      retentionDays: Number((event.currentTarget as HTMLSelectElement).value) || null,
                      maxEntries: null,
                    })}
                  >
                    {RETENTION_OPTIONS.map((option) => <option key={option.value} value={option.value}>{t(option.labelKey)}</option>)}
                  </select>
                  <button type="button" className="btn btn-primary log-settings-save-btn" disabled={settingsLoading || settingsSaving} onClick={() => void saveSettings()}>
                    <Save size={14} className="btn-icon" />
                    {t('txt_save')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="log-settings-retention-block">
                <label className="log-settings-label" htmlFor="log-max-entries-select">{t('txt_log_max_entries')}</label>
                <div className="log-settings-retention-row">
                  <select
                    id="log-max-entries-select"
                    className="input"
                    value={String(settings.maxEntries ?? 0)}
                    disabled={settingsLoading || settingsSaving}
                    onChange={(event) => setSettings({
                      retentionDays: null,
                      maxEntries: Number((event.currentTarget as HTMLSelectElement).value) || null,
                    })}
                  >
                    {MAX_ENTRY_OPTIONS.map((option) => <option key={option.value} value={option.value}>{t(option.labelKey)}</option>)}
                  </select>
                  <button type="button" className="btn btn-primary log-settings-save-btn" disabled={settingsLoading || settingsSaving} onClick={() => void saveSettings()}>
                    <Save size={14} className="btn-icon" />
                    {t('txt_save')}
                  </button>
                </div>
              </div>
            )}
            <div className="log-settings-danger">
              {clearConfirmOpen ? (
                <>
                  <p>{t('txt_clear_logs_confirm')}</p>
                  <div className="actions log-clear-confirm-actions">
                    <button type="button" className="btn btn-secondary" disabled={settingsSaving} onClick={() => setClearConfirmOpen(false)}>
                      {t('txt_cancel')}
                    </button>
                    <button type="button" className="btn btn-danger" disabled={settingsSaving} onClick={() => void clearLogs()}>
                      <Trash2 size={14} className="btn-icon" />
                      {t('txt_clear_all_logs')}
                    </button>
                  </div>
                </>
              ) : (
                <button type="button" className="btn btn-danger ghost-danger" disabled={settingsLoading || settingsSaving} onClick={() => setClearConfirmOpen(true)}>
                  <Trash2 size={14} className="btn-icon" />
                  {t('txt_clear_all_logs')}
                </button>
              )}
            </div>
          </div>
        )}
      </section>

      <div className="log-center-grid">
        <section className="card log-list-panel">
          <div className="section-head">
            <h3>{t('txt_audit_events')}</h3>
            <span className="muted-inline">{page} / {totalPages}</span>
          </div>
          <div className="log-list">
            {logs.map((log) => {
              const metadata = parseMetadata(log);
              const logCategory = inferCategory(log, metadata);
              const logLevel = inferLevel(log, metadata);
              return (
                <button
                  key={log.id}
                  type="button"
                  className={`log-row ${selectedLog?.id === log.id ? 'active' : ''}`}
                  onClick={() => selectLog(log.id)}
                >
                  <span className={`log-row-icon log-category-${logCategory}`}>{iconForCategory(logCategory)}</span>
                  <span className="log-row-main">
                    <strong>{formatAction(log.action)}</strong>
                    <small>{formatTime(log.createdAt)}</small>
                  </span>
                  <span className={`log-level-pill log-level-${logLevel}`}>{t(`txt_log_level_${logLevel}`)}</span>
                </button>
              );
            })}
            {loading && !logs.length && <LoadingState lines={5} compact />}
            {!loading && !logs.length && <div className="empty empty-comfortable">{t('txt_no_logs_found')}</div>}
            {!!error && <div className="local-error">{error}</div>}
          </div>
          <div className="actions log-pagination">
            <button type="button" className="btn btn-secondary small" disabled={loading || offset <= 0} onClick={() => void load(Math.max(0, offset - PAGE_SIZE))}>
              <ChevronLeft size={14} className="btn-icon" />
              {t('txt_prev')}
            </button>
            <span className="log-pagination-count">
              {Math.min(offset + logs.length, total)} / {total}
            </span>
            <button type="button" className="btn btn-secondary small" disabled={loading || !hasMore} onClick={() => void load(offset + PAGE_SIZE)}>
              {t('txt_next')}
              <ChevronRight size={14} className="btn-icon" />
            </button>
          </div>
        </section>

        <section className="card log-detail-panel">
          {selectedLog ? (
            <>
              <div className="section-head log-detail-head">
                <div>
                  <h3>{formatAction(selectedLog.action)}</h3>
                  <p className="muted-inline">{selectedLog.action}</p>
                </div>
                <span className={`log-level-pill log-level-${selectedLevel}`}>{t(`txt_log_level_${selectedLevel}`)}</span>
              </div>
              <div className="log-detail-meta">
                <div><span>{t('txt_time')}</span><strong>{formatTime(selectedLog.createdAt)}</strong></div>
                <div><span>{t('txt_log_category')}</span><strong>{t(`txt_log_category_${selectedCategory}`)}</strong></div>
                <div><span>{t('txt_actor')}</span><strong>{selectedLog.actorEmail || selectedLog.actorUserId || t('txt_dash')}</strong></div>
                <div><span>{t('txt_target')}</span><strong>{formatLogTarget(selectedLog, selectedMetadata)}</strong></div>
              </div>
              <div className="log-detail-json">
                <h4>{t('txt_metadata')}</h4>
                {visibleMetaEntries.length ? (
                  <dl>
                    {visibleMetaEntries.map(([key, value]) => (
                      <div key={key}>
                        <dt>{formatMetaKey(key)}</dt>
                        <dd>{formatMetaValueForKey(key, value)}</dd>
                      </div>
                    ))}
                  </dl>
                ) : (
                  <div className="empty">{t('txt_no_metadata')}</div>
                )}
              </div>
            </>
          ) : (
            <div className="empty empty-comfortable">{t('txt_no_logs_found')}</div>
          )}
        </section>
      </div>
    </div>
  );
}
