import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { CheckCheck, ChevronLeft, Copy, Eye, EyeOff, File, FileText, LayoutGrid, Lock, Pencil, Plus, RefreshCw, Save, Send as SendIcon, Trash2, X } from 'lucide-preact';
import { copyTextToClipboard } from '@/lib/clipboard';
import LoadingState from '@/components/LoadingState';
import type { Send, SendDraft } from '@/lib/types';
import { t } from '@/lib/i18n';

interface SendsPageProps {
  sends: Send[];
  loading: boolean;
  onRefresh: () => Promise<void>;
  onCreate: (draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onUpdate: (send: Send, draft: SendDraft, autoCopyLink: boolean) => Promise<void>;
  onDelete: (send: Send) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  uploadingSendFileName: string;
  sendUploadPercent: number | null;
  mobileSidebarToggleKey: number;
  onNotify: (type: 'success' | 'error', text: string) => void;
}

type SendTypeFilter = 'all' | 'text' | 'file';
const AUTO_COPY_KEY = 'nodewarden.send.auto_copy_link.v1';
const MOBILE_LAYOUT_QUERY = '(max-width: 1180px)';

function daysFromNow(iso: string | null | undefined, fallback: number): string {
  if (!iso) return String(fallback);
  const d = new Date(iso).getTime();
  if (!Number.isFinite(d)) return String(fallback);
  const diff = d - Date.now();
  const days = Math.ceil(diff / (24 * 60 * 60 * 1000));
  return String(Math.max(days, 0));
}

function formatSendDate(value: string | null | undefined): string {
  if (!value) return t('txt_dash');
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return t('txt_dash');
  return parsed.toLocaleString();
}

function buildDefaultDraft(): SendDraft {
  return {
    type: 'text',
    name: '',
    notes: '',
    text: '',
    file: null,
    deletionDays: '7',
    expirationDays: '0',
    maxAccessCount: '',
    password: '',
    hasPassword: false,
    disabled: false,
  };
}

function draftFromSend(send: Send): SendDraft {
  return {
    id: send.id,
    type: Number(send.type) === 1 ? 'file' : 'text',
    name: send.decName || '',
    notes: send.decNotes || '',
    text: send.decText || '',
    file: null,
    deletionDays: daysFromNow(send.deletionDate, 7),
    expirationDays: daysFromNow(send.expirationDate, 0),
    maxAccessCount: send.maxAccessCount !== null && send.maxAccessCount !== undefined ? String(send.maxAccessCount) : '',
    password: '',
    hasPassword: !!send.password,
    disabled: !!send.disabled,
  };
}

export default function SendsPage(props: SendsPageProps) {
  const getInitialIsMobileLayout = () =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(MOBILE_LAYOUT_QUERY).matches
      : false;
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState<SendTypeFilter>('all');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [draft, setDraft] = useState<SendDraft | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [selectedMap, setSelectedMap] = useState<Record<string, boolean>>({});
  const [isMobileLayout, setIsMobileLayout] = useState(getInitialIsMobileLayout);
  const [mobilePanel, setMobilePanel] = useState<'list' | 'detail' | 'edit'>('list');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const mobileSidebarToggleKeyRef = useRef(props.mobileSidebarToggleKey);
  const [autoCopyLink, setAutoCopyLink] = useState<boolean>(() => {
    try {
      return localStorage.getItem(AUTO_COPY_KEY) === '1';
    } catch {
      return false;
    }
  });
  const sendUploadLabel =
    props.sendUploadPercent == null
      ? t('txt_uploading_file_named', { name: props.uploadingSendFileName || t('txt_file') })
      : t('txt_uploading_file_named_percent', {
          name: props.uploadingSendFileName || t('txt_file'),
          percent: props.sendUploadPercent,
        });

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return;
    const media = window.matchMedia(MOBILE_LAYOUT_QUERY);
    const sync = () => setIsMobileLayout(media.matches);
    sync();
    if (typeof media.addEventListener === 'function') {
      media.addEventListener('change', sync);
      return () => media.removeEventListener('change', sync);
    }
    media.addListener(sync);
    return () => media.removeListener(sync);
  }, []);

  useEffect(() => {
    if (props.mobileSidebarToggleKey === mobileSidebarToggleKeyRef.current) return;
    mobileSidebarToggleKeyRef.current = props.mobileSidebarToggleKey;
    setMobileSidebarOpen((open) => !open);
  }, [props.mobileSidebarToggleKey]);

  useEffect(() => {
    try {
      localStorage.setItem(AUTO_COPY_KEY, autoCopyLink ? '1' : '0');
    } catch {
      // ignore storage errors
    }
  }, [autoCopyLink]);

  useEffect(() => {
    if (!isMobileLayout) {
      setMobilePanel('list');
      setMobileSidebarOpen(false);
      return;
    }
    if (isEditing) {
      setMobilePanel('edit');
    } else if (!selectedId) {
      setMobilePanel('list');
    }
  }, [isMobileLayout, isEditing, selectedId]);

  const filteredSends = useMemo(() => {
    const q = search.trim().toLowerCase();
    return props.sends.filter((send) => {
      if (typeFilter === 'text' && Number(send.type) !== 0) return false;
      if (typeFilter === 'file' && Number(send.type) !== 1) return false;
      if (!q) return true;
      const name = (send.decName || '').toLowerCase();
      const text = (send.decText || '').toLowerCase();
      return name.includes(q) || text.includes(q);
    });
  }, [props.sends, search, typeFilter]);

  useEffect(() => {
    if (!filteredSends.length) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !filteredSends.some((x) => x.id === selectedId)) {
      setSelectedId(filteredSends[0].id);
      setIsEditing(false);
      setIsCreating(false);
      setDraft(null);
    }
  }, [filteredSends, selectedId]);

  const selectedSend = useMemo(
    () => props.sends.find((x) => x.id === selectedId) || null,
    [props.sends, selectedId]
  );
  const selectedIds = useMemo(() => Object.keys(selectedMap).filter((id) => selectedMap[id]), [selectedMap]);
  const selectedCount = selectedIds.length;

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    if (!draft.name.trim()) {
      props.onNotify('error', t('txt_name_is_required'));
      return;
    }
    if (draft.type === 'text' && !draft.text.trim()) {
      props.onNotify('error', t('txt_text_is_required'));
      return;
    }
    if (draft.type === 'file' && isCreating && !draft.file) {
      props.onNotify('error', t('txt_please_select_a_file'));
      return;
    }
    setBusy(true);
    try {
      if (isCreating) {
        await props.onCreate(draft, autoCopyLink);
        setSelectedId(null);
      } else if (selectedSend) {
        await props.onUpdate(selectedSend, draft, autoCopyLink);
      }
      setIsEditing(false);
      setIsCreating(false);
      setDraft(null);
      setShowPassword(false);
      if (isMobileLayout) setMobilePanel('detail');
    } finally {
      setBusy(false);
    }
  }

  async function removeSend(send: Send): Promise<void> {
    setBusy(true);
    try {
      await props.onDelete(send);
      if (selectedId === send.id) setSelectedId(null);
      setIsEditing(false);
      setDraft(null);
      if (isMobileLayout) setMobilePanel('list');
    } finally {
      setBusy(false);
    }
  }

  async function removeSelected(): Promise<void> {
    if (!selectedCount) return;
    setBusy(true);
    try {
      await props.onBulkDelete(selectedIds);
      setSelectedMap({});
    } finally {
      setBusy(false);
    }
  }

  function getAccessUrl(send: Send): string {
    const rawUrl = send.shareUrl || `/send/${send.accessId}`;
    if (/^https?:\/\//i.test(rawUrl)) return rawUrl;
    if (rawUrl.startsWith('/#/')) return `${window.location.origin}${rawUrl}`;
    if (rawUrl.startsWith('#/')) return `${window.location.origin}/${rawUrl}`;
    if (rawUrl.startsWith('/')) return `${window.location.origin}/#${rawUrl}`;
    return `${window.location.origin}/#/${rawUrl.replace(/^\/+/, '')}`;
  }

  function copyAccessUrl(send: Send): void {
    const url = getAccessUrl(send);
    void copyTextToClipboard(url, { successMessage: t('txt_link_copied') });
  }

  return (
    <div className={`vault-grid ${isMobileLayout ? `mobile-panel-${mobilePanel}` : ''}`}>
      {isMobileLayout && (
        <div
          className={`mobile-sidebar-mask ${mobileSidebarOpen ? 'open' : ''}`}
          onClick={() => {
            if (!mobileSidebarOpen) return;
            setMobileSidebarOpen(false);
          }}
        />
      )}
      <aside className={`sidebar ${isMobileLayout ? 'mobile-sidebar-sheet' : ''} ${isMobileLayout && mobileSidebarOpen ? 'open' : ''}`}>
        {isMobileLayout && (
          <div className="mobile-sidebar-head">
            <div className="mobile-sidebar-title">{t('txt_all_sends')}</div>
            <button type="button" className="mobile-sidebar-close" onClick={() => setMobileSidebarOpen(false)} aria-label={t('txt_close')}>
              <X size={16} />
            </button>
          </div>
        )}
        <div className="sidebar-block">
          <div className="sidebar-title">{t('txt_all_sends')}</div>
          <button type="button" className={`tree-btn ${typeFilter === 'all' ? 'active' : ''}`} onClick={() => setTypeFilter('all')}>
            <LayoutGrid size={14} className="tree-icon" />
            <span className="tree-label">{t('txt_all_sends')}</span>
          </button>
        </div>
        <div className="sidebar-block">
          <div className="sidebar-title">{t('txt_type')}</div>
          <button type="button" className={`tree-btn ${typeFilter === 'text' ? 'active' : ''}`} onClick={() => setTypeFilter('text')}>
            <FileText size={14} className="tree-icon" />
            <span className="tree-label">{t('txt_text')}</span>
          </button>
          <button type="button" className={`tree-btn ${typeFilter === 'file' ? 'active' : ''}`} onClick={() => setTypeFilter('file')}>
            <File size={14} className="tree-icon" />
            <span className="tree-label">{t('txt_file')}</span>
          </button>
        </div>
      </aside>

      <section className="list-col">
        <div className="list-head">
          <input
            className="search-input"
            placeholder={t('txt_search_sends')}
            value={search}
            onInput={(e) => setSearch((e.currentTarget as HTMLInputElement).value)}
          />
          <button type="button" className="btn btn-secondary small list-icon-btn" disabled={busy || props.loading} onClick={() => void props.onRefresh()}>
            <RefreshCw size={14} className="btn-icon" /> {t('txt_refresh')}
          </button>
        </div>
        <div className="toolbar actions">
          <button type="button" className="btn btn-danger small" disabled={!selectedCount || busy} onClick={() => void removeSelected()}>
            <Trash2 size={14} className="btn-icon" /> {t('txt_delete_selected')}
          </button>
          <button
            type="button"
            className="btn btn-secondary small"
            disabled={!filteredSends.length}
            onClick={() => {
              const map: Record<string, boolean> = {};
              for (const send of filteredSends) map[send.id] = true;
              setSelectedMap(map);
            }}
          >
            <CheckCheck size={14} className="btn-icon" />
            {t('txt_select_all')}
          </button>
          {!!selectedCount && (
            <button type="button" className="btn btn-secondary small" onClick={() => setSelectedMap({})}>
              <X size={14} className="btn-icon" />
              {t('txt_cancel')}
            </button>
          )}
          <button
            type="button"
            className="btn btn-primary small mobile-fab-trigger"
            disabled={busy}
            aria-label={t('txt_add')}
            title={t('txt_add')}
            onClick={() => {
              setIsCreating(true);
              setIsEditing(true);
              setDraft(buildDefaultDraft());
              setShowPassword(false);
              if (isMobileLayout) setMobilePanel('edit');
              setMobileSidebarOpen(false);
            }}
          >
            <Plus size={14} className="btn-icon" />
          </button>
        </div>
        <div className="list-panel">
          {props.loading && !filteredSends.length && <LoadingState lines={6} compact />}
          {filteredSends.map((send, index) => (
            <div
              key={send.id}
              className={`list-item stagger-item stagger-delay-${Math.min(index, 10)} ${selectedId === send.id ? 'active' : ''}`}
              onClick={(event) => {
                const target = event.target as HTMLElement;
                if (target.closest('.row-check')) return;
                setSelectedId(send.id);
                setIsEditing(false);
                setIsCreating(false);
                setDraft(null);
                if (isMobileLayout) setMobilePanel('detail');
                setMobileSidebarOpen(false);
              }}
            >
              <input
                type="checkbox"
                className="row-check"
                checked={!!selectedMap[send.id]}
                onClick={(event) => event.stopPropagation()}
                onInput={(e) =>
                  setSelectedMap((prev) => ({
                    ...prev,
                    [send.id]: (e.currentTarget as HTMLInputElement).checked,
                  }))
                }
              />
              <button
                type="button"
                className="row-main"
                onClick={() => {
                  setSelectedId(send.id);
                  setIsEditing(false);
                  setIsCreating(false);
                  setDraft(null);
                  if (isMobileLayout) setMobilePanel('detail');
                  setMobileSidebarOpen(false);
                }}
              >
                <div className="list-icon-wrap">
                  <span className="list-icon-fallback">
                    <SendIcon />
                  </span>
                </div>
                <div className="list-text">
                  <span className="list-title" title={send.decName || t('txt_no_name')}>{send.decName || t('txt_no_name')}</span>
                  <span className="list-sub">
                    {!!send.password && <><Lock size={12} className="inline-icon" /> </>}
                    {Number(send.type) === 1 ? t('txt_file') : t('txt_text')} - {t('txt_accessed_count_times', { count: send.accessCount || 0 })}
                  </span>
                </div>
              </button>
            </div>
          ))}
          {!props.loading && !filteredSends.length && <div className="empty">{t('txt_no_sends')}</div>}
        </div>
      </section>

      <section className={`detail-col ${isMobileLayout ? 'mobile-detail-sheet' : ''} ${isMobileLayout && mobilePanel !== 'list' ? 'open' : ''}`}>
        {isMobileLayout && mobilePanel !== 'list' && (
          <div className="mobile-panel-head">
            <button
              type="button"
              className="btn btn-secondary small mobile-panel-back"
              onClick={() => {
                if (isEditing) {
                  setIsEditing(false);
                  setIsCreating(false);
                  setDraft(null);
                  setShowPassword(false);
                  setMobilePanel(selectedSend ? 'detail' : 'list');
                } else {
                  setMobilePanel('list');
                }
              }}
            >
              <ChevronLeft size={14} className="btn-icon" />
              {t('txt_back')}
            </button>
          </div>
        )}
        {isEditing && draft && (
          <div key={`send-editor-${draft.id || selectedSend?.id || 'new'}-${draft.type}`} className="detail-switch-stage">
            <div className="card stagger-item stagger-delay-0">
              <h3 className="detail-title">{isCreating ? t('txt_new_send') : t('txt_edit_send')}</h3>
              {!!props.uploadingSendFileName && <div className="detail-sub">{sendUploadLabel}</div>}
              <div className="field-grid">
              <label className="field field-span-2">
                <span>{t('txt_name')}</span>
                <input className="input" value={draft.name} onInput={(e) => setDraft({ ...draft, name: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <label className="field field-span-2">
                <span>{t('txt_type')}</span>
                <div className="send-options">
                  <label>
                    <input
                      type="radio"
                      checked={draft.type === 'file'}
                      disabled={!isCreating}
                      onInput={() => setDraft({ ...draft, type: 'file' })}
                    />
                    {t('txt_file')}
                  </label>
                  <label>
                    <input
                      type="radio"
                      checked={draft.type === 'text'}
                      disabled={!isCreating}
                      onInput={() => setDraft({ ...draft, type: 'text' })}
                    />
                    {t('txt_text')}
                  </label>
                </div>
              </label>
              {draft.type === 'file' ? (
                <label className="field field-span-2">
                  <span>{t('txt_file')}</span>
                  <input className="input" type="file" onInput={(e) => setDraft({ ...draft, file: (e.currentTarget as HTMLInputElement).files?.[0] || null })} />
                </label>
              ) : (
                <label className="field field-span-2">
                  <span>{t('txt_text')}</span>
                  <textarea className="input textarea" rows={8} value={draft.text} onInput={(e) => setDraft({ ...draft, text: (e.currentTarget as HTMLTextAreaElement).value })} />
                </label>
              )}
              <label className="field">
                <span>{t('txt_deletion_days')}</span>
                <input className="input" type="number" min="1" max="31" value={draft.deletionDays} onInput={(e) => setDraft({ ...draft, deletionDays: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <label className="field">
                <span>{t('txt_expiration_days_0_never')}</span>
                <input className="input" type="number" min="0" max="3650" value={draft.expirationDays} onInput={(e) => setDraft({ ...draft, expirationDays: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <label className="field">
                <span>{t('txt_max_access_count')}</span>
                <input className="input" value={draft.maxAccessCount} onInput={(e) => setDraft({ ...draft, maxAccessCount: (e.currentTarget as HTMLInputElement).value })} />
              </label>
              <label className="field">
                <span>{t('txt_password')}</span>
                {draft.hasPassword ? (
                  <div className="password-wrap">
                    <input className="input" type="password" value="••••••••" disabled />
                    {!isCreating && (
                      <button type="button" className="password-toggle text-red-600 hover:text-red-700" onClick={() => setDraft({ ...draft, hasPassword: false, password: '' })} title={t('txt_remove')}>
                        <Trash2 size={16} />
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="password-wrap">
                    <input className="input" type={showPassword ? 'text' : 'password'} value={draft.password} onInput={(e) => setDraft({ ...draft, password: (e.currentTarget as HTMLInputElement).value })} />
                    <button type="button" className="password-toggle" onClick={() => setShowPassword((v) => !v)}>
                      {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                  </div>
                )}
              </label>
              <label className="field field-span-2">
                <span>{t('txt_notes')}</span>
                <textarea className="input textarea" rows={5} value={draft.notes} onInput={(e) => setDraft({ ...draft, notes: (e.currentTarget as HTMLTextAreaElement).value })} />
              </label>
              <label className="field field-span-2">
                <span>{t('txt_options')}</span>
                <div className="send-options">
                  <label><input type="checkbox" checked={draft.disabled} onInput={(e) => setDraft({ ...draft, disabled: (e.currentTarget as HTMLInputElement).checked })} /> {t('txt_disable_this_send')}</label>
                  <label><input type="checkbox" checked={autoCopyLink} onInput={(e) => setAutoCopyLink((e.currentTarget as HTMLInputElement).checked)} /> {t('txt_auto_copy_link_after_save')}</label>
                </div>
              </label>
              </div>
              <div className="detail-actions">
              <button type="button" className="btn btn-primary small" disabled={busy} onClick={() => void saveDraft()}>
                <Save size={14} className="btn-icon" /> {t('txt_save')}
              </button>
              <button
                type="button"
                className="btn btn-secondary small"
                disabled={busy}
                onClick={() => {
                  setIsEditing(false);
                  setIsCreating(false);
                  setDraft(null);
                  setShowPassword(false);
                  if (isMobileLayout) setMobilePanel(selectedSend ? 'detail' : 'list');
                }}
              >
                <X size={14} className="btn-icon" /> {t('txt_cancel')}
              </button>
              </div>
            </div>
          </div>
        )}

        {!isEditing && selectedSend && (
          <div key={`send-detail-${selectedSend.id}`} className="detail-switch-stage">
            <div className="card stagger-item stagger-delay-1">
              <h3 className="detail-title">{selectedSend.decName || t('txt_no_name')}</h3>
              <div className="detail-sub">{Number(selectedSend.type) === 1 ? t('txt_file_send') : t('txt_text_send')}</div>
            </div>

            <div className="card stagger-item stagger-delay-2">
              <h4>{t('txt_send_details')}</h4>
              <div className="kv-line"><span>{t('txt_access_count')}</span><strong>{selectedSend.accessCount || 0}</strong></div>
              <div className="kv-line"><span>{t('txt_deletion_date')}</span><strong>{formatSendDate(selectedSend.deletionDate)}</strong></div>
              <div className="kv-line"><span>{t('txt_expiration_date')}</span><strong>{formatSendDate(selectedSend.expirationDate)}</strong></div>
            </div>

            <div className="card">
              {Number(selectedSend.type) === 1 ? (
                <>
                  <h4>{t('txt_file')}</h4>
                  <div className="kv-line"><span>{t('txt_file_name')}</span><strong>{selectedSend.file?.fileName || t('txt_encrypted_file_2')}</strong></div>
                  <div className="kv-line"><span>{t('txt_file_size')}</span><strong>{selectedSend.file?.sizeName || t('txt_dash')}</strong></div>
                </>
              ) : (
                <>
                  <h4>{t('txt_text')}</h4>
                  <div className="notes">{selectedSend.decText || ''}</div>
                </>
              )}
            </div>

            {!!(selectedSend.decNotes || '').trim() && (
              <div className="card stagger-item stagger-delay-3">
                <h4>{t('txt_notes')}</h4>
                <div className="notes">{selectedSend.decNotes || ''}</div>
              </div>
            )}

            <div className="detail-actions">
              <div className="actions">
                <button type="button" className="btn btn-secondary small" onClick={() => copyAccessUrl(selectedSend)}>
                  <Copy size={14} className="btn-icon" /> {t('txt_copy_link')}
                </button>
                <button type="button" className="btn btn-secondary small" onClick={() => { setDraft(draftFromSend(selectedSend)); setIsCreating(false); setIsEditing(true); setShowPassword(false); }}>
                  <Pencil size={14} className="btn-icon" /> {t('txt_edit')}
                </button>
              </div>
              <button type="button" className="btn btn-danger small detail-delete-btn" disabled={busy} onClick={() => void removeSend(selectedSend)}>
                <Trash2 size={14} className="btn-icon" /> {t('txt_delete')}
              </button>
            </div>
          </div>
        )}
        {!isEditing && !selectedSend && props.loading && <LoadingState card lines={4} />}
      </section>
    </div>
  );
}
