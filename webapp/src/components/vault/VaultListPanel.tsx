import type { ComponentChildren, RefObject } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { memo } from 'preact/compat';
import { createPortal } from 'preact/compat';
import {
  Archive,
  ArrowUpDown,
  Check,
  CheckCheck,
  ChevronDown,
  Copy,
  CreditCard,
  Folder as FolderIcon,
  FolderInput,
  FolderX,
  Globe,
  KeyRound,
  LayoutGrid,
  Plus,
  RefreshCw,
  RotateCcw,
  ShieldUser,
  Star,
  StickyNote,
  Trash2,
  X,
} from 'lucide-preact';
import LoadingState from '@/components/LoadingState';
import type { Cipher, Folder } from '@/lib/types';
import { t } from '@/lib/i18n';
import {
  CreateTypeIcon,
  getCreateTypeOptions,
  getDuplicateDetectionOptions,
  getVaultSortOptions,
  VaultListIcon,
  type DuplicateDetectionMode,
  type SidebarFilter,
  type VaultSortMode,
} from '@/components/vault/vault-page-helpers';

interface VirtualRange {
  start: number;
  end: number;
  padTop: number;
  padBottom: number;
}

interface VaultListPanelProps {
  busy: boolean;
  loading: boolean;
  error: string;
  folders: Folder[];
  searchInput: string;
  sortMode: VaultSortMode;
  sortMenuOpen: boolean;
  duplicateMode: DuplicateDetectionMode;
  selectedCount: number;
  totalCipherCount: number;
  filteredCiphers: Cipher[];
  visibleCiphers: Cipher[];
  duplicateGroupIndexById: Map<string, number>;
  virtualRange: VirtualRange;
  selectedCipherId: string;
  selectedMap: Record<string, boolean>;
  sidebarFilter: SidebarFilter;
  isMobileLayout: boolean;
  mobileFabVisible: boolean;
  createMenuOpen: boolean;
  createMenuRef: RefObject<HTMLDivElement>;
  sortMenuRef: RefObject<HTMLDivElement>;
  listPanelRef: RefObject<HTMLDivElement>;
  onSearchInput: (value: string) => void;
  onClearSearch: () => void;
  onSearchCompositionStart: () => void;
  onSearchCompositionEnd: (value: string) => void;
  onToggleSortMenu: () => void;
  onSelectSortMode: (value: VaultSortMode) => void;
  onDuplicateModeChange: (value: DuplicateDetectionMode) => void;
  onChangeFilter: (filter: SidebarFilter) => void;
  onSyncVault: () => void;
  onOpenBulkDelete: () => void;
  onSelectDuplicates: () => void;
  onSelectUniqueFromDuplicates: () => void;
  onSelectAll: () => void;
  onToggleCreateMenu: () => void;
  onStartCreate: (type: number) => void;
  onBulkRestore: () => void;
  onBulkArchive: () => void;
  onBulkUnarchive: () => void;
  onOpenMove: () => void;
  onClearSelection: () => void;
  onScroll: (top: number) => void;
  onToggleSelected: (cipherId: string, checked: boolean) => void;
  onSelectCipher: (cipherId: string) => void;
  listSubtitle: (cipher: Cipher) => string;
}

interface CipherListItemProps {
  cipher: Cipher;
  selected: boolean;
  checked: boolean;
  duplicateGroupIndex: number | null;
  subtitle: string;
  onToggleSelected: (cipherId: string, checked: boolean) => void;
  onSelectCipher: (cipherId: string) => void;
}

type MobileFilterMenuKey = 'duplicate' | 'menu' | 'type' | 'folder';

interface MobileFilterOption {
  value: string;
  label: string;
  icon: ComponentChildren;
  active: boolean;
  onSelect: () => void;
}

const CipherListItem = memo(function CipherListItem(props: CipherListItemProps) {
  const duplicateGroupHue = props.duplicateGroupIndex === null ? null : (props.duplicateGroupIndex * 137.508) % 360;
  return (
    <div
      className={`list-item ${props.selected ? 'active' : ''} ${duplicateGroupHue === null ? '' : 'duplicate-group-item'}`}
      style={duplicateGroupHue === null ? undefined : { '--duplicate-group-hue': `${duplicateGroupHue}deg` }}
      onClick={(event) => {
        const target = event.target as HTMLElement;
        if (target.closest('.row-check')) return;
        props.onSelectCipher(props.cipher.id);
      }}
    >
      <input
        type="checkbox"
        className="row-check"
        checked={props.checked}
        onClick={(event) => event.stopPropagation()}
        onInput={(e) => props.onToggleSelected(props.cipher.id, (e.currentTarget as HTMLInputElement).checked)}
      />
      <button type="button" className="row-main" onClick={() => props.onSelectCipher(props.cipher.id)}>
        <div className={`list-icon-wrap ${Number(props.cipher.type || 1) === 3 ? 'card-list-icon-wrap' : ''}`}>
          <VaultListIcon cipher={props.cipher} />
        </div>
        <div className="list-text">
          <span className="list-title" title={props.cipher.decName || t('txt_no_name')}>
            <span className="list-title-text">{props.cipher.decName || t('txt_no_name')}</span>
          </span>
          <span className="list-sub" title={props.subtitle}>{props.subtitle}</span>
        </div>
      </button>
    </div>
  );
});

export default function VaultListPanel(props: VaultListPanelProps) {
  const [mobileFilterOpen, setMobileFilterOpen] = useState<MobileFilterMenuKey | null>(null);
  const mobileFilterRef = useRef<HTMLDivElement | null>(null);
  const createTypeOptions = getCreateTypeOptions();
  const duplicateDetectionOptions = getDuplicateDetectionOptions();
  const vaultSortOptions = getVaultSortOptions();
  const duplicateModeOptions: MobileFilterOption[] = duplicateDetectionOptions.map((option) => ({
    value: option.value,
    label: option.label,
    icon: option.value === 'login-site' ? <Globe size={14} /> : option.value === 'exact' ? <Copy size={14} /> : <KeyRound size={14} />,
    active: props.duplicateMode === option.value,
    onSelect: () => props.onDuplicateModeChange(option.value),
  }));
  const menuFilterOptions: MobileFilterOption[] = [
    { value: 'all', label: t('txt_all_items'), icon: <LayoutGrid size={14} />, active: props.sidebarFilter.kind === 'all', onSelect: () => props.onChangeFilter({ kind: 'all' }) },
    { value: 'favorite', label: t('txt_favorites'), icon: <Star size={14} />, active: props.sidebarFilter.kind === 'favorite', onSelect: () => props.onChangeFilter({ kind: 'favorite' }) },
    { value: 'archive', label: t('txt_archive'), icon: <Archive size={14} />, active: props.sidebarFilter.kind === 'archive', onSelect: () => props.onChangeFilter({ kind: 'archive' }) },
    { value: 'trash', label: t('txt_trash'), icon: <Trash2 size={14} />, active: props.sidebarFilter.kind === 'trash', onSelect: () => props.onChangeFilter({ kind: 'trash' }) },
    { value: 'duplicates', label: t('txt_duplicates'), icon: <Copy size={14} />, active: props.sidebarFilter.kind === 'duplicates', onSelect: () => props.onChangeFilter({ kind: 'duplicates' }) },
  ];
  const typeMobileFilterOptions: MobileFilterOption[] = [
    { value: 'login', label: t('txt_login'), icon: <Globe size={14} />, active: props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'login', onSelect: () => props.onChangeFilter({ kind: 'type', value: 'login' }) },
    { value: 'card', label: t('txt_card'), icon: <CreditCard size={14} />, active: props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'card', onSelect: () => props.onChangeFilter({ kind: 'type', value: 'card' }) },
    { value: 'identity', label: t('txt_identity'), icon: <ShieldUser size={14} />, active: props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'identity', onSelect: () => props.onChangeFilter({ kind: 'type', value: 'identity' }) },
    { value: 'note', label: t('txt_note'), icon: <StickyNote size={14} />, active: props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'note', onSelect: () => props.onChangeFilter({ kind: 'type', value: 'note' }) },
    { value: 'ssh', label: t('txt_ssh_key'), icon: <KeyRound size={14} />, active: props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'ssh', onSelect: () => props.onChangeFilter({ kind: 'type', value: 'ssh' }) },
  ];
  const folderMobileFilterOptions: MobileFilterOption[] = [
    { value: '__none__', label: t('txt_no_folder'), icon: <FolderX size={14} />, active: props.sidebarFilter.kind === 'folder' && props.sidebarFilter.folderId === null, onSelect: () => props.onChangeFilter({ kind: 'folder', folderId: null }) },
    ...props.folders.map((folder) => ({
      value: folder.id,
      label: folder.decName || folder.name || folder.id,
      icon: <FolderIcon size={14} />,
      active: props.sidebarFilter.kind === 'folder' && props.sidebarFilter.folderId === folder.id,
      onSelect: () => props.onChangeFilter({ kind: 'folder', folderId: folder.id }),
    })),
  ];
  const menuFilterSelected = menuFilterOptions.find((option) => option.active);
  const typeFilterSelected = typeMobileFilterOptions.find((option) => option.active);
  const folderFilterSelected = folderMobileFilterOptions.find((option) => option.active);
  const duplicateModeSelected = duplicateModeOptions.find((option) => option.active);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!mobileFilterOpen) return;
      const target = event.target as Node | null;
      if (mobileFilterRef.current && target && !mobileFilterRef.current.contains(target)) {
        setMobileFilterOpen(null);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileFilterOpen(null);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [mobileFilterOpen]);

  const renderMobileFilterMenu = (
    key: MobileFilterMenuKey,
    label: string,
    selected: MobileFilterOption | undefined,
    fallbackIcon: ComponentChildren,
    options: MobileFilterOption[]
  ) => (
    <div className="mobile-vault-filter-control">
      <button
        type="button"
        className={`mobile-vault-filter-trigger ${mobileFilterOpen === key ? 'active' : ''}`}
        aria-haspopup="menu"
        aria-expanded={mobileFilterOpen === key}
        onClick={() => setMobileFilterOpen((open) => open === key ? null : key)}
      >
        <span className="mobile-vault-filter-trigger-icon">{selected?.icon || fallbackIcon}</span>
        <span className="mobile-vault-filter-trigger-label">{selected?.label || label}</span>
        <ChevronDown size={13} className="mobile-vault-filter-chevron" />
      </button>
      {mobileFilterOpen === key && (
        <div className="sort-menu mobile-vault-filter-menu" role="menu">
          {options.map((option) => (
            <button
              key={option.value}
              type="button"
              className={`sort-menu-item mobile-vault-filter-item ${option.active ? 'active' : ''}`}
              onClick={() => {
                option.onSelect();
                setMobileFilterOpen(null);
              }}
              role="menuitemradio"
              aria-checked={option.active}
            >
              <span className="mobile-vault-filter-item-main">
                <span className="mobile-vault-filter-item-icon">{option.icon}</span>
                <span>{option.label}</span>
              </span>
              {option.active ? <Check size={14} /> : <span className="sort-menu-check-placeholder" />}
            </button>
          ))}
        </div>
      )}
    </div>
  );

  const createMenu = (
    <div className={`create-menu-wrap ${props.isMobileLayout ? 'mobile-fab-wrap' : 'desktop-create-menu-wrap'}`} ref={props.createMenuRef}>
      <button
        type="button"
        className={`btn btn-primary small ${props.isMobileLayout ? 'mobile-fab-trigger' : 'desktop-create-trigger'}`}
        aria-label={t('txt_add')}
        title={t('txt_add')}
        onClick={props.onToggleCreateMenu}
      >
        <Plus size={14} className="btn-icon" />
      </button>
      {props.createMenuOpen && (
        <div className="create-menu">
          {createTypeOptions.map((option) => (
            <button key={option.type} type="button" className="create-menu-item" onClick={() => props.onStartCreate(option.type)}>
              <CreateTypeIcon type={option.type} />
              <span>{option.label}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );

  return (
    <section className="list-col">
      <div className="list-toolbar-stack" ref={mobileFilterRef}>
        <div className={`list-head ${props.selectedCount > 0 ? 'selection-mode' : ''}`}>
          {props.selectedCount > 0 ? (
            <>
              {props.sidebarFilter.kind !== 'duplicates' && (
                <button type="button" className="btn btn-secondary small" disabled={!props.filteredCiphers.length} onClick={props.onSelectAll}>
                  <CheckCheck size={14} className="btn-icon" /> {t('txt_select_all')}
                </button>
              )}
              <button type="button" className="btn btn-secondary small" onClick={props.onClearSelection}>
                <X size={14} className="btn-icon" /> {t('txt_cancel')}
              </button>
              {props.sidebarFilter.kind === 'trash' && (
                <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkRestore}>
                  <RefreshCw size={14} className="btn-icon" /> {t('txt_restore')}
                </button>
              )}
              {props.sidebarFilter.kind === 'archive' && (
                <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkUnarchive}>
                  <RotateCcw size={14} className="btn-icon" /> {t('txt_unarchive')}
                </button>
              )}
              {props.sidebarFilter.kind !== 'trash' && props.sidebarFilter.kind !== 'archive' && props.sidebarFilter.kind !== 'duplicates' && (
                <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onBulkArchive}>
                  <Archive size={14} className="btn-icon" /> {t('txt_archive_selected')}
                </button>
              )}
              {props.sidebarFilter.kind !== 'trash' && props.sidebarFilter.kind !== 'archive' && props.sidebarFilter.kind !== 'duplicates' && (
                <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onOpenMove}>
                  <FolderInput size={14} className="btn-icon" /> {t('txt_move')}
                </button>
              )}
              <button type="button" className="btn btn-danger small" disabled={props.busy} onClick={props.onOpenBulkDelete}>
                <Trash2 size={14} className="btn-icon" /> {props.sidebarFilter.kind === 'trash' ? t('txt_delete_permanently') : t('txt_delete_selected')}
              </button>
            </>
          ) : (
            <>
              {props.sidebarFilter.kind === 'duplicates' && props.isMobileLayout ? (
                <div className="duplicate-mode-head-menu mobile-duplicate-toolbar">
                  <div className="mobile-duplicate-mode-select-wrap">
                    {renderMobileFilterMenu('duplicate', t('txt_duplicate_detection_mode'), duplicateModeSelected, <Copy size={14} />, duplicateModeOptions)}
                  </div>
                  <button type="button" className="btn btn-secondary small" onClick={props.onSelectUniqueFromDuplicates}>
                    <Check size={14} className="btn-icon" /> {t('txt_select_duplicate_items')}
                  </button>
                </div>
              ) : (
                <div className="search-input-wrap">
                  <input
                    className="search-input"
                    placeholder={t('txt_search_items_count', { count: props.totalCipherCount })}
                    value={props.searchInput}
                    onInput={(e) => props.onSearchInput((e.currentTarget as HTMLInputElement).value)}
                    onCompositionStart={props.onSearchCompositionStart}
                    onCompositionEnd={(e) => props.onSearchCompositionEnd((e.currentTarget as HTMLInputElement).value)}
                    onKeyDown={(e) => {
                      if (e.key !== 'Escape' || !props.searchInput) return;
                      e.preventDefault();
                      props.onClearSearch();
                    }}
                  />
                  {!!props.searchInput && (
                    <button
                      type="button"
                      className="search-clear-btn"
                      aria-label={t('txt_clear_search')}
                      title={t('txt_clear_search_esc')}
                      onClick={props.onClearSearch}
                    >
                      <X size={14} />
                    </button>
                  )}
                </div>
              )}
              {props.sidebarFilter.kind === 'duplicates' && !props.isMobileLayout && (
                <div className="duplicate-mode-head-menu">
                  {renderMobileFilterMenu('duplicate', t('txt_duplicate_detection_mode'), duplicateModeSelected, <Copy size={14} />, duplicateModeOptions)}
                </div>
              )}
              <div className="sort-menu-wrap" ref={props.sortMenuRef}>
                <button
                  type="button"
                  className={`btn btn-secondary small sort-trigger sort-trigger-labeled ${props.sortMenuOpen ? 'active' : ''}`}
                  aria-label={t('txt_sort')}
                  title={t('txt_sort')}
                  onClick={props.onToggleSortMenu}
                >
                  <ArrowUpDown size={14} className="btn-icon" /> <span>{t('txt_sort')}</span>
                </button>
                {props.sortMenuOpen && (
                  <div className="sort-menu">
                    {vaultSortOptions.map((option) => (
                      <button
                        key={option.value}
                        type="button"
                        className={`sort-menu-item ${props.sortMode === option.value ? 'active' : ''}`}
                        onClick={() => props.onSelectSortMode(option.value)}
                      >
                        <span>{option.label}</span>
                        {props.sortMode === option.value ? <Check size={14} /> : <span className="sort-menu-check-placeholder" />}
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <button type="button" className="btn btn-secondary small list-icon-btn" disabled={props.busy || props.loading} onClick={props.onSyncVault}>
                <RefreshCw size={14} className="btn-icon" /> {t('txt_sync_vault')}
              </button>
              {props.sidebarFilter.kind === 'duplicates' && !props.isMobileLayout ? (
                <button type="button" className="btn btn-secondary small" onClick={props.onSelectUniqueFromDuplicates}>
                  <Check size={14} className="btn-icon" /> {t('txt_select_duplicate_items')}
                </button>
              ) : (
                !props.isMobileLayout && props.sidebarFilter !== undefined && createMenu
              )}
            </>
          )}
        </div>
        {props.isMobileLayout && (
          <div className="mobile-vault-filter-row" aria-label={t('txt_filter')}>
            {renderMobileFilterMenu('menu', t('txt_menu'), menuFilterSelected, <LayoutGrid size={14} />, menuFilterOptions)}
            {renderMobileFilterMenu('type', t('txt_type'), typeFilterSelected, <Globe size={14} />, typeMobileFilterOptions)}
            {renderMobileFilterMenu('folder', t('txt_folder'), folderFilterSelected, <FolderIcon size={14} />, folderMobileFilterOptions)}
          </div>
        )}
      </div>
      {!props.selectedCount && props.isMobileLayout && props.sidebarFilter.kind !== 'duplicates' && typeof document !== 'undefined' && props.mobileFabVisible
        ? createPortal(createMenu, document.body)
        : null}
      <div className="list-panel" ref={props.listPanelRef} onScroll={(event) => props.onScroll((event.currentTarget as HTMLDivElement).scrollTop)}>
        {props.loading && !props.filteredCiphers.length && <LoadingState lines={7} compact />}
        {!props.loading && !!props.error && !props.filteredCiphers.length && (
          <div className="empty vault-error-state">
            <strong>{props.error}</strong>
            <button type="button" className="btn btn-secondary small" disabled={props.busy} onClick={props.onSyncVault}>
              {t('txt_retry_sync')}
            </button>
          </div>
        )}
        {!!props.filteredCiphers.length && (
          <div style={{ paddingTop: `${props.virtualRange.padTop}px`, paddingBottom: `${props.virtualRange.padBottom}px` }}>
            {props.visibleCiphers.map((cipher) => (
              <CipherListItem
                key={cipher.id}
                cipher={cipher}
                selected={props.selectedCipherId === cipher.id}
                checked={!!props.selectedMap[cipher.id]}
                duplicateGroupIndex={props.sidebarFilter.kind === 'duplicates' ? props.duplicateGroupIndexById.get(cipher.id) ?? null : null}
                subtitle={props.listSubtitle(cipher)}
                onToggleSelected={props.onToggleSelected}
                onSelectCipher={props.onSelectCipher}
              />
            ))}
          </div>
        )}
        {!props.loading && !props.error && !props.filteredCiphers.length && <div className="empty">{t('txt_no_items')}</div>}
      </div>
    </section>
  );
}
