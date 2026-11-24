import { useEffect, useMemo, useState } from 'preact/hooks';
import type { RefObject } from 'preact';
import {
  Archive,
  ArrowUpDown,
  BookUser,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  CreditCard,
  Folder as FolderIcon,
  FolderPlus,
  FolderX,
  Globe,
  IdCard,
  KeyRound,
  Landmark,
  LayoutGrid,
  Pencil,
  ShieldUser,
  ShieldCheck,
  Star,
  StickyNote,
  Trash2,
  X,
} from 'lucide-preact';
import { Link } from 'wouter';
import type { Folder } from '@/lib/types';
import { t } from '@/lib/i18n';
import { buildFolderTree, flattenFolderTree } from '@/lib/folder-tree';
import { getFolderSortOptions, type SidebarFilter, type VaultSortMode } from '@/components/vault/vault-page-helpers';

interface VaultSidebarProps {
  folders: Folder[];
  sidebarFilter: SidebarFilter;
  busy: boolean;
  isMobileLayout: boolean;
  mobileSidebarOpen: boolean;
  folderSortMode: VaultSortMode;
  folderSortMenuOpen: boolean;
  folderSortMenuRef: RefObject<HTMLDivElement>;
  onCloseMobileSidebar: () => void;
  onChangeFilter: (filter: SidebarFilter) => void;
  onOpenDeleteAllFolders: () => void;
  onOpenCreateFolder: (parent?: Folder) => void;
  onOpenRenameFolder: (folder: Folder) => void;
  onOpenDeleteFolder: (folder: Folder) => void;
  onToggleFolderSortMenu: () => void;
  onSelectFolderSortMode: (value: VaultSortMode) => void;
}

export default function VaultSidebar(props: VaultSidebarProps) {
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(() => new Set());
  const folderSortOptions = getFolderSortOptions();
  const nameCollator = useMemo(
    () => new Intl.Collator(undefined, { sensitivity: 'base', numeric: true }),
    []
  );
  const sortedFolders = useMemo(() => {
    const sorted = [...props.folders];
    sorted.sort((a, b) => {
      if (props.folderSortMode === 'edited') {
        const aTime = new Date(String(a.revisionDate || a.creationDate || '')).getTime();
        const bTime = new Date(String(b.revisionDate || b.creationDate || '')).getTime();
        const aValid = Number.isFinite(aTime);
        const bValid = Number.isFinite(bTime);
        if (aValid && bValid) {
          const diff = bTime - aTime;
          if (diff !== 0) return diff;
        }
        if (aValid !== bValid) return aValid ? -1 : 1;
      } else if (props.folderSortMode === 'created') {
        const aTime = new Date(String(a.creationDate || '')).getTime();
        const bTime = new Date(String(b.creationDate || '')).getTime();
        const aValid = Number.isFinite(aTime);
        const bValid = Number.isFinite(bTime);
        if (aValid && bValid) {
          const diff = bTime - aTime;
          if (diff !== 0) return diff;
        }
        if (aValid !== bValid) return aValid ? -1 : 1;
      }
      const nameDiff = nameCollator.compare(
        String(a.decName || a.name || ''), String(b.decName || b.name || '')
      );
      if (nameDiff !== 0) return nameDiff;
      return String(a.id || '').localeCompare(String(b.id || ''));
    });
    return sorted;
  }, [props.folders, props.folderSortMode, nameCollator]);

  const folderTree = useMemo(() => buildFolderTree(sortedFolders), [sortedFolders]);
  const folderRows = useMemo(() => flattenFolderTree(folderTree, collapsedIds), [folderTree, collapsedIds]);
  const selectedFolderId = props.sidebarFilter.kind === 'folder' ? props.sidebarFilter.folderId : null;
  useEffect(() => {
    // Reveal a selection made elsewhere (for example in the mobile filter).
    const allRows = flattenFolderTree(folderTree, new Set());
    const selectedIndex = allRows.findIndex((row) => row.folder.id === selectedFolderId);
    const ancestors = new Set<string>();
    if (selectedIndex >= 0) {
      let depth = allRows[selectedIndex].depth;
      for (let i = selectedIndex - 1; i >= 0 && depth > 0; i--) {
        if (allRows[i].depth < depth) {
          ancestors.add(allRows[i].folder.id);
          depth = allRows[i].depth;
        }
      }
    }
    const existingIds = new Set(allRows.map((row) => row.folder.id));
    setCollapsedIds((current) => {
      const next = new Set([...current].filter((id) => existingIds.has(id) && !ancestors.has(id)));
      return next.size === current.size ? current : next;
    });
  }, [folderTree, selectedFolderId]);

  function toggleFolder(id: string): void {
    setCollapsedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <aside className={`sidebar ${props.isMobileLayout ? 'mobile-sidebar-sheet' : ''} ${props.isMobileLayout && props.mobileSidebarOpen ? 'open' : ''}`}>
      {props.isMobileLayout && (
        <div className="mobile-sidebar-head">
          <div className="mobile-sidebar-title">{t('txt_folders')}</div>
          <button type="button" className="mobile-sidebar-close" onClick={props.onCloseMobileSidebar} aria-label={t('txt_close')}>
            <X size={16} />
          </button>
        </div>
      )}
      <div className="sidebar-block">
        <Link href="/security/password-health" className="tree-btn">
          <ShieldCheck size={14} className="tree-icon" /> <span className="tree-label">{t('nav_password_security')}</span>
        </Link>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'all' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'all' })}>
          <LayoutGrid size={14} className="tree-icon" /> <span className="tree-label">{t('txt_all_items')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'favorite' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'favorite' })}>
          <Star size={14} className="tree-icon" /> <span className="tree-label">{t('txt_favorites')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'archive' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'archive' })}>
          <Archive size={14} className="tree-icon" /> <span className="tree-label">{t('txt_archive')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'trash' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'trash' })}>
          <Trash2 size={14} className="tree-icon" /> <span className="tree-label">{t('txt_trash')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'duplicates' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'duplicates' })}>
          <Copy size={14} className="tree-icon" /> <span className="tree-label">{t('txt_duplicates')}</span>
        </button>
      </div>

      <div className="sidebar-block">
        <div className="sidebar-title">{t('txt_type')}</div>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'login' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'login' })}>
          <Globe size={14} className="tree-icon" /> <span className="tree-label">{t('txt_login')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'card' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'card' })}>
          <CreditCard size={14} className="tree-icon" /> <span className="tree-label">{t('txt_card')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'bank' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'bank' })}>
          <Landmark size={14} className="tree-icon" /> <span className="tree-label">{t('txt_bank_account')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'identity' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'identity' })}>
          <ShieldUser size={14} className="tree-icon" /> <span className="tree-label">{t('txt_identity')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'license' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'license' })}>
          <IdCard size={14} className="tree-icon" /> <span className="tree-label">{t('txt_drivers_license')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'passport' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'passport' })}>
          <BookUser size={14} className="tree-icon" /> <span className="tree-label">{t('txt_passport')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'note' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'note' })}>
          <StickyNote size={14} className="tree-icon" /> <span className="tree-label">{t('txt_note')}</span>
        </button>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'type' && props.sidebarFilter.value === 'ssh' ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'type', value: 'ssh' })}>
          <KeyRound size={14} className="tree-icon" /> <span className="tree-label">{t('txt_ssh_key')}</span>
        </button>
      </div>

      <div className="sidebar-block">
        <div className="sidebar-title-row">
          <div className="sidebar-title">{t('txt_folders')}</div>
          <div className="folder-title-actions">
            <div className="sort-menu-wrap" ref={props.folderSortMenuRef}>
              <button
                type="button"
                className={`folder-sort-btn ${props.folderSortMenuOpen ? 'active' : ''}`}
                title={t('txt_sort')}
                aria-label={t('txt_sort')}
                onClick={props.onToggleFolderSortMenu}
              >
                <ArrowUpDown size={13} />
              </button>
              {props.folderSortMenuOpen && (
                <div className="sort-menu">
                  {folderSortOptions.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      className={`sort-menu-item ${props.folderSortMode === option.value ? 'active' : ''}`}
                      onClick={() => props.onSelectFolderSortMode(option.value)}
                    >
                      <span>{option.label}</span>
                      {props.folderSortMode === option.value ? <Check size={14} /> : <span className="sort-menu-check-placeholder" />}
                    </button>
                  ))}
                </div>
              )}
            </div>
            <button
              type="button"
              className="folder-delete-btn"
              title={t('txt_delete_all_folders')}
              aria-label={t('txt_delete_all_folders')}
              disabled={props.busy || props.folders.length === 0}
              onClick={props.onOpenDeleteAllFolders}
            >
              <X size={14} />
            </button>
            <button type="button" className="folder-add-btn" title={t('txt_create_folder')} aria-label={t('txt_create_folder')} disabled={props.busy} onClick={() => props.onOpenCreateFolder()}>
              <FolderPlus size={14} />
            </button>
          </div>
        </div>
        <button type="button" className={`tree-btn ${props.sidebarFilter.kind === 'folder' && props.sidebarFilter.folderId === null ? 'active' : ''}`} onClick={() => props.onChangeFilter({ kind: 'folder', folderId: null })}>
          <FolderX size={14} className="tree-icon" /> <span className="tree-label">{t('txt_no_folder')}</span>
        </button>
        {folderRows.map(({ folder, label, children, depth }) => (
          <div key={folder.id} className="folder-row" style={{ paddingInlineStart: `${Math.min(depth, 8) * 12}px` }}>
            {children.length > 0 ? (
              <button
                type="button"
                className="folder-toggle-btn"
                title={t(collapsedIds.has(folder.id) ? 'txt_expand' : 'txt_collapse')}
                aria-label={`${t(collapsedIds.has(folder.id) ? 'txt_expand' : 'txt_collapse')} ${folder.decName || folder.name || folder.id}`}
                aria-expanded={!collapsedIds.has(folder.id)}
                onClick={() => toggleFolder(folder.id)}
              >
                {collapsedIds.has(folder.id) ? <ChevronRight size={14} /> : <ChevronDown size={14} />}
              </button>
            ) : <span className="folder-toggle-spacer" />}
            <button
              type="button"
              className={`tree-btn ${props.sidebarFilter.kind === 'folder' && props.sidebarFilter.folderId === folder.id ? 'active' : ''}`}
              onClick={() => props.onChangeFilter({ kind: 'folder', folderId: folder.id })}
            >
              <FolderIcon size={14} className="tree-icon" />
              <span className="tree-label" title={folder.decName || folder.name || folder.id}>
                {label}
              </span>
            </button>
            <button
              type="button"
              className="folder-delete-btn folder-edit-btn"
              title={t('txt_create_subfolder')}
              aria-label={`${t('txt_create_subfolder')} ${folder.decName || folder.name || folder.id}`}
              disabled={props.busy}
              onClick={() => {
                setCollapsedIds((current) => {
                  if (!current.has(folder.id)) return current;
                  const next = new Set(current);
                  next.delete(folder.id);
                  return next;
                });
                props.onOpenCreateFolder(folder);
              }}
            >
              <FolderPlus size={12} />
            </button>
            <button
              type="button"
              className="folder-delete-btn folder-edit-btn"
              title={t('txt_edit')}
              aria-label={t('txt_edit')}
              disabled={props.busy}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                props.onOpenRenameFolder(folder);
              }}
            >
              <Pencil size={12} />
            </button>
            <button
              type="button"
              className="folder-delete-btn"
              title={t('txt_delete')}
              aria-label={t('txt_delete')}
              disabled={props.busy}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                props.onOpenDeleteFolder(folder);
              }}
            >
              <X size={12} />
            </button>
          </div>
        ))}
      </div>
    </aside>
  );
}
