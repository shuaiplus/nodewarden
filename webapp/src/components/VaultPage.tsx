import { useCallback, useEffect, useMemo, useRef, useState } from 'preact/hooks';
import LoadingState from '@/components/LoadingState';
import VaultDialogs from '@/components/vault/VaultDialogs';
import VaultDetailView from '@/components/vault/VaultDetailView';
import VaultEditor from '@/components/vault/VaultEditor';
import VaultListPanel from '@/components/vault/VaultListPanel';
import VaultSidebar from '@/components/vault/VaultSidebar';
import {
  MOBILE_LAYOUT_QUERY,
  VAULT_LIST_OVERSCAN,
  VAULT_LIST_ROW_HEIGHT,
  cardListSubtitle,
  FOLDER_SORT_STORAGE_KEY,
  VAULT_SORT_STORAGE_KEY,
  bankAccountListSubtitle,
  cipherTypeKey,
  cipherTypeLabel,
  createEmptyDraft,
  creationTimeValue,
  draftFromCipher,
  driversLicenseListSubtitle,
  buildCipherDuplicateSignatures,
  firstCipherUri,
  firstPasskeyCreationTime,
  isCipherVisibleInArchive,
  isCipherVisibleInNormalVault,
  isCipherVisibleInTrash,
  passportListSubtitle,
  sortTimeValue,
  type DuplicateDetectionMode,
  type SidebarFilter,
  type VaultSortMode,
} from '@/components/vault/vault-page-helpers';
import { calcTotpNow, type TotpCodeResult } from '@/lib/crypto';
import { computeSshFingerprint, generateDefaultSshKeyMaterial } from '@/lib/ssh';
import { ChevronLeft } from 'lucide-preact';
import type { Cipher, CustomFieldType, Folder, VaultDraft, VaultDraftField } from '@/lib/types';
import { t } from '@/lib/i18n';

interface VaultPageProps {
  ciphers: Cipher[];
  folders: Folder[];
  loading: boolean;
  error: string;
  emailForReprompt: string;
  onRefresh: () => Promise<void>;
  onCreate: (draft: VaultDraft, attachments?: File[]) => Promise<void>;
  onUpdate: (cipher: Cipher, draft: VaultDraft, options?: { addFiles?: File[]; removeAttachmentIds?: string[] }) => Promise<void>;
  onDelete: (cipher: Cipher) => Promise<void>;
  onArchive: (cipher: Cipher) => Promise<void>;
  onUnarchive: (cipher: Cipher) => Promise<void>;
  onRestore: (ids: string[]) => Promise<void>;
  onBulkDelete: (ids: string[]) => Promise<void>;
  onBulkPermanentDelete: (ids: string[]) => Promise<void>;
  onBulkRestore: (ids: string[]) => Promise<void>;
  onBulkArchive: (ids: string[]) => Promise<void>;
  onBulkUnarchive: (ids: string[]) => Promise<void>;
  onBulkMove: (ids: string[], folderId: string | null) => Promise<void>;
  onVerifyMasterPassword: (email: string, password: string) => Promise<void>;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
  onCreateFolder: (name: string) => Promise<void>;
  onRenameFolder: (folderId: string, name: string) => Promise<void>;
  onDeleteFolder: (folderId: string) => Promise<void>;
  onBulkDeleteFolders: (folderIds: string[]) => Promise<void>;
  onDownloadAttachment: (cipher: Cipher, attachmentId: string) => Promise<void>;
  downloadingAttachmentKey: string;
  attachmentDownloadPercent: number | null;
  uploadingAttachmentName: string;
  attachmentUploadPercent: number | null;
  mobileSidebarToggleKey: number;
}


export default function VaultPage(props: VaultPageProps) {
  const getInitialIsMobileLayout = () =>
    typeof window !== 'undefined' && typeof window.matchMedia === 'function'
      ? window.matchMedia(MOBILE_LAYOUT_QUERY).matches
      : false;
  const [searchInput, setSearchInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchComposing, setSearchComposing] = useState(false);
  const [sortMode, setSortMode] = useState<VaultSortMode>('edited');
  const [sortMenuOpen, setSortMenuOpen] = useState(false);
  const [folderSortMode, setFolderSortMode] = useState<VaultSortMode>('name');
  const [folderSortMenuOpen, setFolderSortMenuOpen] = useState(false);
  const [duplicateMode, setDuplicateMode] = useState<DuplicateDetectionMode>('exact');
  const [sidebarFilter, setSidebarFilter] = useState<SidebarFilter>({ kind: 'all' });
  const [selectedCipherId, setSelectedCipherId] = useState('');
  const [selectedMap, setSelectedMap] = useState<Record<string, boolean>>({});
  const [showPassword, setShowPassword] = useState(false);
  const [createMenuOpen, setCreateMenuOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [draft, setDraft] = useState<VaultDraft | null>(null);
  const [fieldModalOpen, setFieldModalOpen] = useState(false);
  const [fieldType, setFieldType] = useState<CustomFieldType>(0);
  const [fieldLabel, setFieldLabel] = useState('');
  const [fieldValue, setFieldValue] = useState('');
  const [localError, setLocalError] = useState('');
  const [pendingArchive, setPendingArchive] = useState<Cipher | null>(null);
  const [pendingDelete, setPendingDelete] = useState<Cipher | null>(null);
  const [bulkArchiveOpen, setBulkArchiveOpen] = useState(false);
  const [bulkDeleteOpen, setBulkDeleteOpen] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [moveFolderId, setMoveFolderId] = useState('__none__');
  const [createFolderOpen, setCreateFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [pendingRenameFolder, setPendingRenameFolder] = useState<Folder | null>(null);
  const [renameFolderName, setRenameFolderName] = useState('');
  const [pendingDeleteFolder, setPendingDeleteFolder] = useState<Folder | null>(null);
  const [deleteAllFoldersOpen, setDeleteAllFoldersOpen] = useState(false);
  const [totpLive, setTotpLive] = useState<TotpCodeResult | null>(null);
  const [hiddenFieldVisibleMap, setHiddenFieldVisibleMap] = useState<Record<number, boolean>>({});
  const [attachmentQueue, setAttachmentQueue] = useState<File[]>([]);
  const [removedAttachmentIds, setRemovedAttachmentIds] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);
  const [repromptOpen, setRepromptOpen] = useState(false);
  const [repromptPassword, setRepromptPassword] = useState('');
  const [repromptApprovedCipherId, setRepromptApprovedCipherId] = useState<string | null>(null);
  const [pendingDeletePasskeyIndex, setPendingDeletePasskeyIndex] = useState<number | null>(null);
  const [isMobileLayout, setIsMobileLayout] = useState(getInitialIsMobileLayout);
  const [mobilePanel, setMobilePanel] = useState<'list' | 'detail' | 'edit'>('list');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const createMenuRef = useRef<HTMLDivElement | null>(null);
  const sortMenuRef = useRef<HTMLDivElement | null>(null);
  const folderSortMenuRef = useRef<HTMLDivElement | null>(null);
  const attachmentInputRef = useRef<HTMLInputElement | null>(null);
  const listPanelRef = useRef<HTMLDivElement | null>(null);
  const mobileSidebarToggleKeyRef = useRef(props.mobileSidebarToggleKey);

  const sshSeedTicketRef = useRef(0);
  const sshFingerprintTicketRef = useRef(0);
  const listScrollBucketRef = useRef(0);
  const [listScrollTop, setListScrollTop] = useState(0);
  const [listViewportHeight, setListViewportHeight] = useState(0);

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
    const onQuickAdd = () => {
      startCreate(1);
    };
    window.addEventListener('nodewarden:add-item', onQuickAdd);
    return () => window.removeEventListener('nodewarden:add-item', onQuickAdd);
  }, []);

  useEffect(() => {
    try {
      const saved = String(localStorage.getItem(VAULT_SORT_STORAGE_KEY) || '').trim() as VaultSortMode;
      if (saved === 'edited' || saved === 'created' || saved === 'name') {
        setSortMode(saved);
      }
    } catch {
      // ignore storage read failures
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(VAULT_SORT_STORAGE_KEY, sortMode);
    } catch {
      // ignore storage write failures
    }
  }, [sortMode]);

  useEffect(() => {
    try {
      const saved = String(localStorage.getItem(FOLDER_SORT_STORAGE_KEY) || '').trim() as VaultSortMode;
      if (saved === 'edited' || saved === 'created' || saved === 'name') {
        setFolderSortMode(saved);
      }
    } catch {
      // ignore storage read failures
    }
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(FOLDER_SORT_STORAGE_KEY, folderSortMode);
    } catch {
      // ignore storage write failures
    }
  }, [folderSortMode]);

  useEffect(() => {
    const node = listPanelRef.current;
    if (!node) return;
    const updateSize = () => setListViewportHeight(node.clientHeight || 0);
    updateSize();
    const resizeObserver = new ResizeObserver(updateSize);
    resizeObserver.observe(node);
    return () => resizeObserver.disconnect();
  }, []);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!createMenuOpen) return;
      const target = event.target as Node | null;
      if (createMenuRef.current && target && !createMenuRef.current.contains(target)) {
        setCreateMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setCreateMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [createMenuOpen]);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!sortMenuOpen) return;
      const target = event.target as Node | null;
      if (sortMenuRef.current && target && !sortMenuRef.current.contains(target)) {
        setSortMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setSortMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [sortMenuOpen]);

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!folderSortMenuOpen) return;
      const target = event.target as Node | null;
      if (folderSortMenuRef.current && target && !folderSortMenuRef.current.contains(target)) {
        setFolderSortMenuOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setFolderSortMenuOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [folderSortMenuOpen]);

  useEffect(() => {
    setRepromptApprovedCipherId(null);
    setRepromptPassword('');
    setRepromptOpen(false);
    setShowPassword(false);
    setHiddenFieldVisibleMap({});
  }, [selectedCipherId]);

  useEffect(() => {
    if (!isMobileLayout) {
      setMobilePanel('list');
      setMobileSidebarOpen(false);
      return;
    }
    if (isEditing) {
      setMobilePanel('edit');
    } else if (!selectedCipherId) {
      setMobilePanel('list');
    }
  }, [isMobileLayout, isEditing, selectedCipherId]);

  useEffect(() => {
    if (searchComposing) return;
    const timer = window.setTimeout(() => setSearchQuery(searchInput.trim().toLowerCase()), 90);
    return () => window.clearTimeout(timer);
  }, [searchInput, searchComposing]);

  useEffect(() => {
    if (!isEditing || !draft || draft.type !== 5) return;
    void recalculateSshFingerprint(draft.sshPublicKey);
  }, [isEditing, draft?.id, draft?.type]);

  const cipherMetaById = useMemo(() => {
    const meta = new Map<string, {
      name: string;
      searchText: string;
      firstUri: string;
      typeKey: string;
      sortTime: number;
      creationTime: number;
    }>();
    for (const cipher of props.ciphers) {
      const name = String(cipher.decName || cipher.name || '');
      const username = String(cipher.login?.decUsername || '');
      const uri = firstCipherUri(cipher);
      const typedText = [
        cipher.bankAccount?.decBankName,
        cipher.bankAccount?.decNameOnAccount,
        cipher.bankAccount?.decAccountNumber,
        cipher.driversLicense?.decLicenseNumber,
        cipher.driversLicense?.decFirstName,
        cipher.driversLicense?.decLastName,
        cipher.passport?.decPassportNumber,
        cipher.passport?.decGivenName,
        cipher.passport?.decSurname,
      ].filter(Boolean).join('\n');
      const cipherId = String(cipher.id || '').trim();
      meta.set(cipher.id, {
        name,
        searchText: `${cipherId}\n${cipherId.replace(/-/g, '')}\n${name}\n${username}\n${uri}\n${typedText}`.toLowerCase(),
        firstUri: uri,
        typeKey: cipherTypeKey(Number(cipher.type || 1)),
        sortTime: sortTimeValue(cipher),
        creationTime: creationTimeValue(cipher),
      });
    }
    return meta;
  }, [props.ciphers]);

  const cipherById = useMemo(() => {
    const map = new Map<string, Cipher>();
    for (const cipher of props.ciphers) map.set(cipher.id, cipher);
    return map;
  }, [props.ciphers]);

  const folderById = useMemo(() => {
    const map = new Map<string, Folder>();
    for (const folder of props.folders) map.set(folder.id, folder);
    return map;
  }, [props.folders]);

  const nameCollator = useMemo(
    () => new Intl.Collator(undefined, { sensitivity: 'base', numeric: true }),
    []
  );

  const duplicateSignatureInfo = useMemo(() => {
    if (sidebarFilter.kind !== 'duplicates') return null;
    const byId = new Map<string, string[]>();
    const counts = new Map<string, number>();
    for (const cipher of props.ciphers) {
      if (!isCipherVisibleInNormalVault(cipher)) continue;
      const signatures = Array.from(new Set(buildCipherDuplicateSignatures(cipher, duplicateMode)));
      byId.set(cipher.id, signatures);
      for (const signature of signatures) {
        counts.set(signature, (counts.get(signature) || 0) + 1);
      }
    }
    return { byId, counts };
  }, [props.ciphers, sidebarFilter.kind, duplicateMode]);

  const duplicateGroupIndexById = useMemo(() => {
    if (!duplicateSignatureInfo) return new Map<string, number>();
    const groupKeyById = new Map<string, string>();
    const groupKeys = new Set<string>();
    for (const cipher of props.ciphers) {
      const groupKey = (duplicateSignatureInfo.byId.get(cipher.id) || [])
        .filter((signature) => (duplicateSignatureInfo.counts.get(signature) || 0) >= 2)
        .sort()[0];
      if (!groupKey) continue;
      groupKeyById.set(cipher.id, groupKey);
      groupKeys.add(groupKey);
    }
    const groupIndexByKey = new Map<string, number>();
    Array.from(groupKeys).sort().forEach((groupKey, index) => {
      groupIndexByKey.set(groupKey, index % 64);
    });
    const byId = new Map<string, number>();
    for (const [cipherId, groupKey] of groupKeyById.entries()) {
      byId.set(cipherId, groupIndexByKey.get(groupKey) || 0);
    }
    return byId;
  }, [props.ciphers, duplicateSignatureInfo]);

  const filteredCiphers = useMemo(() => {
    const next = props.ciphers.filter((cipher) => {
      const meta = cipherMetaById.get(cipher.id);
      if (sidebarFilter.kind === 'trash') {
        if (!isCipherVisibleInTrash(cipher)) return false;
      } else if (sidebarFilter.kind === 'archive') {
        if (!isCipherVisibleInArchive(cipher)) return false;
      } else {
        if (!isCipherVisibleInNormalVault(cipher)) return false;
        if (sidebarFilter.kind === 'duplicates') {
          const signatures = duplicateSignatureInfo?.byId.get(cipher.id) || [];
          if (!signatures.some((signature) => (duplicateSignatureInfo?.counts.get(signature) || 0) >= 2)) {
            return false;
          }
        }
        if (sidebarFilter.kind === 'favorite' && !cipher.favorite) return false;
        if (sidebarFilter.kind === 'type' && meta?.typeKey !== sidebarFilter.value) return false;
        if (sidebarFilter.kind === 'folder') {
          if (sidebarFilter.folderId === null) {
            if (cipher.folderId) return false;
          } else if (cipher.folderId !== sidebarFilter.folderId) {
            return false;
          }
        }
      }
      if (!searchQuery) return true;
      return !!meta?.searchText.includes(searchQuery);
    });

    // Pre-compute group min name for duplicates group ordering
    const groupMinName = new Map<string, string>();
    if (sidebarFilter.kind === 'duplicates' && duplicateSignatureInfo) {
      for (const cipher of next) {
        const gk = (duplicateSignatureInfo.byId.get(cipher.id) || [])
          .filter(s => (duplicateSignatureInfo.counts.get(s) || 0) >= 2)
          .sort()[0] || '';
        if (!gk) continue;
        const name = cipherMetaById.get(cipher.id)?.name || '';
        const cur = groupMinName.get(gk);
        if (!cur || nameCollator.compare(name, cur) < 0) groupMinName.set(gk, name);
      }
    }

    next.sort((a, b) => {
      // Duplicates view: group by color, sort A-Z within each group
      if (sidebarFilter.kind === 'duplicates' && duplicateSignatureInfo) {
        const gk = (id: string) => (duplicateSignatureInfo.byId.get(id) || [])
          .filter(s => (duplicateSignatureInfo.counts.get(s) || 0) >= 2)
          .sort()[0] || '';
        const gA = gk(a.id), gB = gk(b.id);
        if (gA !== gB) return !gA ? 1 : !gB ? -1 : nameCollator.compare(
          groupMinName.get(gA) || '', groupMinName.get(gB) || ''
        ) || (gA < gB ? -1 : 1);
        return nameCollator.compare(
          cipherMetaById.get(a.id)?.name || '',
          cipherMetaById.get(b.id)?.name || ''
        ) || String(a.id || '').localeCompare(String(b.id || ''));
      }

      const metaA = cipherMetaById.get(a.id);
      const metaB = cipherMetaById.get(b.id);
      if (sortMode === 'edited') {
        const diff = (metaB?.sortTime || 0) - (metaA?.sortTime || 0);
        if (diff !== 0) return diff;
      } else if (sortMode === 'created') {
        const diff = (metaB?.creationTime || 0) - (metaA?.creationTime || 0);
        if (diff !== 0) return diff;
      } else {
        const nameDiff = nameCollator.compare(metaA?.name || '', metaB?.name || '');
        if (nameDiff !== 0) return nameDiff;
      }

      return String(a.id || '').localeCompare(String(b.id || ''));
    });

    return next;
  }, [props.ciphers, cipherMetaById, sidebarFilter, searchQuery, sortMode, duplicateSignatureInfo, nameCollator]);

  const filteredCipherIds = useMemo(() => {
    const ids = new Set<string>();
    for (const cipher of filteredCiphers) ids.add(cipher.id);
    return ids;
  }, [filteredCiphers]);

  const sidebarFilterKey = useMemo(() => {
    if (sidebarFilter.kind === 'folder') return `folder:${sidebarFilter.folderId ?? 'none'}`;
    if (sidebarFilter.kind === 'type') return `type:${sidebarFilter.value}`;
    if (sidebarFilter.kind === 'duplicates') return `duplicates:${duplicateMode}`;
    return sidebarFilter.kind;
  }, [sidebarFilter, duplicateMode]);

  useEffect(() => {
    setListScrollTop(0);
    listScrollBucketRef.current = 0;
    listPanelRef.current?.scrollTo({ top: 0 });
  }, [searchQuery, sortMode, sidebarFilterKey]);

  useEffect(() => {
    if (sidebarFilter.kind === 'duplicates' && sortMode !== 'name') {
      setSortMode('name');
    }
  }, [sidebarFilter.kind, sortMode]);

  useEffect(() => {
    if (sidebarFilter.kind === 'duplicates') setSelectedMap({});
  }, [sidebarFilter.kind, duplicateMode]);

  useEffect(() => {
    if (isCreating) return;
    if (!filteredCiphers.length) {
      if (selectedCipherId) setSelectedCipherId('');
      return;
    }
    if (!selectedCipherId || !filteredCipherIds.has(selectedCipherId)) {
      setSelectedCipherId(filteredCiphers[0].id);
    }
  }, [filteredCiphers, filteredCipherIds, selectedCipherId, isCreating]);

  const selectedCipher = useMemo(() => cipherById.get(selectedCipherId) || null, [cipherById, selectedCipherId]);
  const virtualRange = useMemo(() => {
    if (!filteredCiphers.length) {
      return { start: 0, end: 0, padTop: 0, padBottom: 0 };
    }
    const viewport = Math.max(listViewportHeight, VAULT_LIST_ROW_HEIGHT * 8);
    const visibleCount = Math.ceil(viewport / VAULT_LIST_ROW_HEIGHT);
    const start = Math.max(0, Math.floor(listScrollTop / VAULT_LIST_ROW_HEIGHT) - VAULT_LIST_OVERSCAN);
    const end = Math.min(filteredCiphers.length, start + visibleCount + VAULT_LIST_OVERSCAN * 2);
    return {
      start,
      end,
      padTop: start * VAULT_LIST_ROW_HEIGHT,
      padBottom: Math.max(0, (filteredCiphers.length - end) * VAULT_LIST_ROW_HEIGHT),
    };
  }, [filteredCiphers.length, listScrollTop, listViewportHeight]);
  const visibleCiphers = useMemo(
    () => filteredCiphers.slice(virtualRange.start, virtualRange.end),
    [filteredCiphers, virtualRange.start, virtualRange.end]
  );
  const selectedAttachments = useMemo(
    () => (Array.isArray(selectedCipher?.attachments) ? selectedCipher.attachments : []),
    [selectedCipher]
  );
  const editExistingAttachments = useMemo(
    () =>
      selectedAttachments.filter((attachment) => {
        const id = String(attachment?.id || '').trim();
        return !!id;
      }),
    [selectedAttachments]
  );
  const removedAttachmentCount = useMemo(() => Object.values(removedAttachmentIds).filter(Boolean).length, [removedAttachmentIds]);

  useEffect(() => {
    const raw = selectedCipher?.login?.decTotp || '';
    if (!raw) {
      setTotpLive(null);
      return;
    }
    let stopped = false;
    let timer = 0;
    const tick = async () => {
      try {
        const now = await calcTotpNow(raw);
        if (!stopped) setTotpLive(now);
      } catch {
        if (!stopped) setTotpLive(null);
      }
    };
    void tick();
    timer = window.setInterval(() => void tick(), 1000);
    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [selectedCipher?.id, selectedCipher?.login?.decTotp]);

  const selectedCount = useMemo(
    () => Object.values(selectedMap).reduce((sum, v) => sum + (v ? 1 : 0), 0),
    [selectedMap]
  );
  const totalCipherCount = filteredCiphers.length;

const folderName = useCallback((id: string | null | undefined): string => {
  if (!id) return t('txt_no_folder');
  const folder = folderById.get(id);
  return folder?.decName || folder?.name || id;
}, [folderById]);

  const listSubtitle = useCallback((cipher: Cipher): string => {
    if (Number(cipher.type || 1) === 1) {
      return cipher.login?.decUsername || cipherMetaById.get(cipher.id)?.firstUri || '';
    }
    if (Number(cipher.type || 1) === 3) {
      return cardListSubtitle(cipher);
    }
    if (Number(cipher.type || 1) === 6) return bankAccountListSubtitle(cipher);
    if (Number(cipher.type || 1) === 7) return driversLicenseListSubtitle(cipher);
    if (Number(cipher.type || 1) === 8) return passportListSubtitle(cipher);
    return cipherTypeLabel(Number(cipher.type || 1));
  }, [cipherMetaById]);

  const handleListScroll = useCallback((top: number): void => {
    const bucket = Math.floor(Math.max(0, top) / VAULT_LIST_ROW_HEIGHT);
    if (bucket === listScrollBucketRef.current) return;
    listScrollBucketRef.current = bucket;
    setListScrollTop(top);
  }, []);

  const startCreate = useCallback((type: number): void => {
    setDraft(createEmptyDraft(type));
    setIsCreating(true);
    setIsEditing(true);
    setCreateMenuOpen(false);
    setSelectedCipherId('');
    setShowPassword(false);
    setHiddenFieldVisibleMap({});
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
    if (type === 5) void seedSshDefaults();
  }, [isMobileLayout]);

  const startEdit = useCallback((): void => {
    if (!selectedCipher) return;
    setDraft(draftFromCipher(selectedCipher));
    setIsCreating(false);
    setIsEditing(true);
    setShowPassword(false);
    setHiddenFieldVisibleMap({});
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    if (isMobileLayout) setMobilePanel('edit');
    setMobileSidebarOpen(false);
  }, [selectedCipher, isMobileLayout]);

  const cancelEdit = useCallback((): void => {
    const returnToDetail = isMobileLayout && !isCreating && !!selectedCipher;
    setDraft(null);
    setIsEditing(false);
    setIsCreating(false);
    setShowPassword(false);
    setHiddenFieldVisibleMap({});
    setLocalError('');
    setAttachmentQueue([]);
    setRemovedAttachmentIds({});
    setPendingDeletePasskeyIndex(null);
    if (isMobileLayout) setMobilePanel(returnToDetail ? 'detail' : 'list');
  }, [isMobileLayout, isCreating, selectedCipher]);

  const updateDraft = useCallback((patch: Partial<VaultDraft>): void => {
    setDraft((prev) => (prev ? { ...prev, ...patch } : prev));
  }, []);

  function confirmDeleteLoginPasskey(): void {
    if (pendingDeletePasskeyIndex == null) return;
    setDraft((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        loginFido2Credentials: prev.loginFido2Credentials.filter((_, index) => index !== pendingDeletePasskeyIndex),
      };
    });
    setPendingDeletePasskeyIndex(null);
  }

  async function seedSshDefaults(force = false): Promise<void> {
    const ticket = ++sshSeedTicketRef.current;
    try {
      const generated = await generateDefaultSshKeyMaterial();
      if (ticket !== sshSeedTicketRef.current) return;
      setDraft((prev) => {
        if (!prev || prev.type !== 5) return prev;
        if (!force && (prev.sshPrivateKey.trim() || prev.sshPublicKey.trim())) return prev;
        return {
          ...prev,
          sshPrivateKey: generated.privateKey,
          sshPublicKey: generated.publicKey,
          sshFingerprint: generated.fingerprint,
        };
      });
    } catch {
      // Browser may not support Ed25519 generation; user can still paste keys manually.
    }
  }

  async function recalculateSshFingerprint(publicKey: string): Promise<void> {
    const ticket = ++sshFingerprintTicketRef.current;
    const fingerprint = await computeSshFingerprint(publicKey);
    if (ticket !== sshFingerprintTicketRef.current) return;
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      if (prev.sshPublicKey !== publicKey) return prev;
      if (prev.sshFingerprint === fingerprint) return prev;
      return { ...prev, sshFingerprint: fingerprint };
    });
  }

  function updateSshPublicKey(nextValue: string): void {
    setDraft((prev) => {
      if (!prev || prev.type !== 5) return prev;
      return { ...prev, sshPublicKey: nextValue };
    });
    void recalculateSshFingerprint(nextValue);
  }

  function updateDraftCustomFields(nextFields: VaultDraftField[]): void {
    setDraft((prev) => (prev ? { ...prev, customFields: nextFields } : prev));
  }

  function patchDraftCustomField(index: number, patch: Partial<VaultDraftField>): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.customFields];
      next[index] = { ...next[index], ...patch };
      return { ...prev, customFields: next };
    });
  }

  function updateDraftLoginUri(index: number, value: string): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.loginUris];
      next[index] = { ...(next[index] || { uri: '', match: null }), uri: value };
      return { ...prev, loginUris: next };
    });
  }

  function updateDraftLoginUriMatch(index: number, value: number | null): void {
    setDraft((prev) => {
      if (!prev) return prev;
      const next = [...prev.loginUris];
      next[index] = { ...(next[index] || { uri: '', match: null }), match: value };
      return { ...prev, loginUris: next };
    });
  }

  function reorderDraftLoginUri(fromIndex: number, toIndex: number): void {
    setDraft((prev) => {
      if (!prev) return prev;
      if (fromIndex < 0 || toIndex < 0 || fromIndex >= prev.loginUris.length || toIndex >= prev.loginUris.length || fromIndex === toIndex) {
        return prev;
      }
      const next = [...prev.loginUris];
      const [moved] = next.splice(fromIndex, 1);
      if (!moved) return prev;
      next.splice(toIndex, 0, moved);
      return { ...prev, loginUris: next };
    });
  }

  function queueAttachmentFiles(list: FileList | null): void {
    if (!list || !list.length) return;
    const next = Array.from(list).filter((file) => file && file.size >= 0);
    if (!next.length) return;
    setAttachmentQueue((prev) => [...prev, ...next]);
  }

  function removeQueuedAttachment(index: number): void {
    setAttachmentQueue((prev) => prev.filter((_, i) => i !== index));
  }

  function toggleExistingAttachmentRemoval(attachmentId: string): void {
    const id = String(attachmentId || '').trim();
    if (!id) return;
    setRemovedAttachmentIds((prev) => {
      const next = { ...prev };
      if (next[id]) delete next[id];
      else next[id] = true;
      return next;
    });
  }

  async function saveDraft(): Promise<void> {
    if (!draft) return;
    let nextDraft = draft;
    if (nextDraft.type === 5) {
      const computedFingerprint = await computeSshFingerprint(nextDraft.sshPublicKey);
      if (computedFingerprint !== nextDraft.sshFingerprint) {
        nextDraft = { ...nextDraft, sshFingerprint: computedFingerprint };
        setDraft(nextDraft);
      }
    }
    if (!nextDraft.name.trim()) {
      setLocalError(t('txt_item_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      if (isCreating) {
        await props.onCreate(nextDraft, attachmentQueue);
      } else if (selectedCipher) {
        const removeAttachmentIds = Object.keys(removedAttachmentIds).filter((id) => !!removedAttachmentIds[id]);
        await props.onUpdate(selectedCipher, nextDraft, {
          addFiles: attachmentQueue,
          removeAttachmentIds,
        });
      }
      setIsCreating(false);
      setIsEditing(false);
      setDraft(null);
      setLocalError('');
      setAttachmentQueue([]);
      setRemovedAttachmentIds({});
      if (isMobileLayout) setMobilePanel('detail');
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function deleteSelected(): Promise<void> {
    if (!pendingDelete) return;
    setBusy(true);
    try {
      await props.onDelete(pendingDelete);
      setPendingDelete(null);
      cancelEdit();
      if (isMobileLayout) setMobilePanel('list');
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function handleRestoreSelected(cipher: Cipher): Promise<void> {
    setBusy(true);
    try {
      await props.onRestore([cipher.id]);
      if (isMobileLayout && selectedCipherId === cipher.id) {
        setMobilePanel('list');
      }
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkDelete(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      if (sidebarFilter.kind === 'trash') {
        await props.onBulkPermanentDelete(ids);
      } else {
        await props.onBulkDelete(ids);
      }
      setSelectedMap({});
      setBulkDeleteOpen(false);
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkMove(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    const folderId = moveFolderId === '__none__' ? null : moveFolderId;
    setBusy(true);
    try {
      await props.onBulkMove(ids, folderId);
      setSelectedMap({});
      setMoveOpen(false);
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function syncVault(): Promise<void> {
    setBusy(true);
    try {
      await props.onRefresh();
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function verifyReprompt(): Promise<void> {
    if (!selectedCipher) return;
    if (!repromptPassword) {
      props.onNotify('error', t('txt_master_password_is_required_2'));
      return;
    }
    setBusy(true);
    try {
      await props.onVerifyMasterPassword(props.emailForReprompt, repromptPassword);
      setRepromptApprovedCipherId(selectedCipher.id);
      setRepromptOpen(false);
      setRepromptPassword('');
    } catch (error) {
      props.onNotify('error', error instanceof Error ? error.message : t('txt_unlock_failed'));
    } finally {
      setBusy(false);
    }
  }

  async function confirmCreateFolder(): Promise<void> {
    if (!newFolderName.trim()) {
      props.onNotify('error', t('txt_folder_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      await props.onCreateFolder(newFolderName);
      setCreateFolderOpen(false);
      setNewFolderName('');
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteFolder(): Promise<void> {
    if (!pendingDeleteFolder) return;
    setBusy(true);
    try {
      await props.onDeleteFolder(pendingDeleteFolder.id);
      if (sidebarFilter.kind === 'folder' && sidebarFilter.folderId === pendingDeleteFolder.id) {
        setSidebarFilter({ kind: 'all' });
      }
      setPendingDeleteFolder(null);
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmRenameFolder(): Promise<void> {
    if (!pendingRenameFolder) return;
    const nextName = renameFolderName.trim();
    if (!nextName) {
      props.onNotify('error', t('txt_folder_name_is_required'));
      return;
    }
    setBusy(true);
    try {
      await props.onRenameFolder(pendingRenameFolder.id, nextName);
      setPendingRenameFolder(null);
      setRenameFolderName('');
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkRestore(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkRestore(ids);
      setSelectedMap({});
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmArchiveSelected(): Promise<void> {
    if (!pendingArchive) return;
    setBusy(true);
    try {
      await props.onArchive(pendingArchive);
      setPendingArchive(null);
      if (isMobileLayout && selectedCipherId === pendingArchive.id) {
        setMobilePanel('list');
      }
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function handleUnarchiveSelected(cipher: Cipher): Promise<void> {
    setBusy(true);
    try {
      await props.onBulkUnarchive([cipher.id]);
      setSelectedMap((prev) => {
        const next = { ...prev };
        delete next[cipher.id];
        return next;
      });
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkArchive(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkArchive(ids);
      setSelectedMap({});
      setBulkArchiveOpen(false);
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmBulkUnarchive(): Promise<void> {
    const ids = Object.entries(selectedMap)
      .filter(([, selected]) => selected)
      .map(([id]) => id);
    if (!ids.length) return;
    setBusy(true);
    try {
      await props.onBulkUnarchive(ids);
      setSelectedMap({});
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  async function confirmDeleteAllFolders(): Promise<void> {
    if (!props.folders.length) return;
    setBusy(true);
    try {
      await props.onBulkDeleteFolders(props.folders.map((folder) => folder.id));
      if (sidebarFilter.kind === 'folder') {
        setSidebarFilter({ kind: 'all' });
      }
      setDeleteAllFoldersOpen(false);
    } catch {
      // The action layer already shows the user-facing error toast.
    } finally {
      setBusy(false);
    }
  }

  const handleClearSearch = useCallback(() => setSearchInput(''), []);
  const handleSearchCompositionStart = useCallback(() => setSearchComposing(true), []);
  const handleSearchCompositionEnd = useCallback((value: string) => {
    setSearchComposing(false);
    setSearchInput(value);
  }, []);
  const handleToggleSortMenu = useCallback(() => setSortMenuOpen((open) => !open), []);
  const handleSelectSortMode = useCallback((value: VaultSortMode) => {
    setSortMode(value);
    setSortMenuOpen(false);
  }, []);
  const handleSyncVault = useCallback(() => { void syncVault(); }, [props.onRefresh]);
  const handleOpenBulkDelete = useCallback(() => setBulkDeleteOpen(true), []);
  const handleSelectDuplicates = useCallback(() => {
    if (duplicateMode !== 'exact') return;
    const map: Record<string, boolean> = {};
    const seen = new Set<string>();
    for (const cipher of filteredCiphers) {
      const signature = duplicateSignatureInfo?.byId.get(cipher.id)?.[0] || buildCipherDuplicateSignatures(cipher, 'exact')[0];
      if (seen.has(signature)) {
        map[cipher.id] = true;
        continue;
      }
      seen.add(signature);
    }
    setSelectedMap(map);
  }, [filteredCiphers, duplicateSignatureInfo, duplicateMode]);
  const handleSelectUniqueFromDuplicates = useCallback(() => {
    const map: Record<string, boolean> = {};
    const seen = new Set<number>();
    for (const cipher of filteredCiphers) {
      const groupIndex = duplicateGroupIndexById.get(cipher.id);
      if (groupIndex === undefined) continue;
      if (seen.has(groupIndex)) {
        map[cipher.id] = true;
      } else {
        seen.add(groupIndex);
      }
    }
    setSelectedMap(map);
  }, [filteredCiphers, duplicateGroupIndexById]);
  const handleSelectAll = useCallback(() => {
    const map: Record<string, boolean> = {};
    for (const cipher of filteredCiphers) map[cipher.id] = true;
    setSelectedMap(map);
  }, [filteredCiphers]);
  const handleToggleCreateMenu = useCallback(() => setCreateMenuOpen((open) => !open), []);
  const handleBulkRestore = useCallback(() => { void confirmBulkRestore(); }, [selectedMap, props.onBulkRestore]);
  const handleBulkArchive = useCallback(() => setBulkArchiveOpen(true), []);
  const handleBulkUnarchive = useCallback(() => { void confirmBulkUnarchive(); }, [selectedMap, props.onBulkUnarchive]);
  const handleOpenMove = useCallback(() => {
    setMoveFolderId('__none__');
    setMoveOpen(true);
  }, []);
  const handleClearSelection = useCallback(() => setSelectedMap({}), []);
  const handleToggleSelected = useCallback((cipherId: string, checked: boolean) =>
    setSelectedMap((prev) => {
      if (checked) return { ...prev, [cipherId]: true };
      if (!prev[cipherId]) return prev;
      const next = { ...prev };
      delete next[cipherId];
      return next;
    })
  , []);
  const handleSelectCipher = useCallback((cipherId: string) => {
    if (isEditing || isCreating) {
      cancelEdit();
    }
    setSelectedCipherId(cipherId);
    setRepromptApprovedCipherId(null);
    setShowPassword(false);
    setHiddenFieldVisibleMap({});
    if (isMobileLayout) setMobilePanel('detail');
    setMobileSidebarOpen(false);
  }, [isEditing, isCreating, cancelEdit, isMobileLayout]);
  const handleCloseMobileSidebar = useCallback(() => setMobileSidebarOpen(false), []);
  const handleOpenDeleteAllFolders = useCallback(() => setDeleteAllFoldersOpen(true), []);
  const handleOpenCreateFolder = useCallback(() => setCreateFolderOpen(true), []);
  const handleOpenRenameFolder = useCallback((folder: Folder) => {
    setPendingRenameFolder(folder);
    setRenameFolderName(folder.decName || folder.name || '');
  }, []);
  const handleToggleFolderSortMenu = useCallback(() => setFolderSortMenuOpen((open) => !open), []);
  const handleSelectFolderSortMode = useCallback((value: VaultSortMode) => {
    setFolderSortMode(value);
    setFolderSortMenuOpen(false);
  }, []);
  const handleMobileSidebarMaskClick = useCallback(() => {
    if (!mobileSidebarOpen) return;
    setMobileSidebarOpen(false);
  }, [mobileSidebarOpen]);

  return (
    <>
      <div className={`vault-grid ${isMobileLayout ? `mobile-panel-${mobilePanel}` : ''}`}>
        {isMobileLayout && (
          <div
            className={`mobile-sidebar-mask ${mobileSidebarOpen ? 'open' : ''}`}
            onClick={handleMobileSidebarMaskClick}
          />
        )}
        <VaultSidebar
          folders={props.folders}
          sidebarFilter={sidebarFilter}
          busy={busy}
          isMobileLayout={isMobileLayout}
          mobileSidebarOpen={mobileSidebarOpen}
          folderSortMode={folderSortMode}
          folderSortMenuOpen={folderSortMenuOpen}
          folderSortMenuRef={folderSortMenuRef}
          onCloseMobileSidebar={handleCloseMobileSidebar}
          onChangeFilter={setSidebarFilter}
          onOpenDeleteAllFolders={handleOpenDeleteAllFolders}
          onOpenCreateFolder={handleOpenCreateFolder}
          onOpenRenameFolder={handleOpenRenameFolder}
          onOpenDeleteFolder={setPendingDeleteFolder}
          onToggleFolderSortMenu={handleToggleFolderSortMenu}
          onSelectFolderSortMode={handleSelectFolderSortMode}
        />

        <VaultListPanel
          busy={busy}
          loading={props.loading}
          error={props.error}
          folders={props.folders}
          searchInput={searchInput}
          sortMode={sortMode}
          sortMenuOpen={sortMenuOpen}
          duplicateMode={duplicateMode}
          selectedCount={selectedCount}
          totalCipherCount={totalCipherCount}
          filteredCiphers={filteredCiphers}
          visibleCiphers={visibleCiphers}
          duplicateGroupIndexById={duplicateGroupIndexById}
          virtualRange={virtualRange}
          selectedCipherId={selectedCipherId}
          selectedMap={selectedMap}
          sidebarFilter={sidebarFilter}
          isMobileLayout={isMobileLayout}
          mobileFabVisible={!isMobileLayout || mobilePanel === 'list'}
          createMenuOpen={createMenuOpen}
          createMenuRef={createMenuRef}
          sortMenuRef={sortMenuRef}
          listPanelRef={listPanelRef}
          onSearchInput={setSearchInput}
          onClearSearch={handleClearSearch}
          onSearchCompositionStart={handleSearchCompositionStart}
          onSearchCompositionEnd={handleSearchCompositionEnd}
          onToggleSortMenu={handleToggleSortMenu}
          onSelectSortMode={handleSelectSortMode}
          onDuplicateModeChange={setDuplicateMode}
          onChangeFilter={setSidebarFilter}
          onSyncVault={handleSyncVault}
          onOpenBulkDelete={handleOpenBulkDelete}
          onSelectDuplicates={handleSelectDuplicates}
          onSelectUniqueFromDuplicates={handleSelectUniqueFromDuplicates}
          onSelectAll={handleSelectAll}
          onToggleCreateMenu={handleToggleCreateMenu}
          onStartCreate={startCreate}
          onBulkRestore={handleBulkRestore}
          onBulkArchive={handleBulkArchive}
          onBulkUnarchive={handleBulkUnarchive}
          onOpenMove={handleOpenMove}
          onClearSelection={handleClearSelection}
          onScroll={handleListScroll}
          onToggleSelected={handleToggleSelected}
          onSelectCipher={handleSelectCipher}
          listSubtitle={listSubtitle}
        />

        <section className={`detail-col ${isMobileLayout ? 'mobile-detail-sheet' : ''} ${isMobileLayout && mobilePanel !== 'list' ? 'open' : ''}`}>
          {isMobileLayout && mobilePanel !== 'list' && (
            <div className="mobile-panel-head">
              <button
                type="button"
                className="btn btn-secondary small mobile-panel-back"
                onClick={() => {
                  if (isEditing) cancelEdit();
                  else setMobilePanel('list');
                }}
              >
                <ChevronLeft size={14} className="btn-icon" />
                {t('txt_back')}
              </button>
            </div>
          )}
          {isEditing && draft && (
            <div key={`editor-${draft.id || selectedCipher?.id || 'new'}-${draft.type}`} className="detail-switch-stage">
              <VaultEditor
                draft={draft}
                isCreating={isCreating}
                busy={busy}
                folders={props.folders}
                selectedCipher={selectedCipher}
                editExistingAttachments={editExistingAttachments}
                removedAttachmentIds={removedAttachmentIds}
                removedAttachmentCount={removedAttachmentCount}
                attachmentQueue={attachmentQueue}
                attachmentInputRef={attachmentInputRef}
                localError={localError}
                onUpdateDraft={updateDraft}
                onSeedSshDefaults={(force) => void seedSshDefaults(force)}
                onUpdateSshPublicKey={updateSshPublicKey}
                onUpdateDraftLoginUri={updateDraftLoginUri}
                onUpdateDraftLoginUriMatch={updateDraftLoginUriMatch}
                onReorderDraftLoginUri={reorderDraftLoginUri}
                onRequestDeleteLoginPasskey={setPendingDeletePasskeyIndex}
                onQueueAttachmentFiles={queueAttachmentFiles}
                onToggleExistingAttachmentRemoval={toggleExistingAttachmentRemoval}
                onRemoveQueuedAttachment={removeQueuedAttachment}
                onDownloadAttachment={(cipher, attachmentId) => void props.onDownloadAttachment(cipher, attachmentId)}
                downloadingAttachmentKey={props.downloadingAttachmentKey}
                attachmentDownloadPercent={props.attachmentDownloadPercent}
                uploadingAttachmentName={props.uploadingAttachmentName}
                attachmentUploadPercent={props.attachmentUploadPercent}
                onPatchDraftCustomField={patchDraftCustomField}
                onUpdateDraftCustomFields={updateDraftCustomFields}
                onOpenFieldModal={() => setFieldModalOpen(true)}
                onSave={() => void saveDraft()}
                onCancel={cancelEdit}
                onDeleteSelected={() => selectedCipher && setPendingDelete(selectedCipher)}
              />
            </div>
          )}

          {!isEditing && selectedCipher && (
            <div key={`detail-${selectedCipher.id}`} className="detail-switch-stage">
              <VaultDetailView
                selectedCipher={selectedCipher}
                repromptApprovedCipherId={repromptApprovedCipherId}
                showPassword={showPassword}
                totpLive={totpLive}
                passkeyCreatedAt={firstPasskeyCreationTime(selectedCipher)}
                hiddenFieldVisibleMap={hiddenFieldVisibleMap}
                folderName={folderName}
                onOpenReprompt={() => setRepromptOpen(true)}
                onToggleShowPassword={() => setShowPassword((value) => !value)}
                onToggleHiddenField={(index) => setHiddenFieldVisibleMap((prev) => ({ ...prev, [index]: !prev[index] }))}
                onDownloadAttachment={(cipher, attachmentId) => void props.onDownloadAttachment(cipher, attachmentId)}
                downloadingAttachmentKey={props.downloadingAttachmentKey}
                attachmentDownloadPercent={props.attachmentDownloadPercent}
                onStartEdit={startEdit}
                onDelete={setPendingDelete}
                onRestore={(cipher) => void handleRestoreSelected(cipher)}
                onArchive={(cipher) => setPendingArchive(cipher)}
                onUnarchive={(cipher) => void handleUnarchiveSelected(cipher)}
              />
            </div>
          )}

          {!isEditing && !selectedCipher && (
            props.loading
              ? <LoadingState card lines={5} />
              : props.error
                ? (
                  <div className="empty card vault-error-state">
                    <strong>{props.error}</strong>
                    <button type="button" className="btn btn-secondary small" disabled={busy} onClick={handleSyncVault}>
                      {t('txt_retry_sync')}
                    </button>
                  </div>
                )
                : <div className="empty card">{t('txt_select_an_item')}</div>
          )}
        </section>
      </div>

      <VaultDialogs
        busy={busy}
        fieldModalOpen={fieldModalOpen}
        fieldType={fieldType}
        fieldLabel={fieldLabel}
        fieldValue={fieldValue}
        archiveConfirmOpen={!!pendingArchive}
        bulkArchiveOpen={bulkArchiveOpen}
        pendingDeleteOpen={!!pendingDelete}
        bulkDeleteOpen={bulkDeleteOpen}
        sidebarTrashMode={sidebarFilter.kind === 'trash'}
        selectedCount={selectedCount}
        moveOpen={moveOpen}
        moveFolderId={moveFolderId}
        folders={props.folders}
        createFolderOpen={createFolderOpen}
        newFolderName={newFolderName}
        renameFolderOpen={!!pendingRenameFolder}
        renameFolderName={renameFolderName}
        pendingDeleteFolder={pendingDeleteFolder}
        deleteAllFoldersOpen={deleteAllFoldersOpen}
        repromptOpen={repromptOpen}
        repromptPassword={repromptPassword}
        deletePasskeyOpen={pendingDeletePasskeyIndex != null}
        onConfirmAddField={() => {
          if (!draft) return;
          if (!fieldLabel.trim()) {
            setLocalError(t('txt_field_label_is_required'));
            return;
          }
          updateDraftCustomFields([
            ...draft.customFields,
            {
              type: fieldType,
              label: fieldLabel.trim(),
              value: fieldType === 2 ? (fieldValue === 'true' ? 'true' : 'false') : fieldValue,
            },
          ]);
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
          setLocalError('');
        }}
        onCancelFieldModal={() => {
          setFieldModalOpen(false);
          setFieldType(0);
          setFieldLabel('');
          setFieldValue('');
        }}
        onFieldTypeChange={setFieldType}
        onFieldLabelChange={setFieldLabel}
        onFieldValueChange={setFieldValue}
        onConfirmArchive={() => void confirmArchiveSelected()}
        onCancelArchive={() => setPendingArchive(null)}
        onConfirmBulkArchive={() => void confirmBulkArchive()}
        onCancelBulkArchive={() => setBulkArchiveOpen(false)}
        onConfirmDelete={() => void deleteSelected()}
        onCancelDelete={() => setPendingDelete(null)}
        onConfirmBulkDelete={() => void confirmBulkDelete()}
        onCancelBulkDelete={() => setBulkDeleteOpen(false)}
        onConfirmMove={() => void confirmBulkMove()}
        onCancelMove={() => setMoveOpen(false)}
        onMoveFolderIdChange={setMoveFolderId}
        onConfirmCreateFolder={() => void confirmCreateFolder()}
        onCancelCreateFolder={() => {
          setCreateFolderOpen(false);
          setNewFolderName('');
        }}
        onNewFolderNameChange={setNewFolderName}
        onConfirmRenameFolder={() => void confirmRenameFolder()}
        onCancelRenameFolder={() => {
          setPendingRenameFolder(null);
          setRenameFolderName('');
        }}
        onRenameFolderNameChange={setRenameFolderName}
        onConfirmDeleteFolder={() => void confirmDeleteFolder()}
        onCancelDeleteFolder={() => setPendingDeleteFolder(null)}
        onConfirmDeleteAllFolders={() => void confirmDeleteAllFolders()}
        onCancelDeleteAllFolders={() => setDeleteAllFoldersOpen(false)}
        onConfirmReprompt={() => void verifyReprompt()}
        onCancelReprompt={() => {
          setRepromptOpen(false);
          setRepromptPassword('');
        }}
        onRepromptPasswordChange={setRepromptPassword}
        onConfirmDeletePasskey={confirmDeleteLoginPasskey}
        onCancelDeletePasskey={() => setPendingDeletePasskeyIndex(null)}
      />
    </>
  );
}

