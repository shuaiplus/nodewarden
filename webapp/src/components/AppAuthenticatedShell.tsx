import { ArrowUpDown, Check, ChevronDown, Clock3, Cloud, FileClock, Folder as FolderIcon, KeyRound, Lock, LogOut, MonitorSmartphone, Send as SendIcon, Settings as SettingsIcon, ShieldUser, SlidersHorizontal, Users } from 'lucide-preact';
import type { ComponentChildren } from 'preact';
import { useEffect, useRef, useState } from 'preact/hooks';
import { Link } from 'wouter';
import AppMainRoutes from '@/components/AppMainRoutes';
import NetworkStatusBadge from '@/components/NetworkStatusBadge';
import ThemeSwitch from '@/components/ThemeSwitch';
import type { AppMainRoutesProps } from '@/components/AppMainRoutes';
import { t } from '@/lib/i18n';
import type { Profile } from '@/lib/types';

interface AppAuthenticatedShellProps {
  profile: Profile | null;
  location: string;
  mobilePrimaryRoute: string;
  currentPageTitle: string;
  showSidebarToggle: boolean;
  sidebarToggleTitle: string;
  settingsAccountRoute: string;
  importRoute: string;
  isImportRoute: boolean;
  darkMode: boolean;
  themeToggleTitle: string;
  onLock: () => void;
  onLogout: () => void;
  onToggleTheme: () => void;
  onToggleMobileSidebar: () => void;
  mainRoutesProps: AppMainRoutesProps;
}

type NavLayoutMode = 'flat' | 'grouped-expanded' | 'grouped-smart';

const NAV_LAYOUT_STORAGE_KEY = 'nodewarden.navLayoutMode';

function readNavLayoutMode(): NavLayoutMode {
  if (typeof window === 'undefined') return 'flat';
  try {
    const saved = window.localStorage.getItem(NAV_LAYOUT_STORAGE_KEY);
    if (saved === 'flat' || saved === 'grouped-expanded' || saved === 'grouped-smart') return saved;
  } catch {
    // Ignore local preference read failures.
  }
  return 'flat';
}

function isAdminProfile(profile: Profile | null): boolean {
  return String(profile?.role || '').toLowerCase() === 'admin';
}

const DEVICE_MANAGEMENT_ROUTE = '/settings/security/device-management';
const LEGACY_DEVICE_MANAGEMENT_ROUTE = '/security/devices';

export default function AppAuthenticatedShell(props: AppAuthenticatedShellProps) {
  const routeAnimationKey = props.isImportRoute ? props.importRoute : props.location;
  const isDomainRulesRoute = props.location === '/settings/domain-rules';
  const isLogRoute = props.location === '/logs';
  const isAdmin = isAdminProfile(props.profile);
  const vaultActive = props.location === '/vault' || props.location === '/vault/totp';
  const deviceManagementActive = props.location === DEVICE_MANAGEMENT_ROUTE || props.location === LEGACY_DEVICE_MANAGEMENT_ROUTE;
  const settingsActive = props.location === '/settings' || props.location === props.settingsAccountRoute || props.location === '/settings/domain-rules' || deviceManagementActive;
  const flatSettingsActive = settingsActive && !deviceManagementActive;
  const dataActive = props.location === '/backup' || props.isImportRoute;
  const managementActive = props.location === '/admin' || props.location === '/logs';
  const [navLayoutMode, setNavLayoutMode] = useState<NavLayoutMode>(readNavLayoutMode);
  const [navLayoutPickerOpen, setNavLayoutPickerOpen] = useState(false);
  const navLayoutPickerRef = useRef<HTMLDivElement | null>(null);
  const [expandedGroups, setExpandedGroups] = useState({
    vault: true,
    settings: false,
    data: false,
    management: false,
  });

  useEffect(() => {
    const onPointerDown = (event: Event) => {
      if (!navLayoutPickerOpen) return;
      const target = event.target as Node | null;
      if (navLayoutPickerRef.current && target && !navLayoutPickerRef.current.contains(target)) {
        setNavLayoutPickerOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setNavLayoutPickerOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [navLayoutPickerOpen]);

  function setNavMode(mode: NavLayoutMode): void {
    setNavLayoutMode(mode);
    setNavLayoutPickerOpen(false);
    try {
      window.localStorage.setItem(NAV_LAYOUT_STORAGE_KEY, mode);
    } catch {
      // Ignore local preference write failures.
    }
  }

  function toggleGroup(group: keyof typeof expandedGroups): void {
    setExpandedGroups((current) => ({ ...current, [group]: !current[group] }));
  }

  function groupOpen(group: keyof typeof expandedGroups, active: boolean): boolean {
    if (navLayoutMode === 'grouped-expanded') return true;
    return expandedGroups[group] || active;
  }

  function renderSideLink(href: string, active: boolean, icon: ComponentChildren, label: string) {
    return (
      <Link href={href} className={`side-link ${active ? 'active' : ''}`}>
        {icon}
        <span>{label}</span>
      </Link>
    );
  }

  function renderSubLink(href: string, active: boolean, label: string) {
    return (
      <Link href={href} className={`side-sub-link ${active ? 'active' : ''}`}>
        <span>{label}</span>
      </Link>
    );
  }

  function renderNavGroup(
    group: keyof typeof expandedGroups,
    title: string,
    icon: ComponentChildren,
    active: boolean,
    children: ComponentChildren
  ) {
    const open = groupOpen(group, active);
    return (
      <div className={`side-nav-group ${open ? 'open' : ''}`}>
        <button
          type="button"
          className={`side-group-trigger ${active ? 'active' : ''}`}
          aria-expanded={open}
          onClick={() => toggleGroup(group)}
        >
          {icon}
          <span>{title}</span>
          <ChevronDown size={15} className="side-group-chevron" />
        </button>
        <div className={`side-subnav ${open ? 'open' : ''}`}>
          <div className="side-subnav-inner">
            {children}
          </div>
        </div>
      </div>
    );
  }

  const navLayoutOptions: Array<{ mode: NavLayoutMode; label: string }> = [
    {
      mode: 'flat',
      label: t('txt_nav_layout_flat'),
    },
    {
      mode: 'grouped-expanded',
      label: t('txt_nav_layout_grouped_expanded'),
    },
    {
      mode: 'grouped-smart',
      label: t('txt_nav_layout_grouped_smart'),
    },
  ];

  const navLayoutLabel = navLayoutOptions.find((option) => option.mode === navLayoutMode)?.label || t('txt_nav_layout_flat');
  const flatNav = (
    <>
      {renderSideLink('/vault', props.location === '/vault', <KeyRound size={16} />, t('nav_vault_items'))}
      {renderSideLink('/vault/totp', props.location === '/vault/totp', <Clock3 size={16} />, t('txt_verification_code'))}
      {renderSideLink('/sends', props.location === '/sends', <SendIcon size={16} />, t('nav_sends'))}
      {renderSideLink('/settings', flatSettingsActive, <SettingsIcon size={16} />, t('txt_settings'))}
      {renderSideLink(DEVICE_MANAGEMENT_ROUTE, deviceManagementActive, <MonitorSmartphone size={16} />, t('nav_device_management'))}
      {isAdmin && renderSideLink('/backup', props.location === '/backup', <Cloud size={16} />, t('nav_backup_strategy'))}
      {renderSideLink(props.importRoute, props.isImportRoute, <ArrowUpDown size={16} />, t('nav_import_export'))}
      {isAdmin && renderSideLink('/admin', props.location === '/admin', <Users size={16} />, t('nav_admin_panel'))}
      {isAdmin && renderSideLink('/logs', props.location === '/logs', <FileClock size={16} />, t('nav_log_center'))}
    </>
  );

  const groupedNav = (
    <>
      {renderNavGroup(
        'vault',
        t('nav_my_vault'),
        <KeyRound size={16} />,
        vaultActive,
        <>
          {renderSubLink('/vault', props.location === '/vault', t('nav_vault_items'))}
          {renderSubLink('/vault/totp', props.location === '/vault/totp', t('txt_verification_code'))}
        </>
      )}
      {renderSideLink('/sends', props.location === '/sends', <SendIcon size={16} />, t('nav_sends'))}
      {renderNavGroup(
        'settings',
        t('txt_settings'),
        <SettingsIcon size={16} />,
        settingsActive,
        <>
          {renderSubLink(props.settingsAccountRoute, props.location === props.settingsAccountRoute, t('nav_account_settings'))}
          {renderSubLink('/settings/domain-rules', props.location === '/settings/domain-rules', t('nav_domain_rules'))}
          {renderSubLink(DEVICE_MANAGEMENT_ROUTE, deviceManagementActive, t('nav_device_management'))}
        </>
      )}
      {renderNavGroup(
        'data',
        t('nav_group_data_backup'),
        <Cloud size={16} />,
        dataActive,
        <>
          {isAdmin && renderSubLink('/backup', props.location === '/backup', t('nav_backup_strategy'))}
          {renderSubLink(props.importRoute, props.isImportRoute, t('nav_import_export'))}
        </>
      )}
      {renderNavGroup(
        'management',
        t('nav_group_management'),
        <ShieldUser size={16} />,
        managementActive,
        <>
          {isAdmin && renderSubLink('/admin', props.location === '/admin', t('nav_admin_panel'))}
          {isAdmin && renderSubLink('/logs', props.location === '/logs', t('nav_log_center'))}
        </>
      )}
    </>
  );

  return (
    <div className="app-page">
      <div className="app-shell">
        <header className="topbar">
          <div className="brand">
            <img src="/nodewarden-logo.svg" alt="NodeWarden logo" className="brand-logo" />
            <span className="brand-wordmark" role="img" aria-label="NodeWarden" />
            <span className="mobile-page-title">{props.currentPageTitle}</span>
          </div>
          <div className="topbar-actions">
            <NetworkStatusBadge />
            <div className="user-chip">
              <ShieldUser size={16} />
              <span>{props.profile?.email}</span>
            </div>
            <ThemeSwitch checked={props.darkMode} title={props.themeToggleTitle} onToggle={props.onToggleTheme} />
            <button type="button" className="btn btn-secondary small" onClick={props.onLock}>
              <Lock size={14} className="btn-icon" /> {t('txt_lock')}
            </button>
            {props.showSidebarToggle && (
              <button
                type="button"
                className="btn btn-secondary small mobile-sidebar-toggle"
                aria-label={props.sidebarToggleTitle}
                title={props.sidebarToggleTitle}
                onClick={props.onToggleMobileSidebar}
              >
                <FolderIcon size={16} className="btn-icon" />
              </button>
            )}
            <div className="mobile-theme-btn">
              <ThemeSwitch checked={props.darkMode} title={props.themeToggleTitle} onToggle={props.onToggleTheme} />
            </div>
            <button type="button" className="btn btn-secondary small mobile-lock-btn" aria-label={t('txt_lock')} title={t('txt_lock')} onClick={props.onLock}>
              <Lock size={14} className="btn-icon" />
            </button>
            <button type="button" className="btn btn-secondary small" onClick={props.onLogout}>
              <LogOut size={14} className="btn-icon" /> {t('txt_sign_out')}
            </button>
          </div>
        </header>

        <div className="app-main">
          <aside className="app-side">
            <div className="side-nav-main">
              {navLayoutMode === 'flat' ? flatNav : groupedNav}
            </div>
            <div className="nav-layout-control" ref={navLayoutPickerRef}>
              {navLayoutPickerOpen && (
                <div className="nav-layout-menu" role="menu">
                  {navLayoutOptions.map((option) => (
                    <button
                      key={option.mode}
                      type="button"
                      className={`nav-layout-option ${navLayoutMode === option.mode ? 'active' : ''}`}
                      onClick={() => setNavMode(option.mode)}
                      role="menuitemradio"
                      aria-checked={navLayoutMode === option.mode}
                    >
                      <span className="nav-layout-option-text">
                        <strong>{option.label}</strong>
                      </span>
                      {navLayoutMode === option.mode && <Check size={15} className="nav-layout-check" />}
                    </button>
                  ))}
                </div>
              )}
              <button
                type="button"
                className={`nav-layout-trigger ${navLayoutPickerOpen ? 'active' : ''}`}
                aria-haspopup="menu"
                aria-expanded={navLayoutPickerOpen}
                onClick={() => setNavLayoutPickerOpen((open) => !open)}
                title={t('txt_nav_layout')}
              >
                <SlidersHorizontal size={15} />
              </button>
            </div>
          </aside>
          <main className="content">
            <div key={routeAnimationKey} className={`route-stage ${isDomainRulesRoute ? 'route-stage-fixed' : ''} ${isLogRoute ? 'route-stage-log-fixed' : ''}`}>
              <AppMainRoutes {...props.mainRoutesProps} />
            </div>
          </main>
        </div>

        <nav className="mobile-tabbar" aria-label={t('txt_menu')}>
          <Link href="/vault" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault' ? 'active' : ''}`}>
            <KeyRound size={18} />
            <span>{t('nav_my_vault')}</span>
          </Link>
          <Link href="/vault/totp" className={`mobile-tab ${props.mobilePrimaryRoute === '/vault/totp' ? 'active' : ''}`}>
            <Clock3 size={18} />
            <span>{t('txt_verification_code')}</span>
          </Link>
          <Link href="/sends" className={`mobile-tab ${props.mobilePrimaryRoute === '/sends' ? 'active' : ''}`}>
            <SendIcon size={18} />
            <span>{t('nav_sends')}</span>
          </Link>
          <Link href="/settings" className={`mobile-tab ${props.mobilePrimaryRoute === '/settings' ? 'active' : ''}`}>
            <SettingsIcon size={18} />
            <span>{t('txt_settings')}</span>
          </Link>
        </nav>
      </div>
    </div>
  );
}
