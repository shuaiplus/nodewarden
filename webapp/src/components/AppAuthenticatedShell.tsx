import { ArrowUpDown, ChevronDown, Clock3, Cloud, FileClock, Folder as FolderIcon, KeyRound, Lock, LogOut, MonitorSmartphone, Send as SendIcon, Settings as SettingsIcon, ShieldCheck, ShieldUser, Sparkles, Users } from 'lucide-preact';
import type { ComponentChildren } from 'preact';
import { useState } from 'preact/hooks';
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

const NAV_GROUPS_STORAGE_KEY = 'nodewarden.navGroups';

const DEFAULT_EXPANDED_GROUPS = {
  tools: true,
  settings: true,
  management: true,
};

type NavGroup = keyof typeof DEFAULT_EXPANDED_GROUPS;
type ExpandedGroups = Record<NavGroup, boolean>;

function readExpandedGroups(): ExpandedGroups {
  if (typeof window === 'undefined') return DEFAULT_EXPANDED_GROUPS;
  try {
    const saved = window.localStorage.getItem(NAV_GROUPS_STORAGE_KEY);
    if (!saved) return DEFAULT_EXPANDED_GROUPS;
    const parsed = JSON.parse(saved) as Partial<ExpandedGroups>;
    return {
      tools: typeof parsed.tools === 'boolean' ? parsed.tools : DEFAULT_EXPANDED_GROUPS.tools,
      settings: typeof parsed.settings === 'boolean' ? parsed.settings : DEFAULT_EXPANDED_GROUPS.settings,
      management: typeof parsed.management === 'boolean' ? parsed.management : DEFAULT_EXPANDED_GROUPS.management,
    };
  } catch {
    // Ignore local preference read failures.
  }
  return DEFAULT_EXPANDED_GROUPS;
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
  const deviceManagementActive = props.location === DEVICE_MANAGEMENT_ROUTE || props.location === LEGACY_DEVICE_MANAGEMENT_ROUTE;
  const [expandedGroups, setExpandedGroups] = useState<ExpandedGroups>(readExpandedGroups);

  function toggleGroup(group: NavGroup): void {
    setExpandedGroups((current) => {
      const next = { ...current, [group]: !current[group] };
      try {
        window.localStorage.setItem(NAV_GROUPS_STORAGE_KEY, JSON.stringify(next));
      } catch {
        // Ignore local preference write failures.
      }
      return next;
    });
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
    group: NavGroup,
    title: string,
    icon: ComponentChildren,
    children: ComponentChildren
  ) {
    const open = expandedGroups[group];
    return (
      <div className={`side-nav-group ${open ? 'open' : ''}`}>
        <button
          type="button"
          className="side-group-trigger"
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

  const groupedNav = (
    <>
      {renderSideLink('/vault', props.location === '/vault', <KeyRound size={16} />, t('nav_vault_items'))}
      {renderSideLink('/sends', props.location === '/sends', <SendIcon size={16} />, t('nav_sends'))}
      {renderNavGroup(
        'tools',
        t('nav_group_tools'),
        <Sparkles size={16} />,
        <>
          {renderSubLink('/vault/totp', props.location === '/vault/totp', t('txt_verification_code'))}
          {renderSubLink('/generator', props.location === '/generator', t('nav_generator'))}
          {renderSubLink('/security/password-health', props.location === '/security/password-health', t('nav_password_security'))}
          {renderSubLink(props.importRoute, props.isImportRoute, t('nav_import_export'))}
        </>
      )}
      {renderNavGroup(
        'settings',
        t('txt_settings'),
        <SettingsIcon size={16} />,
        <>
          {renderSubLink(props.settingsAccountRoute, props.location === props.settingsAccountRoute, t('nav_account_settings'))}
          {renderSubLink(DEVICE_MANAGEMENT_ROUTE, deviceManagementActive, t('nav_device_management'))}
          {renderSubLink('/settings/domain-rules', props.location === '/settings/domain-rules', t('nav_domain_rules'))}
        </>
      )}
      {isAdmin &&
        renderNavGroup(
          'management',
          t('nav_group_system_management'),
          <ShieldUser size={16} />,
          <>
            {renderSubLink('/backup', props.location === '/backup', t('nav_backup_strategy'))}
            {renderSubLink('/admin', props.location === '/admin', t('nav_admin_panel'))}
            {renderSubLink('/logs', props.location === '/logs', t('nav_log_center'))}
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
              {groupedNav}
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
          <Link href="/generator" className={`mobile-tab ${props.mobilePrimaryRoute === '/generator' ? 'active' : ''}`}>
            <Sparkles size={18} />
            <span>{t('nav_generator')}</span>
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
