let workspacePreload: Promise<unknown> | null = null;
let adminPreload: Promise<unknown> | null = null;

export function preloadAuthenticatedWorkspace(isAdmin: boolean): Promise<unknown> {
  if (!workspacePreload) {
    workspacePreload = Promise.allSettled([
      import('@/components/SendsPage'),
      import('@/components/TotpCodesPage'),
      import('@/components/SettingsPage'),
      import('@/components/DomainRulesPage'),
      import('@/components/SecurityDevicesPage'),
    ]);
  }

  if (!isAdmin) {
    return workspacePreload;
  }

  if (!adminPreload) {
    adminPreload = Promise.allSettled([
      workspacePreload,
      import('@/components/AdminPage'),
      import('@/components/BackupCenterPage'),
    ]);
  }

  return adminPreload;
}
