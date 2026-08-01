let workspacePreload: Promise<unknown> | null = null;
let adminPreload: Promise<unknown> | null = null;
let demoExperiencePreloadStarted = false;

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

export function preloadDemoExperience(): () => void {
  if (demoExperiencePreloadStarted || typeof window === 'undefined') {
    return () => undefined;
  }

  demoExperiencePreloadStarted = true;
  let cancelled = false;
  let timerId: number | null = null;

  const tasks = [
    () => import('@/components/VaultPage'),
    () => import('@/components/SendsPage'),
    () => import('@/components/TotpCodesPage'),
    () => import('@/components/SettingsPage'),
    () => import('@/components/DomainRulesPage'),
    () => import('@/components/SecurityDevicesPage'),
    () => import('@/components/AdminPage'),
    () => import('@/components/BackupCenterPage'),
    () => import('@/components/ImportPage'),
  ];

  const wait = (ms: number) => new Promise<void>((resolve) => {
    timerId = window.setTimeout(() => {
      timerId = null;
      resolve();
    }, ms);
  });

  void (async () => {
    await wait(120);
    for (const task of tasks) {
      if (cancelled) return;
      await task().catch(() => undefined);
      await wait(180);
    }
  })();

  return () => {
    cancelled = true;
    if (timerId !== null) {
      window.clearTimeout(timerId);
      timerId = null;
    }
  };
}
