export function registerNodeWardenServiceWorker(): void {
  if (typeof window === 'undefined') return;
  if (!('serviceWorker' in navigator)) return;
  if (import.meta.env.DEV) return;

  const register = () => {
    // Reload once when a new build's worker takes control, so an already-open
    // page doesn't keep running old HTML that references removed asset chunks
    // (the blank-vault / dynamic-import-failure bug).
    const hadController = !!navigator.serviceWorker.controller;
    let reloadedForNewWorker = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => {
      if (!hadController || reloadedForNewWorker) return;
      reloadedForNewWorker = true;
      window.location.reload();
    });
    void navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {
      // PWA support is progressive enhancement; the vault still works without it.
    });
  };

  if (document.readyState === 'complete') {
    register();
    return;
  }

  window.addEventListener('load', register, { once: true });
}
