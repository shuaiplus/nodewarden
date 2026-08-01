import { inspectVaultPasswordSecurity, type PasswordSecurityReport } from '@/lib/password-security';
import type { Cipher } from '@/lib/types';

export interface PasswordSecurityState {
  fingerprint: string;
  report: PasswordSecurityReport | null;
  scannedAt: number | null;
  scanning: boolean;
  progress: { checked: number; total: number };
  scanError: boolean;
}

type InternalPasswordSecurityState = PasswordSecurityState & { controller: AbortController | null };

let state: InternalPasswordSecurityState | null = null;
const listeners = new Set<() => void>();

function notify(): void {
  listeners.forEach((listener) => listener());
}

function createState(fingerprint: string): InternalPasswordSecurityState {
  return { fingerprint, report: null, scannedAt: null, scanning: false, progress: { checked: 0, total: 0 }, scanError: false, controller: null };
}

export function getPasswordSecurityState(fingerprint: string): PasswordSecurityState {
  if (state?.fingerprint !== fingerprint) {
    state?.controller?.abort();
    state = createState(fingerprint);
  }
  return state;
}

export function readPasswordSecurityState(fingerprint: string): PasswordSecurityState | null {
  return state?.fingerprint === fingerprint ? state : null;
}

export function subscribePasswordSecurityState(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function startPasswordSecurityScan(fingerprint: string, ciphers: Cipher[]): void {
  const current = getPasswordSecurityState(fingerprint);
  current.controller?.abort();
  const controller = new AbortController();
  const total = ciphers.filter((cipher) => Number(cipher.type) === 1 && !cipher.deletedDate && !(cipher as { deletedAt?: string | null }).deletedAt && !!cipher.login?.decPassword).length;
  state = { ...current, report: null, scannedAt: null, scanning: true, progress: { checked: 0, total }, scanError: false, controller };
  notify();

  void (async () => {
    try {
      const report = await inspectVaultPasswordSecurity(ciphers, (checked, total) => {
        if (controller.signal.aborted || state?.controller !== controller) return;
        state = { ...state, progress: { checked, total } };
        notify();
      }, fetch, controller.signal);
      if (controller.signal.aborted || state?.controller !== controller) return;
      state = { ...state, report, scannedAt: Date.now() };
    } catch (error) {
      if (controller.signal.aborted || (error as { name?: string } | null)?.name === 'AbortError') return;
      if (state?.controller === controller) state = { ...state, scanError: true };
    } finally {
      if (state?.controller === controller) state = { ...state, controller: null, scanning: false };
      notify();
    }
  })();
}

export function clearPasswordSecurityCache(): void {
  state?.controller?.abort();
  state = null;
  notify();
}
