import { deriveLoginHashLocally, unlockVaultKey } from '@/lib/api/auth';
import type { Profile, SessionState, TokenSuccess } from '@/lib/types';

const OFFLINE_UNLOCK_KEY = 'nodewarden.web.offline-unlock.v1';
const OFFLINE_UNLOCK_PERSIST_OPT_IN_KEY = 'nodewarden.web.offline-unlock.persist';

interface OfflineUnlockRecord {
  version: 1;
  email: string;
  profile: Profile;
  profileKey: string;
  kdfIterations: number;
  savedAt: number;
}

function normalizeEmail(email: string | null | undefined): string {
  return String(email || '').trim().toLowerCase();
}

function stripOfflineProfile(profile: Profile): Profile {
  return {
    ...profile,
    email: normalizeEmail(profile.email),
    key: '',
    privateKey: null,
  };
}

function parseRecord(raw: string | null): OfflineUnlockRecord | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<OfflineUnlockRecord>;
    const email = normalizeEmail(parsed.email);
    const profileKey = String(parsed.profileKey || '').trim();
    const iterations = Number(parsed.kdfIterations || 0);
    if (parsed.version !== 1 || !email || !profileKey || !Number.isFinite(iterations) || iterations <= 0) {
      return null;
    }
    const profile = parsed.profile && typeof parsed.profile === 'object'
      ? stripOfflineProfile(parsed.profile as Profile)
      : {
          id: '',
          email,
          name: email,
          key: '',
          privateKey: null,
          role: 'user' as const,
        };
    return {
      version: 1,
      email,
      profile,
      profileKey,
      kdfIterations: iterations,
      savedAt: Number(parsed.savedAt || 0) || 0,
    };
  } catch {
    return null;
  }
}

function isPersistentOfflineUnlockEnabled(): boolean {
  try {
    return typeof localStorage !== 'undefined' && localStorage.getItem(OFFLINE_UNLOCK_PERSIST_OPT_IN_KEY) === '1';
  } catch {
    return false;
  }
}

function readRecord(): OfflineUnlockRecord | null {
  try {
    if (typeof sessionStorage !== 'undefined') {
      const sessionRaw = sessionStorage.getItem(OFFLINE_UNLOCK_KEY);
      if (sessionRaw) return parseRecord(sessionRaw);
    }
  } catch {
    // Ignore sessionStorage read errors.
  }
  if (isPersistentOfflineUnlockEnabled()) {
    try {
      return parseRecord(localStorage.getItem(OFFLINE_UNLOCK_KEY));
    } catch {
      return null;
    }
  }
  return null;
}

export function hasOfflineUnlockRecord(email?: string | null): boolean {
  const record = readRecord();
  if (!record) return false;
  const normalized = normalizeEmail(email);
  return !normalized || record.email === normalized;
}

export function getOfflineUnlockKdfIterations(email?: string | null): number | null {
  const record = readRecord();
  if (!record) return null;
  const normalized = normalizeEmail(email);
  if (normalized && record.email !== normalized) return null;
  return record.kdfIterations;
}

export function loadOfflineProfileSnapshot(email?: string | null): Profile | null {
  const record = readRecord();
  if (!record) return null;
  const normalized = normalizeEmail(email);
  if (normalized && record.email !== normalized) return null;
  return stripOfflineProfile(record.profile);
}

export function saveOfflineUnlockRecord(args: {
  email: string;
  profile: Profile;
  profileKey: string;
  kdfIterations: number;
}): void {
  const email = normalizeEmail(args.email || args.profile.email);
  const profileKey = String(args.profileKey || '').trim();
  const kdfIterations = Number(args.kdfIterations || 0);
  if (!email || !profileKey || !Number.isFinite(kdfIterations) || kdfIterations <= 0) return;
  const record: OfflineUnlockRecord = {
    version: 1,
    email,
    profile: stripOfflineProfile({ ...args.profile, email }),
    profileKey,
    kdfIterations,
    savedAt: Date.now(),
  };
  const serialized = JSON.stringify(record);
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.setItem(OFFLINE_UNLOCK_KEY, serialized);
    }
  } catch {
    // Ignore sessionStorage write errors.
  }
  try {
    if (typeof localStorage !== 'undefined') {
      if (isPersistentOfflineUnlockEnabled()) {
        localStorage.setItem(OFFLINE_UNLOCK_KEY, serialized);
      } else {
        localStorage.removeItem(OFFLINE_UNLOCK_KEY);
      }
    }
  } catch {
    // Ignore localStorage cleanup errors.
  }
}

export function clearOfflineUnlockRecord(): void {
  try {
    if (typeof sessionStorage !== 'undefined') {
      sessionStorage.removeItem(OFFLINE_UNLOCK_KEY);
    }
  } catch {
    // Ignore sessionStorage failures during logout cleanup.
  }
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(OFFLINE_UNLOCK_KEY);
    }
  } catch {
    // Ignore localStorage failures during logout cleanup.
  }
}

export async function unlockOfflineVault(
  session: SessionState,
  profile: Profile | null,
  password: string
): Promise<{ session: SessionState; profile: Profile }> {
  const record = readRecord();
  const email = normalizeEmail(profile?.email || session.email);
  if (!record || record.email !== email) {
    throw new Error('Offline unlock is not available on this device.');
  }
  const derived = await deriveLoginHashLocally(record.email, password, record.kdfIterations);
  return unlockOfflineVaultWithMasterKey(session, profile, derived.masterKey);
}

export async function unlockOfflineVaultWithMasterKey(
  session: SessionState,
  profile: Profile | null,
  masterKey: Uint8Array
): Promise<{ session: SessionState; profile: Profile }> {
  const record = readRecord();
  const email = normalizeEmail(profile?.email || session.email);
  if (!record || record.email !== email) {
    throw new Error('Offline unlock is not available on this device.');
  }
  const keys = await unlockVaultKey(record.profileKey, masterKey);
  const { accessToken: _accessToken, refreshToken: _refreshToken, ...offlineSession } = session;
  return {
    session: {
      ...offlineSession,
      email: record.email,
      ...keys,
    },
    profile: {
      ...stripOfflineProfile(record.profile),
      key: record.profileKey,
    },
  };
}

export function kdfIterationsFromLogin(token: TokenSuccess, fallbackIterations: number): number {
  const value = Number(token.KdfIterations || fallbackIterations || 600000);
  return Number.isFinite(value) && value > 0 ? value : 600000;
}
