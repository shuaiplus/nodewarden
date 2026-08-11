import type { Cipher } from '@/lib/types';

const PWNED_PASSWORDS_RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const TWO_FACTOR_DIRECTORY_URL = 'https://api.2fa.directory/v4/all.json';
const PASSKEY_DIRECTORY_URL = 'https://passkeys-api.2fa.directory/v1/all.json';
const CDN_FETCH_TIMEOUT_MS = 15_000;
const MAX_CONCURRENT_BREACH_CHECKS = 5;
const COMMON_PASSWORDS = new Set([
  'password', 'password1', '123456', '12345678', '123456789', 'qwerty', 'abc123', 'letmein', 'welcome', 'iloveyou', 'admin', 'changeme',
]);

export interface PasswordBreachResult {
  count: number | null;
  available: boolean;
}

export interface PasswordSecurityItem {
  cipherId: string;
  exposedCount: number | null;
  reusedCount: number;
  weak: boolean;
  twoFactorSupported: boolean | null;
  twoFactorDocumentation?: string | null;
  passkeySupported: boolean | null;
  passkeyDocumentation?: string | null;
}

export interface PasswordSecurityReport {
  eligibleCount: number;
  checkedCount: number;
  exposedCount: number;
  reusedCount: number;
  weakCount: number;
  unavailableCount: number;
  twoFactorMissingCount: number;
  passkeyAvailableCount: number;
  twoFactorUnavailable: boolean;
  passkeyUnavailable: boolean;
  items: PasswordSecurityItem[];
}

type Candidate = {
  cipherId: string;
  name: string;
  hash: string;
  weak: boolean;
  hostname: string | null;
};

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('').toUpperCase();
}

function isAbortError(error: unknown): boolean {
  return !!error && typeof error === 'object' && 'name' in error && (error as { name?: string }).name === 'AbortError';
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = new Error('The operation was aborted.');
    error.name = 'AbortError';
    throw error;
  }
}

export async function sha1Password(password: string): Promise<string> {
  const input = new TextEncoder().encode(password);
  return bytesToHex(new Uint8Array(await crypto.subtle.digest('SHA-1', input)));
}

function parseRangeResponse(text: string, suffix: string): number {
  for (const line of text.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator !== 35) continue;
    if (line.slice(0, separator).toUpperCase() !== suffix) continue;
    const count = Number.parseInt(line.slice(separator + 1), 10);
    return Number.isSafeInteger(count) && count > 0 ? count : 0;
  }
  return 0;
}

export async function checkPasswordHashLeaked(
  hash: string,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<number> {
  if (!/^[A-F0-9]{40}$/.test(hash)) throw new Error('Password hash is invalid.');
  throwIfAborted(signal);
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), 12_000);
  const onExternalAbort = () => controller.abort();
  signal?.addEventListener('abort', onExternalAbort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetchImpl(`${PWNED_PASSWORDS_RANGE_URL}${hash.slice(0, 5)}`, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers: { 'Add-Padding': 'true' },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Pwned Passwords returned ${response.status}.`);
    return parseRangeResponse(await response.text(), hash.slice(5));
  } catch (error) {
    // External cancel (leave page / re-scan) must stay distinguishable from timeout/network failures.
    if (signal?.aborted) {
      const abortError = new Error('The operation was aborted.');
      abortError.name = 'AbortError';
      throw abortError;
    }
    if (isAbortError(error)) throw new Error('Pwned Passwords request timed out.');
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener('abort', onExternalAbort);
  }
}

export async function checkPasswordLeaked(
  password: string,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<PasswordBreachResult> {
  if (!password) return { count: 0, available: true };
  try {
    return { count: await checkPasswordHashLeaked(await sha1Password(password), fetchImpl, signal), available: true };
  } catch (error) {
    if (isAbortError(error) || signal?.aborted) throw error;
    return { count: null, available: false };
  }
}

function hasSimpleSequence(value: string): boolean {
  const normalized = value.toLowerCase();
  return ['0123456789', '9876543210', 'abcdefghijklmnopqrstuvwxyz', 'zyxwvutsrqponmlkjihgfedcba', 'qwertyuiop', 'poiuytrewq']
    .some((sequence) => sequence.includes(normalized) || normalized.includes(sequence.slice(0, 5)));
}

export function isWeakPassword(password: string, username: string = ''): boolean {
  const normalized = password.toLowerCase();
  const compactUsername = username.split('@')[0]?.trim().toLowerCase() || '';
  if (COMMON_PASSWORDS.has(normalized) || password.length < 10) return true;
  if (/^(.)\1+$/.test(password) || hasSimpleSequence(password)) return true;
  if (compactUsername.length >= 3 && normalized.includes(compactUsername)) return true;
  const classes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)].filter(Boolean).length;
  return password.length < 14 && classes < 3;
}

interface TwoFactorDirectoryEntry {
  methods?: string[];
  documentation?: string | null;
  [key: string]: unknown;
}

interface PasskeyDirectoryEntry {
  passwordless?: string;
  mfa?: string;
  documentation?: string | null;
  [key: string]: unknown;
}

let twoFactorData: Record<string, TwoFactorDirectoryEntry> | null = null;
let twoFactorDataError = false;
let passkeyData: Record<string, PasskeyDirectoryEntry> | null = null;
let passkeyDataError = false;

async function loadTwoFactorData(fetchImpl: typeof fetch, signal?: AbortSignal): Promise<Record<string, TwoFactorDirectoryEntry> | null> {
  if (twoFactorDataError) return null;
  if (twoFactorData) return twoFactorData;
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), CDN_FETCH_TIMEOUT_MS);
  const onExternalAbort = () => controller.abort();
  signal?.addEventListener('abort', onExternalAbort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetchImpl(TWO_FACTOR_DIRECTORY_URL, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`2FA directory returned ${response.status}.`);
    twoFactorData = (await response.json()) as Record<string, TwoFactorDirectoryEntry>;
    return twoFactorData;
  } catch (error) {
    if (isAbortError(error) || signal?.aborted) throw new Error('The operation was aborted.');
    twoFactorDataError = true;
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener('abort', onExternalAbort);
  }
}

async function loadPasskeyData(fetchImpl: typeof fetch, signal?: AbortSignal): Promise<Record<string, PasskeyDirectoryEntry> | null> {
  if (passkeyDataError) return null;
  if (passkeyData) return passkeyData;
  const controller = new AbortController();
  const timeout = globalThis.setTimeout(() => controller.abort(), CDN_FETCH_TIMEOUT_MS);
  const onExternalAbort = () => controller.abort();
  signal?.addEventListener('abort', onExternalAbort, { once: true });
  if (signal?.aborted) controller.abort();
  try {
    const response = await fetchImpl(PASSKEY_DIRECTORY_URL, {
      method: 'GET',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Passkey directory returned ${response.status}.`);
    passkeyData = (await response.json()) as Record<string, PasskeyDirectoryEntry>;
    return passkeyData;
  } catch (error) {
    if (isAbortError(error) || signal?.aborted) throw new Error('The operation was aborted.');
    passkeyDataError = true;
    return null;
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener('abort', onExternalAbort);
  }
}

function extractHostname(value: string | null | undefined): string | null {
  if (!value) return null;
  try {
    return new URL(value).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return null;
  }
}

function isEligibleCipher(cipher: Cipher): boolean {
  return Number(cipher.type) === 1 && !cipher.deletedDate && !(cipher as { deletedAt?: string | null }).deletedAt && !!cipher.login?.decPassword;
}

async function mapWithConcurrency<T, R>(
  values: T[],
  limit: number,
  worker: (value: T) => Promise<R>,
  signal?: AbortSignal,
): Promise<R[]> {
  const results = new Array<R>(values.length);
  let nextIndex = 0;
  const run = async () => {
    while (true) {
      throwIfAborted(signal);
      const index = nextIndex;
      nextIndex += 1;
      if (index >= values.length) return;
      results[index] = await worker(values[index]);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, run));
  return results;
}

export async function inspectVaultPasswordSecurity(
  ciphers: Cipher[],
  onProgress?: (checked: number, total: number) => void,
  fetchImpl: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<PasswordSecurityReport> {
  throwIfAborted(signal);
  const eligible = ciphers.filter(isEligibleCipher);
  const candidates: Candidate[] = await Promise.all(eligible.map(async (cipher) => {
    throwIfAborted(signal);
    const password = String(cipher.login?.decPassword || '');
    const username = String(cipher.login?.decUsername || '');
    const loginUri = cipher.login?.uris?.[0]?.decUri || cipher.login?.uri || null;
    return {
      cipherId: cipher.id,
      name: String(cipher.decName || cipher.name || ''),
      hash: await sha1Password(password),
      weak: isWeakPassword(password, username),
      hostname: extractHostname(loginUri),
    };
  }));
  const candidatesByHash = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const group = candidatesByHash.get(candidate.hash) || [];
    group.push(candidate);
    candidatesByHash.set(candidate.hash, group);
  }

  const exposureByHash = new Map<string, PasswordBreachResult>();
  let checked = 0;
  await mapWithConcurrency([...candidatesByHash.keys()], MAX_CONCURRENT_BREACH_CHECKS, async (hash) => {
    throwIfAborted(signal);
    let result: PasswordBreachResult;
    try {
      result = { count: await checkPasswordHashLeaked(hash, fetchImpl, signal), available: true };
    } catch (error) {
      if (isAbortError(error) || signal?.aborted) throw error;
      result = { count: null, available: false };
    }
    exposureByHash.set(hash, result);
    checked += candidatesByHash.get(hash)?.length || 0;
    onProgress?.(Math.min(checked, candidates.length), candidates.length);
    return result;
  }, signal);

  throwIfAborted(signal);

  let twoFactorDirectory: Record<string, TwoFactorDirectoryEntry> | null = null;
  let passkeyDirectory: Record<string, PasskeyDirectoryEntry> | null = null;
  let twoFactorUnavailable = false;
  let passkeyUnavailable = false;
  try {
    [twoFactorDirectory, passkeyDirectory] = await Promise.all([
      loadTwoFactorData(fetchImpl, signal),
      loadPasskeyData(fetchImpl, signal),
    ]);
  } catch (error) {
    if (isAbortError(error) || signal?.aborted) throw error;
    // CDN fetch failed; directories remain null, *DataError flags set upstream.
  }
  if (twoFactorDataError) twoFactorUnavailable = true;
  if (passkeyDataError) passkeyUnavailable = true;

  const items = candidates.map((candidate) => {
    const exposure = exposureByHash.get(candidate.hash) || { count: null, available: false };
    let twoFactorSupported: boolean | null = null;
    let twoFactorDocumentation: string | null = null;
    if (twoFactorDirectory && candidate.hostname) {
      const entry = twoFactorDirectory[candidate.hostname];
      if (entry) {
        twoFactorSupported = Array.isArray(entry.methods) && entry.methods.length > 0;
        twoFactorDocumentation = entry.documentation || null;
      } else {
        twoFactorSupported = false;
      }
    } else if (!twoFactorDirectory && !twoFactorDataError) {
      twoFactorSupported = null;
    }
    let passkeySupported: boolean | null = null;
    let passkeyDocumentation: string | null = null;
    if (passkeyDirectory && candidate.hostname) {
      const entry = passkeyDirectory[candidate.hostname];
      if (entry) {
        passkeySupported = entry.passwordless === 'allowed' || entry.mfa === 'allowed';
        passkeyDocumentation = entry.documentation || null;
      } else {
        passkeySupported = false;
      }
    } else if (!passkeyDirectory && !passkeyDataError) {
      passkeySupported = null;
    }
    return {
      cipherId: candidate.cipherId,
      exposedCount: exposure.count,
      reusedCount: candidatesByHash.get(candidate.hash)?.length || 1,
      weak: candidate.weak,
      twoFactorSupported,
      twoFactorDocumentation,
      passkeySupported,
      passkeyDocumentation,
    };
  }).filter((item) => item.exposedCount === null || (item.exposedCount || 0) > 0 || item.reusedCount > 1 || item.weak || item.twoFactorSupported === false || item.passkeySupported === true)
    .sort((a, b) => (Number(b.exposedCount || 0) - Number(a.exposedCount || 0)) || (b.reusedCount - a.reusedCount) || Number(b.weak) - Number(a.weak) || a.cipherId.localeCompare(b.cipherId));

  const twoFactorMissingCount = items.filter((item) => item.twoFactorSupported === false).length;
  const passkeyAvailableCount = items.filter((item) => item.passkeySupported === true).length;

  return {
    eligibleCount: candidates.length,
    checkedCount: checked,
    exposedCount: candidates.filter((candidate) => (exposureByHash.get(candidate.hash)?.count || 0) > 0).length,
    reusedCount: candidates.filter((candidate) => (candidatesByHash.get(candidate.hash)?.length || 0) > 1).length,
    weakCount: candidates.filter((candidate) => candidate.weak).length,
    unavailableCount: candidates.filter((candidate) => exposureByHash.get(candidate.hash)?.count === null).length,
    twoFactorMissingCount,
    passkeyAvailableCount,
    twoFactorUnavailable,
    passkeyUnavailable,
    items,
  };
}
