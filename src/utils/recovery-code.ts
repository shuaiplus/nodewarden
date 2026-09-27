import { constantTimeEquals } from './api-key';

const RECOVERY_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const RECOVERY_ALPHABET_LENGTH = RECOVERY_ALPHABET.length;
const RECOVERY_MAX_UNBIASED_BYTE = Math.floor(256 / RECOVERY_ALPHABET_LENGTH) * RECOVERY_ALPHABET_LENGTH;

function normalizeRecoveryCode(raw: string): string {
  return String(raw || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

function formatRecoveryCode(compact: string): string {
  return compact.replace(/(.{4})/g, '$1 ').trim();
}

export function createRecoveryCode(): string {
  let compact = '';
  while (compact.length < 32) {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    for (const b of bytes) {
      if (b >= RECOVERY_MAX_UNBIASED_BYTE) continue;
      compact += RECOVERY_ALPHABET[b % RECOVERY_ALPHABET_LENGTH];
      if (compact.length >= 32) break;
    }
  }
  return formatRecoveryCode(compact.slice(0, 32));
}

export function recoveryCodeEquals(input: string, storedCode: string | null | undefined): boolean {
  return !!storedCode && constantTimeEquals(normalizeRecoveryCode(input), normalizeRecoveryCode(storedCode));
}
