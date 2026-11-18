import type { VaultDraftField } from './types';

// Keep metadata on each draft field so removing or reordering fields cannot
// accidentally attach another field's link or unknown encrypted properties.
export function cipherFieldMetadata(field: object): Pick<VaultDraftField, 'linkedId' | 'extra'> {
  const raw = field as Record<string, unknown>;
  return {
    ...(typeof raw.linkedId === 'number' || raw.linkedId === null ? { linkedId: raw.linkedId } : {}),
    extra: Object.fromEntries(Object.entries(raw).filter(([key]) =>
      !['type', 'name', 'value', 'linkedId'].includes(key) && !/^dec[A-Z]/.test(key)
    )),
  };
}
