interface AliasedValue<T> {
  present: boolean;
  value: T | null | undefined;
}

function readOwnAliasedValue<T>(source: unknown, aliases: readonly string[]): AliasedValue<T> {
  if (!source || typeof source !== 'object') {
    return { present: false, value: undefined };
  }

  const record = source as Record<string, unknown>;
  for (const alias of aliases) {
    if (Object.prototype.hasOwnProperty.call(record, alias)) {
      return { present: true, value: record[alias] as T | null | undefined };
    }
  }

  return { present: false, value: undefined };
}

/**
 * Full cipher updates use replacement semantics for nullable fields.
 * Bitwarden clients may omit a property after its value is cleared, so an
 * absent property must become null instead of falling back to stored data.
 */
export function readNullableFullUpdateField<T>(
  source: unknown,
  aliases: readonly string[]
): T | null {
  const incoming = readOwnAliasedValue<T>(source, aliases);
  return incoming.present ? incoming.value ?? null : null;
}
