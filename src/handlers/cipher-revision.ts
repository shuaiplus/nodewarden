const SECOND_PRECISION_TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$/i;

export function isStaleCipherUpdate(existingUpdatedAt: string, clientRevisionDate: unknown): boolean {
  if (typeof clientRevisionDate !== 'string') return false;
  const clientTs = Date.parse(clientRevisionDate);
  const existingTs = Date.parse(existingUpdatedAt);

  // Bitwarden's SDK truncates cipher revisions to whole seconds on the wire.
  // Compare at that precision without allowing writes from an earlier second.
  if (SECOND_PRECISION_TIMESTAMP.test(clientRevisionDate)) {
    return Math.floor(existingTs / 1000) * 1000 > clientTs;
  }
  return existingTs > clientTs;
}
