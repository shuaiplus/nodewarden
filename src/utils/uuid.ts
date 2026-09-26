// Generate UUID v4
export function generateUUID(): string {
  return crypto.randomUUID();
}

// The hyphenated form is the only one upstream's System.Text.Json binds into a Guid.
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUUID(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}
