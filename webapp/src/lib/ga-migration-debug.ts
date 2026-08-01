/** Secret-safe Google Authenticator migration diagnostics for browser console. */

const PREFIX = '[ga-migration]';

export function describeQrPayload(raw: string): Record<string, unknown> {
  const value = String(raw || '');
  const scheme = value.includes(':') ? value.slice(0, value.indexOf(':')).toLowerCase() : '';
  return {
    length: value.length,
    scheme: scheme || '(none)',
    looksLikeMigration: /^otpauth-migration:/i.test(value),
    looksLikeOtpauth: /^otpauth:/i.test(value),
    hasDataQuery: /[?&]data=/i.test(value),
  };
}

export function gaMigrationDebug(event: string, detail: Record<string, unknown> = {}): void {
  console.info(PREFIX, event, detail);
}

export function gaMigrationWarn(event: string, detail: Record<string, unknown> = {}, error?: unknown): void {
  if (error !== undefined) console.warn(PREFIX, event, detail, error);
  else console.warn(PREFIX, event, detail);
}
