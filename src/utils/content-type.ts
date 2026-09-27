const ACTIVE_DOWNLOAD_MEDIA_TYPES = new Set([
  'application/xhtml+xml',
  'application/xml',
  'image/svg+xml',
  'text/html',
  'text/xml',
]);

const SAFE_ICON_MEDIA_TYPES = new Set([
  'image/avif',
  'image/bmp',
  'image/gif',
  'image/jpeg',
  'image/png',
  'image/vnd.microsoft.icon',
  'image/webp',
  'image/x-icon',
]);

function normalizeMediaType(contentType: string | null | undefined): string {
  return String(contentType || '')
    .split(';', 1)[0]
    .trim()
    .toLowerCase();
}

export function isSafeWebsiteIconContentType(contentType: string | null | undefined): boolean {
  return SAFE_ICON_MEDIA_TYPES.has(normalizeMediaType(contentType));
}

export function sanitizeDownloadContentType(contentType: string | null | undefined): string {
  const mediaType = normalizeMediaType(contentType);
  if (!mediaType) return 'application/octet-stream';
  if (ACTIVE_DOWNLOAD_MEDIA_TYPES.has(mediaType)) {
    return 'application/octet-stream';
  }
  return contentType || mediaType;
}

// A quote or line break would end the quoted file name early, so each becomes an underscore, and a
// blank name falls back to the caller's default.
export function contentDispositionAttachment(fileName: string | null | undefined, fallback: string): string {
  const value =
    String(fileName || fallback)
      .replace(/[\r\n"]/g, '_')
      .trim() || fallback;
  return `attachment; filename="${value}"`;
}
