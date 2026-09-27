import { AwsClient } from 'aws4fetch';
import { sha256 } from 'hono/utils/crypto';
import {
  BackupDestinationRecord,
  BackupDestinationType,
  S3BackupDestination,
  WebDavBackupDestination,
  normalizeBackupEndpointUrl,
} from './backup-config';

export interface BackupUploadResult {
  provider: BackupDestinationType;
  remotePath: string;
}

export interface RemoteBackupItem {
  path: string;
  name: string;
  isDirectory: boolean;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteBackupListResult {
  provider: BackupDestinationType;
  currentPath: string;
  parentPath: string | null;
  items: RemoteBackupItem[];
}

export interface RemoteBackupFile {
  provider: BackupDestinationType;
  remotePath: string;
  fileName: string;
  contentType: string;
  bytes: Uint8Array;
}

export interface RemoteBackupFileStat {
  provider: BackupDestinationType;
  remotePath: string;
  size: number | null;
  modifiedAt: string | null;
}

export interface RemoteBackupFilePutOptions {
  contentType?: string;
}

function encodePathSegments(path: string): string {
  return path
    .split('/')
    .filter(Boolean)
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

function trimSlashes(value: string): string {
  let next = String(value || '');
  while (next.startsWith('/')) next = next.slice(1);
  while (next.endsWith('/')) next = next.slice(0, -1);
  return next;
}

function buildJoinedPath(...segments: string[]): string {
  return segments.map(trimSlashes).filter(Boolean).join('/');
}

function normalizeRelativePath(path: string): string {
  const normalized = trimSlashes(path).replace(/\\/g, '/');
  if (!normalized) return '';
  const parts = normalized.split('/').filter(Boolean);
  if (parts.some((part) => part === '.' || part === '..')) {
    throw new Error('Invalid remote backup path');
  }
  return parts.join('/');
}

function basename(path: string): string {
  const normalized = trimSlashes(path);
  if (!normalized) return '';
  const parts = normalized.split('/').filter(Boolean);
  return parts[parts.length - 1] || '';
}

function parentPath(path: string): string | null {
  const normalized = normalizeRelativePath(path);
  if (!normalized) return null;
  const parts = normalized.split('/');
  parts.pop();
  return parts.length ? parts.join('/') : '';
}

function sortRemoteItems(items: RemoteBackupItem[]): RemoteBackupItem[] {
  return items.slice().sort((a, b) => {
    const aIsAttachmentsDir = a.isDirectory && a.name === 'attachments';
    const bIsAttachmentsDir = b.isDirectory && b.name === 'attachments';
    if (aIsAttachmentsDir !== bIsAttachmentsDir) return aIsAttachmentsDir ? -1 : 1;
    if (a.isDirectory !== b.isDirectory) return a.isDirectory ? -1 : 1;
    return a.name.localeCompare(b.name, 'en');
  });
}

function parseHttpDate(value: string): string | null {
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function extractXmlBlocks(xml: string, tagName: string): string[] {
  const pattern = new RegExp(`<(?:[^:>]+:)?${tagName}\\b[^>]*>([\\s\\S]*?)</(?:[^:>]+:)?${tagName}>`, 'gi');
  const blocks: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(xml))) {
    blocks.push(match[1]);
  }
  return blocks;
}

function extractXmlFirst(xml: string, tagName: string): string | null {
  const pattern = new RegExp(`<(?:[^:>]+:)?${tagName}\\b[^>]*>([\\s\\S]*?)</(?:[^:>]+:)?${tagName}>`, 'i');
  const match = xml.match(pattern);
  // Decode XML's predefined entities; any other reference stays as written.
  return match?.[1]
    ? match[1]
        .trim()
        .replace(
          /&(amp|lt|gt|quot|#39);/g,
          (_match, entity: string) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" })[entity]!,
        )
    : null;
}

function toBasicAuthHeader(username: string, password: string): string {
  const token = btoa(`${username}:${password}`);
  return `Basic ${token}`;
}

function buildWebDavUrl(baseUrl: string, relativePath: string): string {
  const trimmedBase = baseUrl.replace(/\/+$/, '');
  const normalized = normalizeRelativePath(relativePath);
  return normalized ? `${trimmedBase}/${encodePathSegments(normalized)}` : trimmedBase;
}

function webDavFullPath(config: WebDavBackupDestination, relativePath: string): string {
  return buildJoinedPath(config.remotePath, normalizeRelativePath(relativePath));
}

async function putToWebDav(
  config: WebDavBackupDestination,
  relativePath: string,
  bytes: Uint8Array,
  options: RemoteBackupFilePutOptions = {},
  ensuredDirectories?: Set<string>,
): Promise<void> {
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remoteFilePath = buildJoinedPath(config.remotePath, relativePath);
  const remoteDir = parentPath(remoteFilePath);

  if (remoteDir) {
    // Create each parent collection in turn; a transfer session remembers the ones already created.
    const segments = trimSlashes(remoteDir).split('/').filter(Boolean);
    let current = '';
    for (const segment of segments) {
      current = buildJoinedPath(current, segment);
      if (ensuredDirectories?.has(current)) continue;
      const url = buildWebDavUrl(config.baseUrl, current);
      const response = await fetch(url, {
        method: 'MKCOL',
        headers: {
          Authorization: authHeader,
        },
      });
      if ([200, 201, 204, 405].includes(response.status)) {
        ensuredDirectories?.add(current);
        continue;
      }
      throw new Error(`WebDAV directory creation failed: ${response.status}`);
    }
  }

  const response = await fetch(buildWebDavUrl(config.baseUrl, remoteFilePath), {
    method: 'PUT',
    headers: {
      Authorization: authHeader,
      'Content-Type': options.contentType || 'application/octet-stream',
      'Content-Length': String(bytes.byteLength),
    },
    body: bytes,
  });

  if (!response.ok) {
    throw new Error(`WebDAV upload failed: ${response.status}`);
  }
}

async function statWebDavFile(
  config: WebDavBackupDestination,
  relativePath: string,
): Promise<RemoteBackupFileStat | null> {
  const authHeader = toBasicAuthHeader(config.username, config.password);
  const remotePath = webDavFullPath(config, relativePath);
  const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
    method: 'HEAD',
    headers: {
      Authorization: authHeader,
    },
  });
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`WebDAV existence check failed: ${response.status}`);
  }
  const size = Number(response.headers.get('Content-Length') || '');
  return {
    provider: 'webdav',
    remotePath: normalizeRelativePath(relativePath),
    size: Number.isFinite(size) ? size : null,
    modifiedAt: parseHttpDate(response.headers.get('Last-Modified') || ''),
  };
}

function s3BucketBaseUrl(config: S3BackupDestination): URL {
  const endpoint = new URL(config.endpoint.replace(/\/+$/, ''));
  const bucket = config.bucket.trim();

  if (config.addressingStyle === 'virtual-hosted-style') {
    // An endpoint whose host already starts with the bucket is used as is.
    const hostname = endpoint.hostname.toLowerCase();
    const bucketName = bucket.toLowerCase();
    if (!!bucketName && (hostname === bucketName || hostname.startsWith(`${bucketName}.`))) return endpoint;
    endpoint.hostname = `${bucket}.${endpoint.hostname}`;
    return endpoint;
  }

  return new URL(`${endpoint.toString().replace(/\/+$/, '')}/${encodeURIComponent(bucket)}`);
}

function s3ObjectUrl(config: S3BackupDestination, objectKey: string): URL {
  return new URL(`${s3BucketBaseUrl(config).toString().replace(/\/+$/, '')}/${encodePathSegments(objectKey)}`);
}

function normalizeS3ObjectKey(config: S3BackupDestination, relativePath: string): string {
  return buildJoinedPath(config.rootPath, normalizeRelativePath(relativePath));
}

async function signedS3Request(
  config: S3BackupDestination,
  method: 'GET' | 'PUT' | 'DELETE' | 'HEAD',
  url: URL,
  body?: Uint8Array,
  contentType?: string,
): Promise<Response> {
  // aws4fetch retries 5xx/429 by default; callers already surface failures, so keep a single attempt.
  const client = new AwsClient({
    accessKeyId: config.accessKeyId,
    secretAccessKey: config.secretAccessKey,
    service: 's3',
    region: config.region || 'auto',
    retries: 0,
  });
  // Upload bodies are signed by hash, as before aws4fetch, so a plain-http endpoint cannot swap the archive
  // in transit; reads keep aws4fetch's UNSIGNED-PAYLOAD default.
  const headers: Record<string, string> =
    method === 'PUT' && body
      ? {
          'Content-Type': contentType || 'application/octet-stream',
          'X-Amz-Content-Sha256': (await sha256(body)) ?? 'UNSIGNED-PAYLOAD',
        }
      : {};
  return client.fetch(url, { method, headers, body });
}

async function statS3File(config: S3BackupDestination, relativePath: string): Promise<RemoteBackupFileStat | null> {
  const objectKey = normalizeS3ObjectKey(config, relativePath);
  const url = s3ObjectUrl(config, objectKey);
  const response = await signedS3Request(config, 'HEAD', url);
  if (response.status === 404) return null;
  if (!response.ok) {
    throw new Error(`S3 existence check failed: ${response.status}`);
  }
  const size = Number(response.headers.get('Content-Length') || '');
  return {
    provider: 's3',
    remotePath: normalizeRelativePath(relativePath),
    size: Number.isFinite(size) ? size : null,
    modifiedAt: parseHttpDate(response.headers.get('Last-Modified') || ''),
  };
}

interface ConfiguredDestinationAdapter {
  provider: 'webdav' | 's3';
  config: WebDavBackupDestination | S3BackupDestination;
  putFile: (
    config: WebDavBackupDestination | S3BackupDestination,
    relativePath: string,
    bytes: Uint8Array,
    options?: RemoteBackupFilePutOptions,
  ) => Promise<void>;
  list: (
    config: WebDavBackupDestination | S3BackupDestination,
    relativePath: string,
  ) => Promise<RemoteBackupListResult>;
  download: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<RemoteBackupFile>;
  deleteFile: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<void>;
  exists: (config: WebDavBackupDestination | S3BackupDestination, relativePath: string) => Promise<boolean>;
  stat: (
    config: WebDavBackupDestination | S3BackupDestination,
    relativePath: string,
  ) => Promise<RemoteBackupFileStat | null>;
}

export interface RemoteBackupTransferSession {
  provider: BackupDestinationType;
  uploadArchive(archive: Uint8Array, fileName: string): Promise<BackupUploadResult>;
  putFile(relativePath: string, bytes: Uint8Array, options?: RemoteBackupFilePutOptions): Promise<void>;
  list(relativePath: string): Promise<RemoteBackupListResult>;
  download(relativePath: string): Promise<RemoteBackupFile>;
  deleteFile(relativePath: string): Promise<void>;
  exists(relativePath: string): Promise<boolean>;
  stat(relativePath: string): Promise<RemoteBackupFileStat | null>;
}

// Every transfer re-checks the destination first, including the SSRF policy on its endpoint.
function resolveConfiguredDestinationAdapter(destination: BackupDestinationRecord): ConfiguredDestinationAdapter {
  if (destination.type === 'webdav') {
    const webdav = destination.destination as WebDavBackupDestination;
    if (!String(webdav.baseUrl || '').trim()) throw new Error('WebDAV server URL is required');
    normalizeBackupEndpointUrl(String(webdav.baseUrl || '').trim(), 'WebDAV server URL');
    if (!String(webdav.username || '').trim()) throw new Error('WebDAV username is required');
    if (!String(webdav.password || '')) throw new Error('WebDAV password is required');
    return {
      provider: 'webdav',
      config: webdav,
      putFile: (config, relativePath, bytes, options) =>
        putToWebDav(config as WebDavBackupDestination, relativePath, bytes, options),
      list: async (destinationConfig, relativePath) => {
        const config = destinationConfig as WebDavBackupDestination;
        const currentPath = normalizeRelativePath(relativePath);
        const targetFullPath = webDavFullPath(config, currentPath);
        const authHeader = toBasicAuthHeader(config.username, config.password);
        const response = await fetch(buildWebDavUrl(config.baseUrl, targetFullPath), {
          method: 'PROPFIND',
          headers: {
            Authorization: authHeader,
            Depth: '1',
            'Content-Type': 'application/xml; charset=utf-8',
          },
          body: `<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><resourcetype/><getcontentlength/><getlastmodified/></prop></propfind>`,
        });
        if (response.status === 404) {
          return {
            provider: 'webdav',
            currentPath,
            parentPath: parentPath(currentPath),
            items: [],
          };
        }
        if (!response.ok) {
          throw new Error(`WebDAV listing failed: ${response.status}`);
        }

        const xml = await response.text();
        const rootFullPath = trimSlashes(config.remotePath);
        const items: RemoteBackupItem[] = [];
        for (const block of extractXmlBlocks(xml, 'response')) {
          const href = extractXmlFirst(block, 'href');
          if (!href) continue;
          // An href is a URL or an absolute path: resolve it against the server URL, then drop the server's own path.
          const base = new URL(config.baseUrl);
          const target = new URL(href, base);
          const basePath = trimSlashes(decodeURIComponent(base.pathname));
          const entryPath = trimSlashes(decodeURIComponent(target.pathname));
          const serverRelativePath = !basePath
            ? entryPath
            : entryPath === basePath
              ? ''
              : entryPath.startsWith(`${basePath}/`)
                ? entryPath.slice(basePath.length + 1)
                : entryPath;
          const fullPath = trimSlashes(serverRelativePath);
          if (!fullPath) continue;
          if (fullPath === targetFullPath) continue;
          if (rootFullPath && !(fullPath === rootFullPath || fullPath.startsWith(`${rootFullPath}/`))) continue;
          const relative = rootFullPath
            ? fullPath === rootFullPath
              ? ''
              : fullPath.slice(rootFullPath.length + 1)
            : fullPath;
          if (!relative) continue;
          const directParent = parentPath(relative);
          if ((directParent || '') !== currentPath) continue;

          const resourceTypeBlock = extractXmlFirst(block, 'resourcetype') || '';
          const isDirectory = /<(?:[^:>]+:)?collection\b/i.test(resourceTypeBlock);
          const sizeRaw = extractXmlFirst(block, 'getcontentlength');
          const modifiedAtRaw = extractXmlFirst(block, 'getlastmodified');
          items.push({
            path: relative,
            name: basename(relative) || relative,
            isDirectory,
            size: !isDirectory && sizeRaw && Number.isFinite(Number(sizeRaw)) ? Number(sizeRaw) : null,
            modifiedAt: modifiedAtRaw ? parseHttpDate(modifiedAtRaw) : null,
          });
        }

        return {
          provider: 'webdav',
          currentPath,
          parentPath: parentPath(currentPath),
          items: sortRemoteItems(items),
        };
      },
      download: async (destinationConfig, relativePath) => {
        const config = destinationConfig as WebDavBackupDestination;
        const normalized = normalizeRelativePath(relativePath);
        if (!normalized || normalized.endsWith('/')) {
          throw new Error('Please select a backup file');
        }
        const authHeader = toBasicAuthHeader(config.username, config.password);
        const remotePath = webDavFullPath(config, normalized);
        const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
          method: 'GET',
          headers: {
            Authorization: authHeader,
          },
        });
        if (!response.ok) {
          throw new Error(`WebDAV download failed: ${response.status}`);
        }
        return {
          provider: 'webdav',
          remotePath: normalized,
          fileName: basename(normalized) || 'backup.zip',
          contentType: String(response.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip',
          bytes: new Uint8Array(await response.arrayBuffer()),
        };
      },
      deleteFile: async (destinationConfig, relativePath) => {
        const config = destinationConfig as WebDavBackupDestination;
        const authHeader = toBasicAuthHeader(config.username, config.password);
        const remotePath = webDavFullPath(config, relativePath);
        const response = await fetch(buildWebDavUrl(config.baseUrl, remotePath), {
          method: 'DELETE',
          headers: {
            Authorization: authHeader,
          },
        });
        if (!response.ok && response.status !== 404) {
          throw new Error(`WebDAV delete failed: ${response.status}`);
        }
      },
      exists: async (config, relativePath) =>
        (await statWebDavFile(config as WebDavBackupDestination, relativePath)) !== null,
      stat: (config, relativePath) => statWebDavFile(config as WebDavBackupDestination, relativePath),
    };
  }
  if (destination.type === 's3') {
    const s3 = destination.destination as S3BackupDestination;
    if (!String(s3.endpoint || '').trim()) throw new Error('S3 endpoint is required');
    normalizeBackupEndpointUrl(String(s3.endpoint || '').trim(), 'S3 endpoint');
    if (!String(s3.bucket || '').trim()) throw new Error('S3 bucket is required');
    if (!String(s3.accessKeyId || '').trim()) throw new Error('S3 access key is required');
    if (!String(s3.secretAccessKey || '')) throw new Error('S3 secret key is required');
    return {
      provider: 's3',
      config: s3,
      putFile: async (destinationConfig, relativePath, bytes, options = {}) => {
        const config = destinationConfig as S3BackupDestination;
        const objectKey = normalizeS3ObjectKey(config, relativePath);
        const url = s3ObjectUrl(config, objectKey);
        const response = await signedS3Request(config, 'PUT', url, bytes, options.contentType);

        if (!response.ok) {
          throw new Error(`S3 upload failed: ${response.status}`);
        }
      },
      list: async (destinationConfig, relativePath) => {
        const config = destinationConfig as S3BackupDestination;
        const currentPath = normalizeRelativePath(relativePath);
        const targetPrefixBase = normalizeS3ObjectKey(config, currentPath);
        const targetPrefix = trimSlashes(targetPrefixBase) ? `${trimSlashes(targetPrefixBase)}/` : '';
        const rootPrefix = trimSlashes(config.rootPath);
        const items: RemoteBackupItem[] = [];
        let continuationToken = '';

        do {
          const url = s3BucketBaseUrl(config);
          url.searchParams.set('list-type', '2');
          url.searchParams.set('delimiter', '/');
          if (targetPrefix) url.searchParams.set('prefix', targetPrefix);
          if (continuationToken) url.searchParams.set('continuation-token', continuationToken);

          const response = await signedS3Request(config, 'GET', url);
          if (!response.ok) {
            throw new Error(`S3 listing failed: ${response.status}`);
          }

          const xml = await response.text();

          for (const prefix of extractXmlBlocks(xml, 'CommonPrefixes')) {
            const fullPrefix = trimSlashes(extractXmlFirst(prefix, 'Prefix') || '');
            if (!fullPrefix) continue;
            const relative = rootPrefix
              ? fullPrefix === rootPrefix
                ? ''
                : fullPrefix.startsWith(`${rootPrefix}/`)
                  ? fullPrefix.slice(rootPrefix.length + 1)
                  : ''
              : fullPrefix;
            const normalizedRelative = trimSlashes(relative);
            if (!normalizedRelative) continue;
            const itemPath = normalizedRelative.replace(/\/+$/, '');
            if ((parentPath(itemPath) || '') !== currentPath) continue;
            items.push({
              path: itemPath,
              name: basename(itemPath) || itemPath,
              isDirectory: true,
              size: null,
              modifiedAt: null,
            });
          }

          for (const content of extractXmlBlocks(xml, 'Contents')) {
            const fullKey = trimSlashes(extractXmlFirst(content, 'Key') || '');
            if (!fullKey || (targetPrefix && fullKey === trimSlashes(targetPrefix))) continue;
            const relative = rootPrefix
              ? fullKey.startsWith(`${rootPrefix}/`)
                ? fullKey.slice(rootPrefix.length + 1)
                : ''
              : fullKey;
            const normalizedRelative = trimSlashes(relative);
            if (!normalizedRelative || (parentPath(normalizedRelative) || '') !== currentPath) continue;
            items.push({
              path: normalizedRelative,
              name: basename(normalizedRelative) || normalizedRelative,
              isDirectory: false,
              size: Number(extractXmlFirst(content, 'Size') || 0) || null,
              modifiedAt: parseHttpDate(extractXmlFirst(content, 'LastModified') || '') || null,
            });
          }

          continuationToken = extractXmlFirst(xml, 'NextContinuationToken') || '';
        } while (continuationToken);

        const deduped = new Map<string, RemoteBackupItem>();
        for (const item of items) deduped.set(`${item.isDirectory ? 'd' : 'f'}:${item.path}`, item);

        return {
          provider: 's3',
          currentPath,
          parentPath: parentPath(currentPath),
          items: sortRemoteItems(Array.from(deduped.values())),
        };
      },
      download: async (destinationConfig, relativePath) => {
        const config = destinationConfig as S3BackupDestination;
        const normalized = normalizeRelativePath(relativePath);
        if (!normalized || normalized.endsWith('/')) {
          throw new Error('Please select a backup file');
        }
        const objectKey = normalizeS3ObjectKey(config, normalized);
        const url = s3ObjectUrl(config, objectKey);
        const response = await signedS3Request(config, 'GET', url);
        if (!response.ok) {
          throw new Error(`S3 download failed: ${response.status}`);
        }
        return {
          provider: 's3',
          remotePath: normalized,
          fileName: basename(normalized) || 'backup.zip',
          contentType: String(response.headers.get('Content-Type') || 'application/zip').trim() || 'application/zip',
          bytes: new Uint8Array(await response.arrayBuffer()),
        };
      },
      deleteFile: async (destinationConfig, relativePath) => {
        const config = destinationConfig as S3BackupDestination;
        const objectKey = normalizeS3ObjectKey(config, relativePath);
        const url = s3ObjectUrl(config, objectKey);
        const response = await signedS3Request(config, 'DELETE', url);
        if (!response.ok && response.status !== 404) {
          throw new Error(`S3 delete failed: ${response.status}`);
        }
      },
      exists: async (config, relativePath) => (await statS3File(config as S3BackupDestination, relativePath)) !== null,
      stat: (config, relativePath) => statS3File(config as S3BackupDestination, relativePath),
    };
  }

  throw new Error('Unsupported backup destination type');
}

export function createRemoteBackupTransferSession(destination: BackupDestinationRecord): RemoteBackupTransferSession {
  const adapter = resolveConfiguredDestinationAdapter(destination);
  const ensuredDirectories = adapter.provider === 'webdav' ? new Set<string>() : null;

  const putFile = async (
    relativePath: string,
    bytes: Uint8Array,
    options: RemoteBackupFilePutOptions = {},
  ): Promise<void> => {
    const normalized = normalizeRelativePath(relativePath);
    if (adapter.provider === 'webdav' && ensuredDirectories) {
      await putToWebDav(adapter.config as WebDavBackupDestination, normalized, bytes, options, ensuredDirectories);
      return;
    }
    await adapter.putFile(adapter.config, normalized, bytes, options);
  };

  return {
    provider: adapter.provider,
    uploadArchive: async (archive: Uint8Array, fileName: string) => {
      await putFile(fileName, archive, { contentType: 'application/zip' });
      return {
        provider: adapter.provider,
        remotePath:
          adapter.provider === 'webdav'
            ? buildJoinedPath((adapter.config as WebDavBackupDestination).remotePath, fileName)
            : normalizeS3ObjectKey(adapter.config as S3BackupDestination, fileName),
      };
    },
    putFile,
    list: async (relativePath: string) => adapter.list(adapter.config, relativePath),
    download: async (relativePath: string) => adapter.download(adapter.config, relativePath),
    deleteFile: async (relativePath: string) => adapter.deleteFile(adapter.config, normalizeRelativePath(relativePath)),
    exists: async (relativePath: string) => adapter.exists(adapter.config, normalizeRelativePath(relativePath)),
    stat: async (relativePath: string) => adapter.stat(adapter.config, normalizeRelativePath(relativePath)),
  };
}

export async function uploadBackupArchive(
  destination: BackupDestinationRecord,
  archive: Uint8Array,
  fileName: string,
): Promise<BackupUploadResult> {
  return createRemoteBackupTransferSession(destination).uploadArchive(archive, fileName);
}

export async function listRemoteBackupEntries(
  destination: BackupDestinationRecord,
  relativePath: string,
): Promise<RemoteBackupListResult> {
  return createRemoteBackupTransferSession(destination).list(relativePath);
}

export async function downloadRemoteBackupFile(
  destination: BackupDestinationRecord,
  relativePath: string,
): Promise<RemoteBackupFile> {
  return createRemoteBackupTransferSession(destination).download(relativePath);
}

export async function deleteRemoteBackupFile(
  destination: BackupDestinationRecord,
  relativePath: string,
): Promise<void> {
  const normalized = ensureRemoteRestoreCandidate(relativePath);
  await createRemoteBackupTransferSession(destination).deleteFile(normalized);
}

export async function remoteBackupFileExists(
  destination: BackupDestinationRecord,
  relativePath: string,
): Promise<boolean> {
  const normalized = normalizeRelativePath(relativePath);
  return createRemoteBackupTransferSession(destination).exists(normalized);
}

export async function uploadRemoteBackupFile(
  destination: BackupDestinationRecord,
  relativePath: string,
  bytes: Uint8Array,
  options: RemoteBackupFilePutOptions = {},
): Promise<void> {
  const normalized = normalizeRelativePath(relativePath);
  await createRemoteBackupTransferSession(destination).putFile(normalized, bytes, options);
}

export async function pruneRemoteBackupArchives(
  destination: BackupDestinationRecord,
  retentionCount: number | null,
  preferredFileName?: string,
): Promise<number> {
  if (retentionCount === null) return 0;
  const adapter = resolveConfiguredDestinationAdapter(destination);
  const listing = await adapter.list(adapter.config, '');
  // The archive just uploaded ranks first so retention never deletes it, then newer archives, then by name.
  const backupFiles = listing.items
    .filter((item) => !item.isDirectory && /\.zip$/i.test(String(item.name || '').trim()))
    .sort((a, b) => {
      if (preferredFileName) {
        const aPreferred = a.name === preferredFileName ? 1 : 0;
        const bPreferred = b.name === preferredFileName ? 1 : 0;
        if (aPreferred !== bPreferred) return bPreferred - aPreferred;
      }
      const aTime = a.modifiedAt ? new Date(a.modifiedAt).getTime() : 0;
      const bTime = b.modifiedAt ? new Date(b.modifiedAt).getTime() : 0;
      if (aTime !== bTime) return bTime - aTime;
      return b.name.localeCompare(a.name, 'en');
    });
  if (backupFiles.length <= retentionCount) return 0;
  for (const item of backupFiles.slice(retentionCount)) {
    await adapter.deleteFile(adapter.config, item.path);
  }
  return backupFiles.length - retentionCount;
}

export function ensureRemoteRestoreCandidate(relativePath: string): string {
  const normalized = normalizeRelativePath(relativePath);
  if (!normalized || !/\.zip$/i.test(normalized)) {
    throw new Error('Please select a backup ZIP file');
  }
  return normalized;
}
