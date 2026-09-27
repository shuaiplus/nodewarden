import type { Cipher } from '../types';

const DEFAULT_DEVICE_NAME = 'Unknown device';
const DEFAULT_DEVICE_TYPE = 14;

function decodeBase64UrlUtf8(value: string): string | null {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    const padded = padding === 0 ? normalized : normalized + '='.repeat(4 - padding);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function normalizeDeviceIdentifier(value: string | undefined | null): string | null {
  if (!value) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  return normalized.slice(0, 128);
}

function normalizeDeviceName(value: string | undefined | null): string {
  const normalized = String(value || '').trim();
  if (!normalized) return DEFAULT_DEVICE_NAME;
  return normalized.slice(0, 128);
}

function parseDeviceType(value: string | number | undefined | null): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.max(0, Math.floor(value));
  }
  const parsed = Number.parseInt(String(value || ''), 10);
  if (Number.isFinite(parsed) && parsed >= 0) return parsed;
  return DEFAULT_DEVICE_TYPE;
}

export interface AuthRequestDeviceInfo {
  deviceIdentifier: string | null;
  deviceName: string;
  deviceType: number;
}

export function readAuthRequestDeviceInfo(
  body: Record<string, string | undefined>,
  request: Request
): AuthRequestDeviceInfo {
  const bodyIdentifier = body.deviceIdentifier || body.device_identifier;
  const headerIdentifier = request.headers.get('X-Device-Identifier') || undefined;
  const bodyName = body.deviceName || body.device_name;
  const headerName = request.headers.get('X-Device-Name') || undefined;
  const bodyType = body.deviceType || body.device_type;
  const headerType = request.headers.get('Device-Type') || undefined;

  return {
    deviceIdentifier: normalizeDeviceIdentifier(bodyIdentifier || headerIdentifier),
    deviceName: normalizeDeviceName(bodyName || headerName),
    deviceType: parseDeviceType(bodyType || headerType),
  };
}

export function readKnownDeviceProbe(request: Request): { email: string | null; deviceIdentifier: string | null } {
  const encodedEmail = request.headers.get('X-Request-Email') || '';
  const decodedEmail = decodeBase64UrlUtf8(encodedEmail);
  const fallbackRawEmail = request.headers.get('X-Request-Email');
  const email = (decodedEmail || fallbackRawEmail || '').trim().toLowerCase() || null;
  const deviceIdentifier = normalizeDeviceIdentifier(request.headers.get('X-Device-Identifier'));
  return { email, deviceIdentifier };
}

export function readActingDeviceIdentifier(request: Request): string | null {
  return normalizeDeviceIdentifier(request.headers.get('X-NodeWarden-Acting-Device-Id'));
}

// The cipher create/update/delete signals carry the same payload: the row, its organization and
// collections, and the acting device so that device's own connection skips the echo.
export function cipherNotifyPayload(cipher: Cipher, revisionDate: string, request: Request) {
  return {
    userId: cipher.userId,
    cipherId: cipher.id,
    revisionDate,
    organizationId: String(cipher.organizationId ?? '').trim() || null,
    collectionIds: Array.isArray(cipher.collectionIds)
      ? cipher.collectionIds.map((id: unknown) => String(id || '').trim()).filter(Boolean)
      : null,
    contextId: readActingDeviceIdentifier(request),
  };
}

export function deviceTypeName(type: number): string {
  const names: Record<number, string> = {
    0: 'Android',
    1: 'iOS',
    2: 'Chrome Extension',
    3: 'Firefox Extension',
    4: 'Opera Extension',
    5: 'Edge Extension',
    6: 'Windows Desktop',
    7: 'macOS Desktop',
    8: 'Linux Desktop',
    9: 'Chrome',
    10: 'Firefox',
    11: 'Opera',
    12: 'Edge',
    13: 'Internet Explorer',
    14: 'Unknown Browser',
    15: 'Android',
    16: 'Windows UWP',
    17: 'Safari',
    18: 'Vivaldi',
    19: 'Vivaldi Extension',
    20: 'Safari Extension',
    21: 'SDK',
    22: 'Server',
    23: 'Windows CLI',
    24: 'macOS CLI',
    25: 'Linux CLI',
    26: 'DuckDuckGo',
  };
  return names[type] || `Device ${type}`;
}

