import { decodeBase64Url } from 'hono/utils/encode';
import { z } from 'zod';
import type { Cipher } from '../types';

const DEFAULT_DEVICE_NAME = 'Unknown device';
const DEFAULT_DEVICE_TYPE = 14;
const DEVICE_TEXT_MAX_LENGTH = 128;

function decodeBase64UrlUtf8(value: string): string | null {
  try {
    return new TextDecoder().decode(decodeBase64Url(value));
  } catch {
    return null;
  }
}

// Device fields come from form posts, JSON bodies and headers. Each is clipped to its column width
// and falls back to a default instead of failing the sign-in it rides on.
export const deviceText = z.string().trim().transform((text) => text.slice(0, DEVICE_TEXT_MAX_LENGTH));
const deviceType = z.coerce.number().int().min(0);
const DeviceIdentifierSchema = deviceText.transform((text) => text || null).catch(null);
export const DeviceInfoSchema = z.object({
  deviceIdentifier: DeviceIdentifierSchema,
  deviceName: deviceText.transform((text) => text || DEFAULT_DEVICE_NAME).catch(DEFAULT_DEVICE_NAME),
  deviceType: deviceType.catch(DEFAULT_DEVICE_TYPE),
});

export type AuthRequestDeviceInfo = z.output<typeof DeviceInfoSchema>;

const firstPresent = (...values: unknown[]) => values.find((value) => value != null && value !== '');

// The body wins over the headers, field by field; official clients name the device in Device-Identifier.
export function readAuthRequestDeviceInfo(body: Record<string, unknown>, request: Request): AuthRequestDeviceInfo {
  return DeviceInfoSchema.parse({
    deviceIdentifier: firstPresent(body.deviceIdentifier, body.device_identifier, request.headers.get('Device-Identifier'), request.headers.get('X-Device-Identifier')),
    deviceName: firstPresent(body.deviceName, body.device_name, request.headers.get('X-Device-Name')),
    deviceType: firstPresent(body.deviceType, body.device_type, request.headers.get('Device-Type')),
  });
}

export function readKnownDeviceProbe(request: Request): { email: string | null; deviceIdentifier: string | null } {
  const encodedEmail = request.headers.get('X-Request-Email') || '';
  const decodedEmail = decodeBase64UrlUtf8(encodedEmail);
  const fallbackRawEmail = request.headers.get('X-Request-Email');
  const email = (decodedEmail || fallbackRawEmail || '').trim().toLowerCase() || null;
  const deviceIdentifier = DeviceIdentifierSchema.parse(request.headers.get('X-Device-Identifier'));
  return { email, deviceIdentifier };
}

export function readActingDeviceIdentifier(request: Request): string | null {
  return DeviceIdentifierSchema.parse(request.headers.get('X-NodeWarden-Acting-Device-Id'));
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

