import { base64ToBytes, bytesToBase64, hkdfExpand, toBufferSource } from '@/lib/crypto';
import { EFFLongWordList } from '@/lib/fingerprint-wordlist';
import { t } from '@/lib/i18n';
import type { AuthRequest, ListResponse, SessionState } from '@/lib/types';
import type { AuthedFetch } from './shared';
import { parseErrorMessage, parseJson } from './shared';

function readResponseProperty<T>(source: Record<string, any>, camel: string, pascal: string, fallback: T): T {
  return (source[camel] ?? source[pascal] ?? fallback) as T;
}

function normalizeAuthRequest(raw: Record<string, any>): AuthRequest {
  return {
    id: String(readResponseProperty(raw, 'id', 'Id', '')),
    publicKey: String(readResponseProperty(raw, 'publicKey', 'PublicKey', '')),
    requestDeviceType: readResponseProperty(raw, 'requestDeviceType', 'RequestDeviceType', null),
    requestDeviceTypeValue: readResponseProperty(raw, 'requestDeviceTypeValue', 'RequestDeviceTypeValue', null),
    requestDeviceIdentifier: String(readResponseProperty(raw, 'requestDeviceIdentifier', 'RequestDeviceIdentifier', '')),
    requestIpAddress: readResponseProperty(raw, 'requestIpAddress', 'RequestIpAddress', null),
    requestCountryName: readResponseProperty(raw, 'requestCountryName', 'RequestCountryName', null),
    key: readResponseProperty(raw, 'key', 'Key', null),
    creationDate: String(readResponseProperty(raw, 'creationDate', 'CreationDate', '')),
    requestApproved: readResponseProperty(raw, 'requestApproved', 'RequestApproved', null),
    responseDate: readResponseProperty(raw, 'responseDate', 'ResponseDate', null),
    deviceId: readResponseProperty(raw, 'deviceId', 'DeviceId', null),
    requestDeviceId: readResponseProperty(raw, 'requestDeviceId', 'RequestDeviceId', null),
  };
}

async function withFingerprintPhrase(email: string, request: AuthRequest): Promise<AuthRequest> {
  if (!request.publicKey) return request;
  try {
    return {
      ...request,
      fingerprintPhrase: await getFingerprintPhrase(email, base64ToBytes(request.publicKey)),
    };
  } catch {
    return request;
  }
}

export async function listPendingAuthRequests(authedFetch: AuthedFetch, email: string): Promise<AuthRequest[]> {
  const resp = await authedFetch('/api/auth-requests/pending');
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_auth_requests_load_failed')));
  const body = await parseJson<ListResponse<Record<string, any>> & { Data?: Record<string, any>[] }>(resp);
  const rows = (body?.data || body?.Data || []).map(normalizeAuthRequest);
  return Promise.all(rows.map((row) => withFingerprintPhrase(email, row)));
}

export async function respondToAuthRequest(
  authedFetch: AuthedFetch,
  requestId: string,
  payload: {
    key?: string | null;
    deviceIdentifier: string;
    requestApproved: boolean;
  }
): Promise<AuthRequest> {
  const resp = await authedFetch(`/api/auth-requests/${encodeURIComponent(requestId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!resp.ok) throw new Error(await parseErrorMessage(resp, t('txt_auth_request_update_failed')));
  const body = await parseJson<Record<string, any>>(resp);
  if (!body) throw new Error(t('txt_auth_request_update_failed'));
  return normalizeAuthRequest(body);
}

export function isPendingAuthRequest(request: AuthRequest): boolean {
  if (!request.id || !request.creationDate) return false;
  if (request.responseDate) return false;
  const createdAt = new Date(request.creationDate).getTime();
  if (!Number.isFinite(createdAt)) return true;
  return Date.now() - createdAt < 15 * 60 * 1000;
}

export async function encryptSessionUserKeyForAuthRequest(session: SessionState, authRequest: AuthRequest): Promise<string> {
  if (!session.symEncKey || !session.symMacKey) throw new Error(t('txt_vault_key_unavailable'));
  if (!authRequest.publicKey) throw new Error(t('txt_auth_request_missing_public_key'));

  const userKeyBytes = new Uint8Array(64);
  userKeyBytes.set(base64ToBytes(session.symEncKey), 0);
  userKeyBytes.set(base64ToBytes(session.symMacKey), 32);
  const publicKey = await crypto.subtle.importKey(
    'spki',
    toBufferSource(base64ToBytes(authRequest.publicKey)),
    { name: 'RSA-OAEP', hash: 'SHA-1' },
    false,
    ['encrypt']
  );
  const encryptedBytes = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    toBufferSource(userKeyBytes)
  ));
  return `4.${bytesToBase64(encryptedBytes)}`;
}

export async function getFingerprintPhrase(email: string, publicKey: Uint8Array): Promise<string> {
  const keyFingerprint = new Uint8Array(await crypto.subtle.digest('SHA-256', toBufferSource(publicKey)));
  const userFingerprint = await hkdfExpand(keyFingerprint, email.toLowerCase(), 32);
  return hashPhrase(userFingerprint).join('-');
}

function hashPhrase(hash: Uint8Array, minimumEntropy = 64): string[] {
  const entropyPerWord = Math.log(EFFLongWordList.length) / Math.log(2);
  let numWords = Math.ceil(minimumEntropy / entropyPerWord);
  if (numWords * entropyPerWord > hash.length * 4) {
    throw new Error('Output entropy of hash function is too small');
  }

  let hashNumber = 0n;
  for (const byte of hash) {
    hashNumber = (hashNumber * 256n) + BigInt(byte);
  }

  const phrase: string[] = [];
  const wordCount = BigInt(EFFLongWordList.length);
  while (numWords > 0) {
    const remainder = Number(hashNumber % wordCount);
    hashNumber /= wordCount;
    phrase.push(EFFLongWordList[remainder]);
    numWords -= 1;
  }
  return phrase;
}
