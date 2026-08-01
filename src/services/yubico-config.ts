import {
  requestYubicoApiCredentials,
  type YubicoApiCredentials,
} from '../utils/yubico-otp';

export const YUBICO_CLIENT_ID_CONFIG_KEY = 'globalSettings__yubico__clientId';
export const YUBICO_SECRET_KEY_CONFIG_KEY = 'globalSettings__yubico__key';
export const YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY = 'yubico.bootstrap.claim.v1';

const YUBICO_BOOTSTRAP_CLAIM_TTL_MS = 2 * 60 * 1000;

export interface YubicoCredentialInitializationResult {
  credentials: YubicoApiCredentials;
  created: boolean;
}

export async function getYubicoCredentials(db: D1Database): Promise<YubicoApiCredentials | null> {
  const result = await db
    .prepare('SELECT key, value FROM config WHERE key IN (?, ?)')
    .bind(YUBICO_CLIENT_ID_CONFIG_KEY, YUBICO_SECRET_KEY_CONFIG_KEY)
    .all<{ key: string; value: string }>();
  const values = new Map((result.results || []).map((row) => [row.key, String(row.value || '').trim()]));
  const clientId = values.get(YUBICO_CLIENT_ID_CONFIG_KEY) || '';
  const secretKey = values.get(YUBICO_SECRET_KEY_CONFIG_KEY) || '';
  return clientId && secretKey ? { clientId, secretKey } : null;
}

export async function replaceYubicoCredentials(
  db: D1Database,
  credentials: YubicoApiCredentials
): Promise<void> {
  const clientId = String(credentials.clientId || '').trim();
  const secretKey = String(credentials.secretKey || '').trim();
  if (!clientId || !secretKey) throw new Error('Yubico credentials are incomplete');
  await db.batch([
    db.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(YUBICO_CLIENT_ID_CONFIG_KEY, clientId),
    db.prepare(
      'INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    ).bind(YUBICO_SECRET_KEY_CONFIG_KEY, secretKey),
  ]);
}

async function acquireBootstrapClaim(db: D1Database): Promise<string | null> {
  const now = Date.now();
  await db
    .prepare('DELETE FROM config WHERE key = ? AND CAST(value AS INTEGER) < ?')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, now)
    .run();
  const claim = `${now + YUBICO_BOOTSTRAP_CLAIM_TTL_MS}:${crypto.randomUUID()}`;
  const result = await db
    .prepare('INSERT OR IGNORE INTO config(key, value) VALUES(?, ?)')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, claim)
    .run();
  return (result.meta.changes ?? 0) > 0 ? claim : null;
}

async function releaseBootstrapClaim(db: D1Database, claim: string): Promise<void> {
  await db
    .prepare('DELETE FROM config WHERE key = ? AND value = ?')
    .bind(YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, claim)
    .run();
}

export async function initializeYubicoCredentialsOnce(
  db: D1Database,
  email: string,
  otp: string
): Promise<YubicoCredentialInitializationResult | null> {
  const existing = await getYubicoCredentials(db);
  if (existing) return { credentials: existing, created: false };

  const claim = await acquireBootstrapClaim(db);
  if (!claim) {
    const concurrentlyCreated = await getYubicoCredentials(db);
    return concurrentlyCreated ? { credentials: concurrentlyCreated, created: false } : null;
  }

  try {
    const rechecked = await getYubicoCredentials(db);
    if (rechecked) return { credentials: rechecked, created: false };

    const issued = await requestYubicoApiCredentials(email, otp);
    if (!issued?.clientId || !issued.secretKey) return null;

    const configuredDuringRequest = await getYubicoCredentials(db);
    if (configuredDuringRequest) {
      return { credentials: configuredDuringRequest, created: false };
    }

    await replaceYubicoCredentials(db, issued);
    return { credentials: issued, created: true };
  } finally {
    await releaseBootstrapClaim(db, claim).catch(() => undefined);
  }
}
