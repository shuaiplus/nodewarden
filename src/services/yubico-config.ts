import { and, eq, inArray, sql } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { config } from '../db/schema';
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
  const rows = await getOrm(db)
    .select({ key: config.key, value: config.value })
    .from(config)
    .where(inArray(config.key, [YUBICO_CLIENT_ID_CONFIG_KEY, YUBICO_SECRET_KEY_CONFIG_KEY]));
  const values = new Map(rows.map((row) => [row.key, String(row.value || '').trim()]));
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
  const orm = getOrm(db);
  await orm.batch([
    orm.insert(config).values({ key: YUBICO_CLIENT_ID_CONFIG_KEY, value: clientId })
      .onConflictDoUpdate({ target: config.key, set: { value: clientId } }),
    orm.insert(config).values({ key: YUBICO_SECRET_KEY_CONFIG_KEY, value: secretKey })
      .onConflictDoUpdate({ target: config.key, set: { value: secretKey } }),
  ]);
}

async function acquireBootstrapClaim(db: D1Database): Promise<string | null> {
  const now = Date.now();
  const orm = getOrm(db);
  await orm
    .delete(config)
    .where(and(eq(config.key, YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY), sql`cast(${config.value} as integer) < ${now}`));
  const claim = `${now + YUBICO_BOOTSTRAP_CLAIM_TTL_MS}:${crypto.randomUUID()}`;
  const result = await orm
    .insert(config)
    .values({ key: YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY, value: claim })
    .onConflictDoNothing({ target: config.key })
    .run();
  return (result.meta.changes ?? 0) > 0 ? claim : null;
}

async function releaseBootstrapClaim(db: D1Database, claim: string): Promise<void> {
  await getOrm(db)
    .delete(config)
    .where(and(eq(config.key, YUBICO_BOOTSTRAP_CLAIM_CONFIG_KEY), eq(config.value, claim)));
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
