import { and, eq, gt, lt } from 'drizzle-orm';

import { twoFactorClearStatements } from './two-factor-providers';
import { readEnvConfig } from '../config/env';
import { abortUnlessChanged, getOrm, userRowMatches } from '../db/client';
import { users, verification } from '../db/schema';
import { jsonExtract, jsonSet } from '../db/sql';
import type { Env, User } from '../types';
import { constantTimeEquals, hashApiKey } from '../utils/api-key';
import { readAuthRequestDeviceInfo } from '../utils/device';

const PURPOSE = 'sso-continuation';
const TTL_MS = 5 * 60 * 1000;
const TOMBSTONE_TTL_MS = 24 * 60 * 60 * 1000;

export interface SsoContinuationContext { id: string; binding: string }
export interface SsoContinuation extends SsoContinuationContext {
  userId: string;
  email: string;
  securityStamp: string;
}

export async function ssoContinuationContext(env: Env, request: Request, body: Record<string, unknown>, code: string): Promise<SsoContinuationContext> {
  const origin = new URL(request.url).origin;
  const { SSO_AUTHORITY, SSO_CLIENT_ID } = readEnvConfig(env);
  const provider = [SSO_AUTHORITY, SSO_CLIENT_ID];
  const device = readAuthRequestDeviceInfo(body, request);
  return {
    id: `${PURPOSE}:${await hashApiKey(JSON.stringify([...provider, code]))}`,
    binding: await hashApiKey(JSON.stringify([origin, body.client_id || '', body.redirect_uri || '', body.code_verifier || '', body.scope || '', device.deviceIdentifier, device.deviceType])),
  };
}

// Missing permits the first IdP exchange; an expired, consumed or mismatched row never does.
export async function getSsoContinuation(env: Env, context: SsoContinuationContext): Promise<SsoContinuation | null | undefined> {
  const row = await getOrm(env.DB).select({ value: verification.value, expiresAt: verification.expiresAt }).from(verification)
    .where(and(eq(verification.id, context.id), eq(verification.identifier, PURPOSE))).get();
  if (!row) return undefined;
  const value = JSON.parse(row.value) as SsoContinuation & { consumed: boolean; expiresAt: number };
  if (row.expiresAt <= Date.now() || !(value.expiresAt > Date.now()) || value.consumed || !constantTimeEquals(value.binding, context.binding)) return null;
  return { ...context, userId: value.userId, email: value.email, securityStamp: value.securityStamp };
}

export async function saveSsoContinuation(env: Env, context: SsoContinuationContext, user: User): Promise<SsoContinuation | null> {
  const now = Date.now();
  const value = { ...context, userId: user.id, email: user.email, securityStamp: user.securityStamp };
  const orm = getOrm(env.DB);
  const [, result] = await orm.batch([
    // Better Auth globally deletes expired verification rows, so keep tombstones beyond the logical login window.
    orm.delete(verification).where(and(eq(verification.identifier, PURPOSE), lt(verification.expiresAt, now))),
    orm.insert(verification).values({
      id: context.id, identifier: PURPOSE, value: JSON.stringify({ ...value, consumed: false, expiresAt: now + TTL_MS }),
      expiresAt: now + TOMBSTONE_TTL_MS, createdAt: now, updatedAt: now,
    }).onConflictDoNothing({ target: verification.id }),
  ]);
  return result.meta.changes ? value : null;
}

export async function consumeSsoContinuation(env: Env, continuation: SsoContinuation, user: User, recovery?: { recoveryCode: string; securityStamp: string }): Promise<boolean> {
  const now = Date.now();
  const orm = getOrm(env.DB);
  const claim = orm.update(verification).set({ value: jsonSet(verification.value, '$.consumed', 1), updatedAt: now })
    .where(and(
      eq(verification.id, continuation.id), eq(verification.identifier, PURPOSE), gt(verification.expiresAt, now),
      gt(jsonExtract(verification.value, '$.expiresAt'), now),
      eq(jsonExtract(verification.value, '$.consumed'), 0),
      eq(jsonExtract(verification.value, '$.binding'), continuation.binding),
      eq(jsonExtract(verification.value, '$.userId'), user.id),
      eq(jsonExtract(verification.value, '$.securityStamp'), user.securityStamp),
      eq(jsonExtract(verification.value, '$.email'), user.email),
      userRowMatches(orm, user.id, eq(users.status, 'active'), eq(users.securityStamp, user.securityStamp), eq(users.email, user.email)),
    ));
  try {
    const [result] = await orm.batch([claim, ...(recovery ? [
      // D1 batches are atomic; a losing claim must not clear factors or rotate the account stamp.
      abortUnlessChanged(orm, 'invalid sso continuation'),
      ...twoFactorClearStatements(env.DB, user.id, recovery),
    ] : [])]);
    return result.meta.changes === 1;
  } catch (error) {
    if (recovery && error instanceof Error && error.message.includes('malformed JSON')) return false;
    throw error;
  }
}
