import { twoFactorClearStatements } from './two-factor-providers';
import { readEnvConfig } from '../config/env';
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

export async function ssoContinuationContext(env: Env, request: Request, body: Record<string, string>, code: string): Promise<SsoContinuationContext> {
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
  const row = await env.DB.prepare('SELECT value, expires_at FROM verification WHERE id = ? AND identifier = ?').bind(context.id, PURPOSE).first<{ value: string; expires_at: number }>();
  if (!row) return undefined;
  const value = JSON.parse(row.value) as SsoContinuation & { consumed: boolean; expiresAt: number };
  if (row.expires_at <= Date.now() || !(value.expiresAt > Date.now()) || value.consumed || !constantTimeEquals(value.binding, context.binding)) return null;
  return { ...context, userId: value.userId, email: value.email, securityStamp: value.securityStamp };
}

export async function saveSsoContinuation(env: Env, context: SsoContinuationContext, user: User): Promise<SsoContinuation | null> {
  const now = Date.now();
  const value = { ...context, userId: user.id, email: user.email, securityStamp: user.securityStamp };
  const [, result] = await env.DB.batch([
    // Better Auth globally deletes expired verification rows, so keep tombstones beyond the logical login window.
    env.DB.prepare('DELETE FROM verification WHERE identifier = ? AND expires_at < ?').bind(PURPOSE, now),
    env.DB.prepare('INSERT INTO verification (id, identifier, value, expires_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING').bind(context.id, PURPOSE, JSON.stringify({ ...value, consumed: false, expiresAt: now + TTL_MS }), now + TOMBSTONE_TTL_MS, now, now),
  ]);
  return result.meta.changes ? value : null;
}

export async function consumeSsoContinuation(env: Env, continuation: SsoContinuation, user: User, recovery?: { recoveryCode: string; securityStamp: string }): Promise<boolean> {
  const claim = env.DB.prepare(`UPDATE verification SET value = json_set(value, '$.consumed', 1), updated_at = ?
    WHERE id = ? AND identifier = ? AND expires_at > ? AND json_extract(value, '$.expiresAt') > ? AND json_extract(value, '$.consumed') = 0
      AND json_extract(value, '$.binding') = ? AND json_extract(value, '$.userId') = ? AND json_extract(value, '$.securityStamp') = ? AND json_extract(value, '$.email') = ?
      AND EXISTS (SELECT 1 FROM users WHERE id = ? AND status = 'active' AND security_stamp = ? AND email = ?)`)
    .bind(Date.now(), continuation.id, PURPOSE, Date.now(), Date.now(), continuation.binding, user.id, user.securityStamp, user.email, user.id, user.securityStamp, user.email);
  try {
    const [result] = await env.DB.batch([claim, ...(recovery ? [
      // D1 batches are atomic; a losing claim must not clear factors or rotate the account stamp.
      env.DB.prepare("SELECT CASE WHEN changes() = 0 THEN json('invalid sso continuation') END"),
      ...twoFactorClearStatements(env.DB, user.id, recovery),
    ] : [])]);
    return result.meta.changes === 1;
  } catch (error) {
    if (recovery && error instanceof Error && error.message.includes('malformed JSON')) return false;
    throw error;
  }
}
