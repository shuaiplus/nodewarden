import { and, asc, count, eq, isNotNull, isNull, lt, or } from 'drizzle-orm';

import { getOrm } from '../db/client';
import { webauthnChallenges, webauthnCredentials } from '../db/schema';
import type { AccountPasskeyChallenge, AccountPasskeyChallengeScope, AccountPasskeyCredential } from '../types';

function parseTransports(value: string | null): string[] | null {
  if (!value) return null;
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed)) return null;
    return parsed.map((item) => String(item || '').trim()).filter(Boolean);
  } catch {
    return null;
  }
}

function mapCredentialRow(row: typeof webauthnCredentials.$inferSelect): AccountPasskeyCredential {
  return {
    id: row.id,
    userId: row.userId,
    purpose: row.purpose === 'twoFactor' ? 'twoFactor' : 'login',
    name: row.name,
    publicKey: row.publicKey,
    credentialId: row.credentialId,
    counter: Number(row.counter || 0),
    type: row.type ?? null,
    aaGuid: row.aaGuid ?? null,
    transports: parseTransports(row.transports),
    encryptedUserKey: row.encryptedUserKey ?? null,
    encryptedPublicKey: row.encryptedPublicKey ?? null,
    encryptedPrivateKey: row.encryptedPrivateKey ?? null,
    supportsPrf: !!row.supportsPrf,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

function mapChallengeRow(row: typeof webauthnChallenges.$inferSelect): AccountPasskeyChallenge {
  return {
    challengeHash: row.challengeHash,
    scope: row.scope as AccountPasskeyChallengeScope,
    userId: row.userId ?? null,
    expiresAt: Number(row.expiresAt || 0),
    usedAt: row.usedAt == null ? null : Number(row.usedAt),
    createdAt: Number(row.createdAt || 0),
  };
}

export async function saveAccountPasskeyCredential(
  db: D1Database,
  credential: AccountPasskeyCredential
): Promise<void> {
  const values = {
    id: credential.id,
    userId: credential.userId,
    purpose: credential.purpose,
    name: credential.name,
    publicKey: credential.publicKey,
    credentialId: credential.credentialId,
    counter: credential.counter,
    type: credential.type,
    aaGuid: credential.aaGuid,
    transports: credential.transports ? JSON.stringify(credential.transports) : null,
    encryptedUserKey: credential.encryptedUserKey,
    encryptedPublicKey: credential.encryptedPublicKey,
    encryptedPrivateKey: credential.encryptedPrivateKey,
    supportsPrf: credential.supportsPrf ? 1 : 0,
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt,
  };
  await getOrm(db)
    .insert(webauthnCredentials)
    .values(values)
    .onConflictDoUpdate({
      target: webauthnCredentials.id,
      set: {
        purpose: values.purpose,
        name: values.name,
        publicKey: values.publicKey,
        credentialId: values.credentialId,
        counter: values.counter,
        type: values.type,
        aaGuid: values.aaGuid,
        transports: values.transports,
        encryptedUserKey: values.encryptedUserKey,
        encryptedPublicKey: values.encryptedPublicKey,
        encryptedPrivateKey: values.encryptedPrivateKey,
        supportsPrf: values.supportsPrf,
        updatedAt: values.updatedAt,
      },
    });
}

export async function listAccountPasskeyCredentialsByUserId(
  db: D1Database,
  userId: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<AccountPasskeyCredential[]> {
  const rows = await getOrm(db)
    .select()
    .from(webauthnCredentials)
    .where(and(eq(webauthnCredentials.userId, userId), eq(webauthnCredentials.purpose, purpose)))
    .orderBy(asc(webauthnCredentials.createdAt));
  return rows.map(mapCredentialRow);
}

export async function getAccountPasskeyCredentialById(
  db: D1Database,
  userId: string,
  id: string
): Promise<AccountPasskeyCredential | null> {
  const [row] = await getOrm(db)
    .select()
    .from(webauthnCredentials)
    .where(and(eq(webauthnCredentials.userId, userId), eq(webauthnCredentials.id, id)))
    .limit(1);
  return row ? mapCredentialRow(row) : null;
}

export async function getAccountPasskeyCredentialByCredentialId(
  db: D1Database,
  credentialId: string
): Promise<AccountPasskeyCredential | null> {
  const [row] = await getOrm(db)
    .select()
    .from(webauthnCredentials)
    .where(eq(webauthnCredentials.credentialId, credentialId))
    .limit(1);
  return row ? mapCredentialRow(row) : null;
}

export async function countAccountPasskeyCredentialsByUserId(
  db: D1Database,
  userId: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<number> {
  const [row] = await getOrm(db)
    .select({ count: count() })
    .from(webauthnCredentials)
    .where(and(eq(webauthnCredentials.userId, userId), eq(webauthnCredentials.purpose, purpose)));
  return Number(row?.count || 0);
}

export async function updateAccountPasskeyCounter(
  db: D1Database,
  userId: string,
  credentialId: string,
  counter: number,
  updatedAt: string
): Promise<void> {
  await getOrm(db)
    .update(webauthnCredentials)
    .set({ counter, updatedAt })
    .where(and(eq(webauthnCredentials.userId, userId), eq(webauthnCredentials.credentialId, credentialId)));
}

export async function updateAccountPasskeyEncryption(
  db: D1Database,
  userId: string,
  credentialId: string,
  encryptedUserKey: string,
  encryptedPublicKey: string,
  encryptedPrivateKey: string,
  updatedAt: string
): Promise<boolean> {
  const result = await getOrm(db)
    .update(webauthnCredentials)
    .set({
      encryptedUserKey,
      encryptedPublicKey,
      encryptedPrivateKey,
      supportsPrf: 1,
      updatedAt,
    })
    .where(and(
      eq(webauthnCredentials.userId, userId),
      eq(webauthnCredentials.credentialId, credentialId),
      eq(webauthnCredentials.purpose, 'login'),
    ))
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function deleteAccountPasskeyCredential(
  db: D1Database,
  userId: string,
  id: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login'
): Promise<boolean> {
  const result = await getOrm(db)
    .delete(webauthnCredentials)
    .where(and(
      eq(webauthnCredentials.userId, userId),
      eq(webauthnCredentials.id, id),
      eq(webauthnCredentials.purpose, purpose),
    ))
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function saveAccountPasskeyChallenge(
  db: D1Database,
  challenge: AccountPasskeyChallenge
): Promise<void> {
  const orm = getOrm(db);
  await orm
    .delete(webauthnChallenges)
    .where(or(lt(webauthnChallenges.expiresAt, Date.now()), isNotNull(webauthnChallenges.usedAt)));
  await orm
    .insert(webauthnChallenges)
    .values({
      challengeHash: challenge.challengeHash,
      scope: challenge.scope,
      userId: challenge.userId,
      expiresAt: challenge.expiresAt,
      usedAt: challenge.usedAt,
      createdAt: challenge.createdAt,
    })
    .onConflictDoUpdate({
      target: webauthnChallenges.challengeHash,
      set: {
        scope: challenge.scope,
        userId: challenge.userId,
        expiresAt: challenge.expiresAt,
        usedAt: challenge.usedAt,
        createdAt: challenge.createdAt,
      },
    });
}

export async function consumeAccountPasskeyChallenge(
  db: D1Database,
  challengeHash: string,
  scope: AccountPasskeyChallengeScope,
  userId: string | null,
  nowMs: number
): Promise<AccountPasskeyChallenge | null> {
  const orm = getOrm(db);
  const [row] = await orm
    .select()
    .from(webauthnChallenges)
    .where(and(eq(webauthnChallenges.challengeHash, challengeHash), eq(webauthnChallenges.scope, scope)))
    .limit(1);
  if (!row) return null;
  const challenge = mapChallengeRow(row);
  if (challenge.usedAt != null || challenge.expiresAt < nowMs) return null;
  if (userId !== null && challenge.userId !== userId) return null;
  if (userId === null && challenge.userId !== null) return null;

  const result = await orm
    .update(webauthnChallenges)
    .set({ usedAt: nowMs })
    .where(and(eq(webauthnChallenges.challengeHash, challengeHash), isNull(webauthnChallenges.usedAt)))
    .run();
  if (Number(result.meta.changes || 0) <= 0) return null;
  return { ...challenge, usedAt: nowMs };
}
