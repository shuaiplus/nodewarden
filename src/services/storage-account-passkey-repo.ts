import { and, asc, count, eq, isNotNull, isNull, lt, ne, or } from 'drizzle-orm';

import { getOrm, userRowMatches } from '../db/client';
import { users, webauthnChallenges, webauthnCredentials } from '../db/schema';
import { SINGLE_ROW, boundRow, coalesce } from '../db/sql';
import type { AccountPasskeyChallenge, AccountPasskeyChallengeScope, AccountPasskeyCredential } from '../types';
import { normalizeTransports } from '../utils/account-passkeys';

function mapCredentialRow(row: typeof webauthnCredentials.$inferSelect): AccountPasskeyCredential {
  let transports: string[] | null = null;
  try {
    if (row.transports) transports = normalizeTransports(JSON.parse(row.transports));
  } catch {
    // Unreadable stored transports read as none.
  }
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
    transports,
    encryptedUserKey: row.encryptedUserKey ?? null,
    encryptedPublicKey: row.encryptedPublicKey ?? null,
    encryptedPrivateKey: row.encryptedPrivateKey ?? null,
    supportsPrf: !!row.supportsPrf,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export async function saveAccountPasskeyCredential(
  db: D1Database,
  credential: AccountPasskeyCredential,
  securityStamp?: string,
): Promise<boolean> {
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
  const orm = getOrm(db);
  const insert = orm.insert(webauthnCredentials);
  // A two-factor key also needs the user to hold a recovery code at that stamp.
  const write =
    securityStamp === undefined
      ? insert.values(values)
      : insert.select(
          orm
            .select(boundRow(values))
            .from(SINGLE_ROW)
            .where(
              userRowMatches(
                orm,
                values.userId,
                eq(users.securityStamp, securityStamp),
                values.purpose === 'twoFactor' ? ne(coalesce(users.totpRecoveryCode, ''), '') : undefined,
              ),
            ),
        );
  const result = await write
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
    })
    .run();
  return (result.meta.changes ?? 0) > 0;
}

export async function listAccountPasskeyCredentialsByUserId(
  db: D1Database,
  userId: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login',
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
  id: string,
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
  credentialId: string,
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
  purpose: AccountPasskeyCredential['purpose'] = 'login',
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
  updatedAt = new Date().toISOString(),
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
  updatedAt = new Date().toISOString(),
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
    .where(
      and(
        eq(webauthnCredentials.userId, userId),
        eq(webauthnCredentials.credentialId, credentialId),
        eq(webauthnCredentials.purpose, 'login'),
      ),
    )
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function deleteAccountPasskeyCredential(
  db: D1Database,
  userId: string,
  id: string,
  purpose: AccountPasskeyCredential['purpose'] = 'login',
): Promise<boolean> {
  const result = await getOrm(db)
    .delete(webauthnCredentials)
    .where(
      and(
        eq(webauthnCredentials.userId, userId),
        eq(webauthnCredentials.id, id),
        eq(webauthnCredentials.purpose, purpose),
      ),
    )
    .run();
  return Number(result.meta.changes || 0) > 0;
}

export async function saveAccountPasskeyChallenge(db: D1Database, challenge: AccountPasskeyChallenge): Promise<void> {
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
  nowMs = Date.now(),
): Promise<AccountPasskeyChallenge | null> {
  const orm = getOrm(db);
  const [row] = await orm
    .select()
    .from(webauthnChallenges)
    .where(and(eq(webauthnChallenges.challengeHash, challengeHash), eq(webauthnChallenges.scope, scope)))
    .limit(1);
  if (!row) return null;
  const challenge: AccountPasskeyChallenge = {
    challengeHash: row.challengeHash,
    scope: row.scope as AccountPasskeyChallengeScope,
    userId: row.userId ?? null,
    expiresAt: Number(row.expiresAt || 0),
    usedAt: row.usedAt == null ? null : Number(row.usedAt),
    createdAt: Number(row.createdAt || 0),
  };
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
