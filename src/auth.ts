import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { sso } from '@better-auth/sso';
import { betterAuth } from 'better-auth/minimal';
import { bearer } from 'better-auth/plugins/bearer';
import { twoFactor } from 'better-auth/plugins/two-factor';

import { getOrm } from './db/client';
import { account, session, twoFactor as twoFactorTable, users, verification } from './db/schema';
import { hashPassword, verifyBetterAuthPassword } from './services/auth-password';
import type { Env } from './types';

const AUTH_TABLES = {
  user: users,
  session,
  account,
  verification,
  twoFactor: twoFactorTable,
};

function kvSecondaryStorage(kv: KVNamespace) {
  return {
    get: (key: string) => kv.get(key),
    set: async (key: string, value: string, ttl?: number) => {
      await kv.put(key, value, ttl ? { expirationTtl: Math.max(60, ttl) } : undefined);
    },
    delete: (key: string) => kv.delete(key),
  };
}

export function createAuth(env?: Pick<Env, 'DB' | 'JWT_SECRET' | 'CACHE_KV'>, request?: Request) {
  const origin = request ? new URL(request.url).origin : 'http://localhost';
  const orm = env?.DB ? getOrm(env.DB) : undefined;

  return betterAuth({
    appName: 'NodeWarden',
    baseURL: origin,
    secret: env?.JWT_SECRET,
    database: orm
      ? drizzleAdapter(orm as never, { provider: 'sqlite', schema: AUTH_TABLES, transaction: false })
      : undefined,
    secondaryStorage: env?.CACHE_KV ? kvSecondaryStorage(env.CACHE_KV) : undefined,
    emailAndPassword: {
      enabled: true,
      password: {
        hash: hashPassword,
        verify: verifyBetterAuthPassword,
      },
    },
    session: {
      storeSessionInDatabase: true,
      expiresIn: 60 * 60 * 24 * 30,
    },
    user: {
      additionalFields: {
        masterPasswordHash: { type: 'string', required: true, input: false },
        masterPasswordHint: { type: 'string', required: false, input: false },
        key: { type: 'string', required: true, input: false },
        securityStamp: { type: 'string', required: true, input: false },
        role: { type: 'string', required: false, input: false },
        status: { type: 'string', required: false, input: false },
      },
    },
    plugins: [
      bearer(),
      twoFactor({ issuer: 'NodeWarden' }),
      sso(),
    ],
    trustedOrigins: [origin],
    advanced: {
      ipAddress: {
        ipAddressHeaders: ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'],
      },
    },
  });
}

export type AppAuth = ReturnType<typeof createAuth>;
