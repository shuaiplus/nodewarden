import { drizzleAdapter } from '@better-auth/drizzle-adapter';
import { sso } from '@better-auth/sso';
import { eq } from 'drizzle-orm';
import { betterAuth } from 'better-auth/minimal';
import { bearer } from 'better-auth/plugins/bearer';

import { getOrm } from './db/client';
import { account, session, users, verification } from './db/schema';
import { hashPassword, verifyBetterAuthPassword } from './services/auth-password';
import type { Env } from './types';

const AUTH_TABLES = {
  user: users,
  session,
  account,
  verification,
};

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
    // Sessions stay in D1 so disable/delete revocation cannot be undone by stale KV entries.
    rateLimit: env?.CACHE_KV
      ? {
          customStorage: {
            get: async (key) => {
              const value = await env.CACHE_KV!.get(key);
              return value ? JSON.parse(value) : null;
            },
            set: async (key, value) => {
              // ponytail: built-in windows are at most 60s; raise this with any longer custom rule.
              await env.CACHE_KV!.put(key, JSON.stringify(value), { expirationTtl: 60 });
            },
          },
        }
      : undefined,
    emailAndPassword: {
      enabled: true,
      password: {
        hash: hashPassword,
        verify: verifyBetterAuthPassword,
      },
    },
    databaseHooks: {
      session: {
        create: {
          before: async (session) => {
            if (!orm) return false;
            const [user] = await orm.select({ status: users.status }).from(users).where(eq(users.id, session.userId));
            return user?.status === 'active' ? { data: session } : false;
          },
        },
      },
    },
    session: {
      storeSessionInDatabase: true,
      expiresIn: 60 * 60 * 24 * 30,
    },
    user: {
      deleteUser: { enabled: false },
      changeEmail: { enabled: false },
      additionalFields: {
        masterPasswordHash: { type: 'string', required: true, input: false },
        masterPasswordHint: { type: 'string', required: false, input: false },
        key: { type: 'string', required: true, input: false },
        securityStamp: { type: 'string', required: true, input: false },
        role: { type: 'string', required: false, input: false },
        status: { type: 'string', required: false, input: false },
      },
    },
    plugins: [bearer(), sso()],
    trustedOrigins: [origin],
    advanced: {
      ipAddress: {
        ipAddressHeaders: ['cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'],
      },
    },
  });
}

export type AppAuth = ReturnType<typeof createAuth>;
