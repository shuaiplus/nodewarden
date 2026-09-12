// 共享测试夹具：按**生产同样的方式**建库 + 常用种子数据。
//
// 为什么需要 resetStorageServiceStatics()：
//   `StorageService` 上有几个 `private static` 的"已初始化"标志
//   （schemaVerified / attachmentTokenTableReady / …cleanupAt）。它们的作用是
//   "每个 isolate 只做一次"，这在生产里是对的，但在测试里同一进程会建**多个**库 ——
//   不重置的话只有第一个库会真正执行 `ensureStorageSchema()`，后续库会缺表缺索引，
//   报出与业务逻辑无关的错。测试里重置它们等价于"模拟一个全新 isolate"。
import { readFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';
import path from 'node:path';

import type { D1Database } from '@cloudflare/workers-types';
import { countAccountPasskeyCredentialsByUserId } from '../../src/services/storage-account-passkey-repo';
import { AuthService } from '../../src/services/auth';
import { RateLimitService } from '../../src/services/ratelimit';
import { StorageService } from '../../src/services/storage';
import { createD1SqliteDatabase, type D1SqliteDatabase } from './d1-sqlite';

const REPO_ROOT = path.resolve(import.meta.dirname, '..', '..');
const MIGRATION_SQL = readFileSync(path.join(REPO_ROOT, 'migrations', '0001_init.sql'), 'utf8');

/** 固定时间戳，让断言可复现 */
export const FIXED_NOW = '2026-01-01T00:00:00.000Z';

/**
 * 生成合法的 Bitwarden EncString。
 * 服务端会校验"加密串"格式（`isValidEncString`）：type 2 = AES-CBC-HMAC，
 * 需 `2.<iv>|<data>|<mac>` 三段。传明文会被 400 拒绝。
 */
export function enc(label: string): string {
  return `2.${label}-iv|${label}-data|${label}-mac`;
}

/** 重置所有进程级的"已初始化 / 上次清理时间"标志，模拟全新 isolate */
export function resetProcessScopedStatics(): void {
  Object.assign(StorageService as unknown as Record<string, unknown>, {
    schemaVerified: false,
    attachmentTokenTableReady: false,
    lastRefreshTokenCleanupAt: 0,
    lastAttachmentTokenCleanupAt: 0,
    lastTotpReplayCleanupAt: 0,
  } satisfies Partial<Record<string, unknown>>);

  Object.assign(RateLimitService as unknown as Record<string, unknown>, {
    loginIpTableReady: false,
    strictBudgetTableReady: false,
    lastLoginIpCleanupAt: 0,
    lastStrictBudgetCleanupAt: 0,
  });

  // AuthService 的两个 static Map 缓存跨库泄漏：同一个 email 在第二个库里
  // 可能拿到第一个库缓存的用户对象（例如把 disabled 用户认成 active）。
  // 它们没有公开的清空接口，直接取字段清。
  for (const field of ['userCache', 'deviceCache']) {
    const cache = (AuthService as unknown as Record<string, unknown>)[field];
    if (cache instanceof Map) cache.clear();
  }
}

/** 测试用的 JWT 密钥。值与 `.dev.vars` 保持一致的形态（真实部署用自己的值）。 */
export const TEST_JWT_SECRET = 'test-jwt-secret-at-least-32-characters-long';

/**
 * 建一个"生产同款"的库：
 *   ① 跑 `migrations/0001_init.sql`（新库基线）
 *   ② 调 `StorageService.initializeDatabase()` 补上运行时 schema（索引 / 新列 / 管理员兜底）
 * 第 ② 步刻意调用**生产入口**而不是自己重放 `SCHEMA_STATEMENTS` ——
 * 后者夹着一堆 `ALTER TABLE ... ADD COLUMN`，迁移里已有该列时会报
 * `duplicate column name`，真实实现靠 `executeSchemaStatement()` 吞掉这类错误。
 */
export async function createSchemaDatabase(): Promise<D1SqliteDatabase> {
  const handle = createD1SqliteDatabase();
  handle.connection.exec(MIGRATION_SQL);
  resetProcessScopedStatics();
  await new StorageService(handle.db).initializeDatabase();
  await warmUpLazySchemaEnsures(handle.db);
  return handle;
}

/**
 * 预热**模块级**惰性 schema 初始化。
 *
 * `storage-account-passkey-repo.ts` 里有一个模块级的 `accountPasskeySchemaReady` 标志，
 * 首次调用 passkey 相关方法时会先跑一轮建表/补列（实测约 39 条 DDL）。
 * 它只在**进程内第一次**发生 —— 也就是说：第一个建库的测试会额外看到这 39 条，
 * 后续测试看不到。如果测试要断言"查询条数"，这个一次性的差值就是纯粹的噪声
 * （实测会让 3 用户与 8 用户的对比变成 49 : 10，方向都是反的）。
 *
 * 所以在夹具里主动跑掉它，让每个库都处在同样的"已预热"状态。
 * 顺带一提：生产上这意味着**每个 isolate 的第一个请求**会多付这些 DDL 的开销，
 * 属既有设计（"每个 isolate 只做一次"），本文件不改变它。
 */
async function warmUpLazySchemaEnsures(db: D1Database): Promise<void> {
  await countAccountPasskeyCredentialsByUserId(db, '__warmup__', 'twoFactor');
  // 限流服务的两张表也是惰性创建的，同样预热掉
  const rateLimit = new RateLimitService(db);
  await rateLimit.checkLoginAttempt('__warmup__').catch(() => undefined);
}

export interface InsertUserOptions {
  email?: string;
  name?: string;
  role?: string;
  status?: string;
  createdAt?: string;
  /** 第二层（服务端）密码哈希。用 `AuthService.hashPasswordServer()` 生成，不要手写 */
  masterPasswordHash?: string;
  /** 客户端加密后的用户对称密钥 */
  key?: string;
  /** 设置 YubiKey 公钥 ID（任意非空字符串即可让 isYubiKeyEnabled() 为真） */
  yubikeyKey1?: string;
}

/** 插入一个用户，只填测试需要关心的列，其余给固定默认值 */
export function insertUser(connection: DatabaseSync, id: string, options: InsertUserOptions = {}): void {
  const createdAt = options.createdAt ?? FIXED_NOW;
  connection
    .prepare(
      'INSERT INTO users (id, email, name, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, verify_devices, created_at, updated_at) ' +
        'VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run(
      id,
      options.email ?? `${id}@example.test`,
      options.name ?? id,
      options.masterPasswordHash ?? 'master-hash',
      options.key ?? 'wrapped-key',
      0,
      600000,
      `stamp-${id}`,
      options.role ?? 'user',
      options.status ?? 'active',
      0,
      createdAt,
      createdAt
    );
  if (options.yubikeyKey1 !== undefined) {
    connection
      .prepare('UPDATE users SET yubikey_key1 = ? WHERE id = ?')
      .run(options.yubikeyKey1, id);
  }
}
