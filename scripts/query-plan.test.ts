// §3.3 查询计划审计：主要列表/分页查询到底用不用得上索引？
//
// 为什么必须用「运行时采集 + EXPLAIN QUERY PLAN」而不是靠人读代码：
//   "建了索引" ≠ "索引被用上"。列的**顺序**、`WHERE` 里的函数包裹、`ORDER BY` 的方向、
//   `LIKE` 前缀 —— 任何一项不对，SQLite 就会默默退化成全表扫描。代码看起来完全正常，
//   只有在数据量上来之后才表现为"越用越慢"。
//
// 本文件做的事：
//   ① 按**生产同样的方式**建库（迁移建表 → `StorageService.initializeDatabase()` 补索引）
//   ② 用 Proxy 采集被测代码**实际发出**的 SQL（见 scripts/lib/sql-recorder.ts）
//   ③ 对每条 SQL 跑 EXPLAIN QUERY PLAN，判定规则见下
//   ④ 每次运行都打印完整报告，供人工复核
//
// 判定规则（刻意保守，避免假警报）：
//   ✗ 硬失败：`SCAN <表>` —— **不带** `USING`。这是真·全表逐行读。
//   ✓ 通过　：`SCAN <表> USING INDEX ...` —— 全索引扫描。常常是**最优**解：配合
//              `ORDER BY ... LIMIT` 可以顺着索引顺序取前 N 行并提前终止，比
//              "用 WHERE 索引 + 临时 B 树排序"更快。因此只报告、不判失败。
//   ✓ 通过　：`SEARCH <表> USING ...` —— 按索引/主键定位。
//   仅报告　：`USE TEMP B-TREE`（额外排序）。
//
// 运行方式：npm run test:query-plan
import assert from 'node:assert/strict';
import type { DatabaseSync } from 'node:sqlite';
import test from 'node:test';

import { handleSync } from '../src/handlers/sync';
import { RateLimitService } from '../src/services/ratelimit';
import { StorageService } from '../src/services/storage';
import type { D1Database } from '@cloudflare/workers-types';
import type { Env } from '../src/types';
import { createSchemaDatabase, enc, FIXED_NOW, insertUser } from './lib/test-harness';
import { recordQueries } from './lib/sql-recorder';

const USER = 'plan-user';

/**
 * 允许出现裸 `SCAN` 的表 → 理由。
 *
 * 只允许放**确实没有更好解**的情况。不要为了"让测试通过"往这里加东西 ——
 * 先判断是不是缺索引。本方集会顺带校验**没有过期条目**（若某张表已不再被裸扫，
 * 说明可以删掉这一行），避免它变成"技术债墓地"。
 */
const ALLOWED_BARE_SCANS: Record<string, string> = {
  users:
    '管理端全局列用户：查询没有 user 维度的过滤条件，任何计划都得读全表；排序列为 created_at 却没有索引。' +
    '属「管理端低频 + 表规模受注册用户数约束」，为它加索引会在每次用户写入时增加维护成本，不划算。',
  invites:
    '两条语句都扫这张表，但原因不同：' +
    '① `listInvites(includeInactive = true)` 的 `WHERE 1 = 1` 是拼接用的哨兵、无实际过滤，' +
    '`ORDER BY created_at DESC` 也不是 `idx_invites_created_by(created_by, created_at)` 的最左列；' +
    '② 清理语句 `WHERE status != \'active\' OR expires_at <= ?` 里的 `!=` 与 `OR` 都无法用索引 —— ' +
    '**实测加 expires_at 索引后依然是全表扫**。' +
    '邀请码由管理员手动创建，表规模天然很小，故不为此改语句结构或加索引。',
};

/** 用户维度的热路径表：这些表上的 `WHERE user_id = ?` 必须走索引 */
const USER_SCOPED_TABLES = ['ciphers', 'folders', 'sends', 'devices', 'webauthn_credentials'];

/**
 * 要审计的语句类型。
 * `DELETE`/`UPDATE` 也纳入：清理类查询（如"删掉过期的限流记录"）是**周期性全表跑**的，
 * 一旦缺索引，代价会随表增长而线性上升。`INSERT` 不纳入（不涉及扫描）。
 */
const AUDITED_STATEMENT = /^(SELECT|DELETE|UPDATE)\b/i;

interface Plan {
  sql: string;
  details: string[];
  bareScanTables: string[];
  tempBTree: boolean;
}

/** 从 `EXPLAIN QUERY PLAN` 的 detail 里挑出"裸全表扫描"的表名 */
function findBareScans(details: readonly string[]): string[] {
  const tables: string[] = [];
  for (const detail of details) {
    // 不带 USING 的 SCAN 才是真·全表逐行读；`SCAN t USING INDEX ...` 是索引扫描
    const match = /^SCAN ([a-z_][a-z0-9_]*)$/i.exec(detail);
    if (match) tables.push(match[1]);
  }
  return tables;
}

/** 造一份覆盖面够广的数据，让每个读路径都能真正走到查询 */
function seed(connection: DatabaseSync): void {
  insertUser(connection, USER, { email: 'plan@example.test' });

  connection
    .prepare('INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?,?,?,?,?)')
    .run('folder-1', USER, 'folder', FIXED_NOW, FIXED_NOW);

  for (let i = 0; i < 3; i += 1) {
    connection
      .prepare(
        'INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, created_at, updated_at, deleted_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
      )
      .run(
        `cipher-${i}`,
        USER,
        1,
        i === 0 ? 'folder-1' : null,
        enc(`c${i}`),
        null,
        i === 0 ? 1 : 0,
        '{}',
        FIXED_NOW,
        FIXED_NOW,
        // 第 3 条造一个"已软删除"的，好让 includeDeleted 的两条分支都被驱动
        i === 2 ? FIXED_NOW : null
      );
  }

  connection
    .prepare(
      'INSERT INTO sends (id, user_id, type, name, data, key, auth_type, access_count, disabled, created_at, updated_at, deletion_date) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('send-1', USER, 0, enc('send'), '{}', enc('send-key'), 2, 0, 0, FIXED_NOW, FIXED_NOW, '2027-01-01T00:00:00.000Z');

  connection
    .prepare('INSERT INTO attachments (id, cipher_id, file_name, size, size_name, key) VALUES (?,?,?,?,?,?)')
    .run('att-1', 'cipher-0', enc('file'), 10, '10 B', enc('att-key'));

  // devices 的主键是 (user_id, device_identifier)，没有单独的 id 列
  connection
    .prepare(
      'INSERT INTO devices (user_id, device_identifier, name, type, push_token, last_seen_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)'
    )
    .run(USER, 'device-1', 'phone', 1, 'push-1', FIXED_NOW, FIXED_NOW, FIXED_NOW);

  connection
    .prepare('INSERT INTO invites (code, created_by, expires_at, status, created_at, updated_at) VALUES (?,?,?,?,?,?)')
    .run('invite-1', USER, '2027-01-01T00:00:00.000Z', 'active', FIXED_NOW, FIXED_NOW);

  connection
    .prepare(
      'INSERT INTO audit_logs (id, actor_user_id, action, category, level, target_type, target_id, metadata, created_at) VALUES (?,?,?,?,?,?,?,?,?)'
    )
    .run('log-1', USER, 'user.login', 'security', 'info', 'user', USER, '{}', FIXED_NOW);

  // refresh_tokens 的时间列是整数（Unix 毫秒），不是 ISO 字符串
  connection
    .prepare('INSERT INTO refresh_tokens (token, user_id, expires_at, created_at) VALUES (?,?,?,?)')
    .run('token-1', USER, Date.now() + 86_400_000, Date.now());

  connection
    .prepare(
      'INSERT INTO webauthn_credentials (id, user_id, purpose, name, public_key, credential_id, counter, transports, supports_prf, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('pk-1', USER, 'login', 'passkey', 'pub', 'cred-1', 0, '[]', 0, FIXED_NOW, FIXED_NOW);

  connection
    .prepare(
      'INSERT INTO auth_requests (id, user_id, type, request_device_identifier, request_device_type, access_code, public_key, approved, creation_date) VALUES (?,?,?,?,?,?,?,?,?)'
    )
    .run('ar-1', USER, 0, 'device-1', 1, 'code-1', 'pk', null, new Date().toISOString());

  connection
    .prepare('INSERT INTO trusted_two_factor_device_tokens (token, user_id, device_identifier, expires_at) VALUES (?,?,?,?)')
    .run('tt-1', USER, 'device-1', Date.now() + 86_400_000);
}

/** 驱动所有"读/列表/分页"路径，让真实 SQL 流经 Proxy */
async function driveReadPaths(storage: StorageService, env: Env): Promise<void> {
  const calls: Array<() => Promise<unknown>> = [
    () => storage.isRegistered(),
    () => storage.getConfigValue('registered'),
    () => storage.getUser('plan@example.test'),
    () => storage.getUserById(USER),
    () => storage.getUserCount(),
    () => storage.getAllUsers(),
    () => storage.getInvite('invite-1'),
    () => storage.listInvites(true),
    // 带过滤的分支：应当走 idx_invites_status_expires，而不是裸扫
    () => storage.listInvites(false),
    () => storage.listAuditLogs({ limit: 50, offset: 0 }),
    () => storage.listAuditLogs({ limit: 50, offset: 0, category: 'security' }),
    () => storage.listAuditLogs({ limit: 50, offset: 0, level: 'info' }),
    () => storage.listAuditLogs({ limit: 50, offset: 0, from: FIXED_NOW, to: FIXED_NOW }),
    () => storage.listAuditLogs({ limit: 50, offset: 0, q: 'login' }),
    () => storage.listAuditLogs({ limit: 50, offset: 100 }),
    () => storage.getUserDomainSettings(USER),
    () => storage.getAccountPasskeyCredentialsByUserId(USER),
    () => storage.getAccountPasskeyCredentialById(USER, 'pk-1'),
    () => storage.getAccountPasskeyCredentialByCredentialId('cred-1'),
    () => storage.countAccountPasskeyCredentialsByUserId(USER),
    () => storage.listAccountPasskeyUserIds('twoFactor'),
    () => storage.getCipher('cipher-0'),
    () => storage.getCipherForUser('cipher-0', USER),
    () => storage.getAllCiphers(USER),
    () => storage.getCiphersPage(USER, false, 50, 0),
    () => storage.getCiphersPage(USER, true, 50, 100),
    () => storage.getCiphersByIds(['cipher-0', 'cipher-1'], USER),
    () => storage.getFolder('folder-1'),
    () => storage.getFolderForUser('folder-1', USER),
    () => storage.getAllFolders(USER),
    () => storage.getFoldersPage(USER, 50, 0),
    () => storage.getAttachment('att-1'),
    () => storage.getAttachmentForUser('att-1', USER),
    () => storage.getAttachmentsByCipher('cipher-0'),
    () => storage.getAttachmentsByCipherIds(['cipher-0', 'cipher-1']),
    () => storage.getAttachmentsByUserId(USER),
    () => storage.getRefreshTokenRecord('token-1'),
    () => storage.getRefreshTokenUserId('token-1'),
    () => storage.getSend('send-1'),
    () => storage.getSendForUser('send-1', USER),
    () => storage.getSendsByIds(['send-1'], USER),
    () => storage.getAllSends(USER),
    () => storage.getSendsPage(USER, 50, 100),
    () => storage.isKnownDevice(USER, 'device-1'),
    () => storage.isKnownDeviceByEmail('plan@example.test', 'device-1'),
    () => storage.getDevicesByUserId(USER),
    () => storage.getDevice(USER, 'device-1'),
    () => storage.getDevicePushUuid(USER, 'device-1'),
    () => storage.getAuthRequestById('ar-1'),
    () => storage.getAuthRequestByIdForUser('ar-1', USER),
    () => storage.listAuthRequestsByUserId(USER),
    () => storage.listPendingAuthRequestsByUserId(USER),
    () => storage.getTrustedDeviceTokenSummariesByUserId(USER),
    () => storage.getTrustedTwoFactorDeviceTokenUserId('tt-1', 'device-1'),
    () => storage.getRevisionDate(USER),
  ];

  for (const call of calls) {
    // 采集型调用：个别方法在特定参数组合下可能抛错，不应中断整轮采集
    await call().catch(() => undefined);
  }

  // 再走一遍 handler 层，覆盖"列表之外的读路径"（sync 是全量拼装，读得最多）。
  //
  // 刻意**不**在这里调写操作 handler（如 handleCreateCipher）：它们会在写完后
  // `void` 起一条通知链，而通知链可能在 `handle.close()` 之后才碰到 D1，
  // 于是往 stderr 打 "database is not open"。而写操作产生的 SQL 全是
  // INSERT/UPDATE（本文件只审计 SELECT），去掉它不损失覆盖面。
  await handleSync(new Request('https://vault.example.test/api/sync', { method: 'GET' }), env, USER).catch(
    () => undefined
  );

  // 限流：跑在**每一个**请求上，是真实热路径中最热的一条，必须纳入审计
  const rateLimit = new RateLimitService(env.DB);
  await rateLimit.checkLoginAttempt('203.0.113.1').catch(() => undefined);
  await rateLimit.recordFailedLogin('203.0.113.1').catch(() => undefined);
  await rateLimit.clearLoginAttempts('203.0.113.1').catch(() => undefined);
  await rateLimit.consumeStrictBudget('strict-key', 10).catch(() => undefined);
  await rateLimit.consumeBudget('budget-key', 10).catch(() => undefined);
}

/**
 * 确定性驱动所有"周期性清理"路径。
 *
 * 这些清理藏在普通操作里，且用 `Math.random() < 0.05` 做概率门控 ——
 * 不干预的话它们十次里跑不到一次，审计就会"看起来没问题"。
 * 把 `Math.random` 临时钉成 0 即可让所有门控必开（区间判定用的是**真实**时间，不受影响）。
 * 清理类 DELETE 是**周期性全表跑**的，缺索引时代价会随表增长线性上升，最该被审计。
 */
async function driveCleanupPaths(storage: StorageService, env: Env): Promise<void> {
  const originalRandom = Math.random;
  Math.random = () => 0;
  try {
    const future = Date.now() + 86_400_000;
    const calls: Array<[string, () => Promise<unknown>]> = [
      ['清理 refresh_tokens', () => storage.getRefreshTokenRecord('token-1')],
      ['清理 trusted_two_factor_device_tokens', () => storage.getTrustedDeviceTokenSummariesByUserId(USER)],
      ['清理 trusted_two_factor_device_tokens（写入路径）', () => storage.saveTrustedTwoFactorDeviceToken('tt-2', USER, 'device-1', future)],
      ['清理 trusted_two_factor_device_tokens（续期路径）', () => storage.updateTrustedTwoFactorTokensExpiryByDevice(USER, 'device-1', future)],
      ['清理 used_attachment_download_tokens', () => storage.consumeAttachmentDownloadToken('jti-1', Math.floor(Date.now() / 1000) + 3600)],
      ['清理 totp_login_replays', () => storage.consumeTotpLoginCounter(USER, 1)],
      ['清理 webauthn_challenges', () => storage.saveAccountPasskeyChallenge({
        challengeHash: 'challenge-1',
        scope: 'Authentication',
        userId: USER,
        expiresAt: future,
        usedAt: null,
        createdAt: Date.now(),
      })],
      ['清理 auth_requests', () => storage.pruneExpiredAuthRequests()],
      ['清理 audit_logs', () => storage.pruneAuditLogs('2027-01-01T00:00:00.000Z')],
      ['清理未使用的邀请码', () => storage.deleteInvalidInvites()],
      // 登录尝试表的清理藏在 checkLoginAttempt / recordFailedLogin 里，同样是概率门控的。
      // 早先漏了这两条 —— 结果这条 DELETE 只有约 5% 的运行会被采集到，
      // 于是"缺索引"这件事时隐时现，表现为偶发失败。
      ['清理 login_attempts_ip（读取路径）', () => new RateLimitService(env.DB).checkLoginAttempt('203.0.113.99')],
      ['清理 login_attempts_ip（写入路径）', () => new RateLimitService(env.DB).recordFailedLogin('203.0.113.99')],
    ];
    for (const [, call] of calls) {
      await call().catch(() => undefined);
    }
  } finally {
    Math.random = originalRandom;
  }
}

test('主要列表/分页查询的查询计划（无裸全表扫描）', async () => {
  const handle = await createSchemaDatabase();
  seed(handle.connection);

  const recorder = recordQueries(handle.db);
  const env = {
    DB: recorder.db,
    NOTIFICATIONS_HUB: {
      idFromName: (name: string) => ({ toString: () => name }),
      get: () => ({ fetch: async () => new Response('{}', { status: 200 }) }),
    },
  } as unknown as Env;

  // sync.ts 用 caches.default；Node 里没有这个全局
  (globalThis as unknown as { caches: unknown }).caches = {
    default: { match: async () => undefined, put: async () => undefined },
  };

  const storage = new StorageService(recorder.db as unknown as D1Database);
  await driveReadPaths(storage, env);
  await driveCleanupPaths(storage, env);

  const statements = recorder.distinctQueries.filter((sql) => AUDITED_STATEMENT.test(sql));
  assert.ok(statements.length > 40, `采集到的可变扫描语句太少（${statements.length} 条），驱动脚本可能失效了`);

  const plans: Plan[] = statements.map((sql) => {
    let details: string[];
    try {
      const rows = handle.connection.prepare(`EXPLAIN QUERY PLAN ${sql}`).all() as Array<{ detail: string }>;
      details = rows.map((row) => String(row.detail));
    } catch (error) {
      details = [`<无法解析: ${(error as Error).message}>`];
    }
    return {
      sql,
      details,
      bareScanTables: findBareScans(details),
      tempBTree: details.some((detail) => detail.includes('TEMP B-TREE')),
    };
  });

  // ---- 打印完整报告（这是 §3.3 要留档的人工复核材料）----
  const bareScanSet = new Set(plans.flatMap((plan) => plan.bareScanTables));
  const withBareScan = plans.filter((plan) => plan.bareScanTables.length > 0).length;
  const withIndexScan = plans.filter((plan) => plan.details.some((detail) => /^SCAN .+ USING /.test(detail))).length;
  const withSearch = plans.filter((plan) => plan.details.some((detail) => /^SEARCH /.test(detail))).length;

  console.log('');
  console.log(`已审计 ${plans.length} 条去重语句（SELECT/DELETE/UPDATE）：`);
  console.log(`  · 按索引/主键定位（SEARCH）：${withSearch} 条`);
  console.log(`  · 含全索引扫描（SCAN … USING INDEX）：${withIndexScan} 条`);
  console.log(`  · 含裸全表扫描（SCAN 无 USING）：${withBareScan} 条`);
  console.log('');
  for (const plan of plans) {
    const flag = plan.bareScanTables.length > 0 ? '✗' : '·';
    console.log(`${flag} ${plan.sql.slice(0, 150)}`);
    for (const detail of plan.details) {
      console.log(`    ${detail}`);
    }
  }
  console.log('');
  console.log(`裸全表扫描涉及的表：${bareScanSet.size ? [...bareScanSet].map((t) => `SCAN ${t}`).join(', ') : '（无）'}`);
  console.log(`含 TEMP B-TREE（额外排序）的查询数：${plans.filter((plan) => plan.tempBTree).length}`);
  console.log('');

  // ---- 断言 1：不允许裸全表扫描（白名单除外，且必须有理由）----
  const forbidden = [...bareScanSet].filter((table) => !(table in ALLOWED_BARE_SCANS));
  assert.deepStrictEqual(
    forbidden,
    [],
    `以下表出现裸全表扫描（\`SCAN <表>\` 不带 USING），需要检查是否缺索引：\n${forbidden
      .map((table) => {
        const affected = plans.filter((plan) => plan.bareScanTables.includes(table));
        return `  · SCAN ${table}（${affected.length} 条查询）\n${affected.map((p) => `      ${p.sql.slice(0, 140)}`).join('\n')}`;
      })
      .join('\n')}`
  );

  // ---- 断言 2：白名单不许留过期条目（否则它会变成"技术债墓地"）----
  const stale = Object.keys(ALLOWED_BARE_SCANS).filter((table) => !bareScanSet.has(table));
  assert.deepStrictEqual(stale, [], `白名单里以下条目已不再发生裸扫描，应当删除：${stale.join(', ')}`);

  // ---- 断言 3：用户维度的列表查询必须按索引定位（热路径，退化后果最重）----
  for (const plan of plans) {
    if (!/WHERE[\s\S]*user_id\s*=\s*\?/i.test(plan.sql)) continue;
    const table = USER_SCOPED_TABLES.find((name) => new RegExp(`FROM ${name}\\b`).test(plan.sql));
    if (!table) continue;
    assert.ok(
      plan.details.some((detail) => detail.startsWith('SEARCH')),
      `用户维度查询未按索引定位：${plan.sql.slice(0, 140)}\n  计划：${plan.details.join(' / ')}`
    );
  }

  handle.close();
});
