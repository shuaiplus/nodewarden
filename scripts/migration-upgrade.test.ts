// D1 迁移在「已有数据的库」上的升级路径测试
//
// 要回答的问题：一个有存量的老库升级到新版本时，**数据是否完好**？
//
// 之前的验证只覆盖了「语法能执行」与「运行时 schema 与迁移文件无漂移」（第 3 轮），
// 但**从未在真实数据上跑过一次升级**。而升级是部署路径上的必经步骤，只对有存量库的
// 实例生效 —— 恰恰是最难靠人工发现问题的场景。
//
// 做法：用 node:sqlite 适配器（./lib/d1-sqlite.ts）跑真实 SQL。
//   ① 用 migrations/0001_init.sql 建库（新库基线）
//   ② 灌入代表性数据
//   ③ **机械地**把「后加的列」DROP 掉，模拟老库形态
//      —— 后加列的清单来自 SCHEMA_STATEMENTS 的 `ALTER TABLE ... ADD COLUMN`，
//         而不是手写清单，因此将来新增列时本测试会自动覆盖到
//   ④ 跑 ensureStorageSchema / initializeDatabase
//   ⑤ 断言：列被补齐、原有数据逐行完好、重复执行幂等
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import type { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import test from 'node:test';

import { ensureStorageSchema, SCHEMA_STATEMENTS } from '../src/services/storage-schema';
import { StorageService } from '../src/services/storage';
import { createD1SqliteDatabase } from './lib/d1-sqlite';

const REPO_ROOT = path.resolve(import.meta.dirname, '..');
const SCHEMA_SQL = readFileSync(path.join(REPO_ROOT, 'migrations', '0001_init.sql'), 'utf8');
const NOW = '2026-01-01T00:00:00.000Z';
const SCHEMA_VERSION_KEY = 'schema.version';
const REQUIRED_SCHEMA_TABLES = ['webauthn_credentials', 'webauthn_challenges', 'auth_requests', 'totp_login_replays'];

/** 运行时会补、但新库基线（migration 的 CREATE TABLE）里可能没有的列 */
const ADDED_COLUMNS: ReadonlyArray<{ table: string; column: string }> = SCHEMA_STATEMENTS.flatMap((sql) => {
  const match = sql.match(/^ALTER TABLE (\w+) ADD COLUMN (\w+)/i);
  return match ? [{ table: match[1], column: match[2] }] : [];
});

function freshDatabase() {
  const handle = createD1SqliteDatabase();
  handle.connection.exec(SCHEMA_SQL);
  return handle;
}

function columnsOf(conn: DatabaseSync, table: string): string[] {
  const rows = conn.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string }>;
  return rows.map((row) => row.name);
}

/** node:sqlite 返回的行是 null-prototype 对象，与普通对象字面量做 deepStrictEqual 会失败 */
function plain<T extends Record<string, unknown>>(rows: T[]): T[] {
  return rows.map((row) => ({ ...row }));
}

interface TableSnapshot {
  columns: string[];
  rows: Array<Record<string, unknown>>;
}

function snapshotRows(conn: DatabaseSync): Record<string, TableSnapshot> {
  const tables = (conn
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as Array<{ name: string }>).map((row) => row.name);

  const snapshot: Record<string, TableSnapshot> = {};
  for (const table of tables) {
    snapshot[table] = {
      columns: columnsOf(conn, table),
      rows: plain(conn.prepare(`SELECT * FROM "${table}" ORDER BY rowid`).all() as Array<Record<string, unknown>>),
    };
  }
  return snapshot;
}

/** 取主键列（按 pk 序号排序），用于按行定位 */
function primaryKeyOf(conn: DatabaseSync, table: string): string[] {
  const rows = conn.prepare(`PRAGMA table_info("${table}")`).all() as Array<{ name: string; pk: number }>;
  return rows
    .filter((row) => row.pk > 0)
    .sort((a, b) => a.pk - b.pk)
    .map((row) => row.name);
}

function pick(row: Record<string, unknown>, columns: string[]): Record<string, unknown> {
  return Object.fromEntries(columns.map((column) => [column, row[column]]));
}

/**
 * 断言「升级前已存在的行」在升级后仍存在，且**既有列**取值未变。
 *
 * 两处刻意的放宽，都对应 bootstrap 的**文档化副作用**（见 src/services/storage-schema.ts）：
 *  - **允许新增行**：兜底提权会补写一条审计事件。所以按主键逐行定位，而不是比较整个数组
 *  - **`ignoreColumns` 内的列允许变化**：兜底提权会改写 `users.role` 与 `users.updated_at`
 *
 * 另外只比较「升级前就存在的列」—— 补列会让行的字段集合变大，那是预期的结构变化，不是数据损坏。
 */
function assertPreExistingRowsPreserved(
  conn: DatabaseSync,
  before: Record<string, TableSnapshot>,
  ignoreColumns: ReadonlySet<string> = new Set()
): void {
  for (const [table, snapshot] of Object.entries(before)) {
    const afterColumns = columnsOf(conn, table);
    for (const column of snapshot.columns) {
      assert.ok(afterColumns.includes(column), `${table}.${column} 在升级后消失`);
    }

    const pk = primaryKeyOf(conn, table);
    if (pk.length === 0) continue; // 无主键的表无法逐行定位，跳过（本库所有表都有主键）

    const compared = snapshot.columns.filter(
      (column) => !ignoreColumns.has(`${table}.${column}`) && afterColumns.includes(column)
    );
    const projection = compared.map((column) => `"${column}"`).join(', ');
    const where = pk.map((column) => `"${column}" = ?`).join(' AND ');

    for (const row of snapshot.rows) {
      const key = pk.map((column) => row[column]) as never[];
      const found = conn.prepare(`SELECT ${projection} FROM "${table}" WHERE ${where}`).get(...key) as
        | Record<string, unknown>
        | undefined;
      assert.ok(found, `${table} 中主键为 ${JSON.stringify(key)} 的行在升级后丢失`);
      assert.deepStrictEqual(
        { ...found },
        pick(row, compared),
        `${table} 中主键为 ${JSON.stringify(key)} 的既有数据在升级后发生变化`
      );
    }
  }
}

function tableExists(conn: DatabaseSync, table: string): boolean {
  return !!conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?").get(table);
}

/**
 * 模拟老库：把「后加的列」逐个 DROP 掉。
 * 若该列被索引引用，先 DROP 掉相关索引再 DROP 列；SQLite 不允许删的（如 PK/UNIQUE
 * 自动索引）则跳过并记录，最后用下界断言确保"确实降级了"而不是静默什么都没做。
 */
function degradeToLegacyShape(conn: DatabaseSync): { degraded: string[]; skipped: string[] } {
  const degraded: string[] = [];
  const skipped: string[] = [];

  for (const { table, column } of ADDED_COLUMNS) {
    if (!tableExists(conn, table)) {
      skipped.push(`${table}.${column} (table missing)`);
      continue;
    }
    if (!columnsOf(conn, table).includes(column)) {
      skipped.push(`${table}.${column} (already absent)`);
      continue;
    }
    try {
      const indexes = conn
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = ? AND sql IS NOT NULL")
        .all(table) as Array<{ name: string; sql: string }>;
      for (const index of indexes) {
        if (new RegExp(`\\b${column}\\b`).test(index.sql)) conn.exec(`DROP INDEX IF EXISTS "${index.name}"`);
      }
      conn.exec(`ALTER TABLE "${table}" DROP COLUMN "${column}"`);
      degraded.push(`${table}.${column}`);
    } catch (error) {
      skipped.push(`${table}.${column} (${error instanceof Error ? error.message : String(error)})`);
    }
  }
  return { degraded, skipped };
}

function seedRows(conn: DatabaseSync): void {
  conn
    .prepare(
      'INSERT INTO users (id, email, name, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('user-1', 'alice@example.test', 'Alice', 'master-hash', 'wrapped-key', 0, 600000, 'stamp-1', 'user', NOW, NOW);
  conn.prepare('INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?,?,?,?,?)')
    .run('folder-1', 'user-1', 'enc-folder', NOW, NOW);
  conn
    .prepare('INSERT INTO ciphers (id, user_id, type, folder_id, name, notes, favorite, data, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)')
    .run('cipher-1', 'user-1', 1, 'folder-1', 'enc-name', 'enc-notes', 1, '{"x":1}', NOW, NOW);
  conn.prepare('INSERT INTO config (key, value) VALUES (?,?)').run('ui.language', 'zh-CN');
  conn
    .prepare('INSERT INTO audit_logs (id, actor_user_id, action, target_type, target_id, created_at) VALUES (?,?,?,?,?,?)')
    .run('audit-1', 'user-1', 'test.event', 'user', 'user-1', NOW);
}

/** 快照所有表的所有行，用于"数据是否逐行完好"的比对 */
function snapshotAllRows(conn: DatabaseSync): Record<string, unknown[]> {
  const tables = (conn
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
    .all() as Array<{ name: string }>).map((row) => row.name);

  const snapshot: Record<string, unknown[]> = {};
  for (const table of tables) {
    snapshot[table] = plain(
      conn.prepare(`SELECT * FROM "${table}" ORDER BY rowid`).all() as Array<Record<string, unknown>>
    );
  }
  return snapshot;
}

/** StorageService.schemaVerified 是 private static，测试需要重置它来观察每次调用的真实行为 */
function resetSchemaVerifiedFlag(): void {
  (StorageService as unknown as { schemaVerified: boolean }).schemaVerified = false;
}

/**
 * 断言 `initializeDatabase` **不发起任何出站请求**。
 *
 * 背景：它此前会在末尾调 `ensurePushInstallationCredentials`，在缺少缓存凭据时向 Bitwarden
 * 的 push relay 发起真实 POST（实测吃到 429 限流）。但 `/config` 硬编码
 * `pushTechnology: 0` 与 `'web-push': false`，客户端根本不会使用推送 —— 也就是说
 * **每个 isolate 的首次请求都在白等一次第三方往返**。
 *
 * 而真正需要凭据的两处（`getPushAccessToken`、设备注册）都会自己先调
 * `ensurePushInstallationCredentials`，因此数据库初始化不该承担这件事。
 * 本测试锁死"数据库初始化是纯本地的"。
 */
async function expectNoOutboundFetch<T>(run: () => Promise<T>): Promise<T> {
  const original = globalThis.fetch;
  const calls: string[] = [];
  globalThis.fetch = ((input: unknown) => {
    calls.push(String(input));
    return Promise.reject(new Error('unexpected outbound fetch'));
  }) as typeof fetch;

  try {
    const result = await run();
    assert.deepStrictEqual(calls, [], `数据库初始化不应发起出站请求，实际发生：${JSON.stringify(calls)}`);
    return result;
  } finally {
    globalThis.fetch = original;
  }
}

// ------------------------------------------------------------------ 测试

test('后加列的清单可从 SCHEMA_STATEMENTS 机械推导（防测试失效）', () => {
  assert.ok(ADDED_COLUMNS.length > 0, '应能推导出后加的列');
  // 这条断言的作用：若将来 ALTER 语句的写法变了导致推导失效，测试会立刻失败，
  // 而不是悄悄退化成"没降级任何东西"的空测试。
  assert.ok(
    ADDED_COLUMNS.every((item) => item.table && item.column),
    `推导结果异常：${JSON.stringify(ADDED_COLUMNS.slice(0, 3))}`
  );
});

test('老库缺列 → bootstrap 补齐全部列，且原有数据逐行完好', () => {
  const handle = freshDatabase();
  seedRows(handle.connection);

  const { degraded, skipped } = degradeToLegacyShape(handle.connection);
  assert.ok(
    degraded.length >= 25,
    `应实际降级足够多的列（当前 ${degraded.length}），否则本测试名不副实。跳过项：${JSON.stringify(skipped)}`
  );
  console.log(`    [降级] ${degraded.length} 列已 DROP，${skipped.length} 列跳过`);

  const beforeSnapshot = snapshotRows(handle.connection);

  return ensureStorageSchema(handle.db).then(() => {
    // ① 被降级的列全部回来
    for (const { table, column } of ADDED_COLUMNS) {
      assert.ok(columnsOf(handle.connection, table).includes(column), `${table}.${column} 未被补齐`);
    }

    // ② 既有行仍然存在、既有列的取值未变（users.role/updated_at 例外，见下）
    assertPreExistingRowsPreserved(
      handle.connection,
      beforeSnapshot,
      new Set(['users.role', 'users.updated_at'])
    );

    // ③ 记录一个**真实且重要**的行为：`users.role` 是"后加的列"，老库补列时其默认值是
    //    'user'，于是该实例变成"没有任何 admin"，兜底提权随即把最早注册的用户提为管理员。
    //    这不是副作用瑕疵，而是设计意图（否则老库升级后会永久失管），故显式断言住。
    const roles = plain(
      handle.connection.prepare('SELECT id, role FROM users ORDER BY id').all() as Array<{ id: string; role: string }>
    );
    assert.deepStrictEqual(roles, [{ id: 'user-1', role: 'admin' }], '补列后应触发兜底提权');

    const promotions = plain(
      handle.connection
        .prepare("SELECT target_id, category, level FROM audit_logs WHERE action = 'user.bootstrap.admin_promoted'")
        .all() as Array<Record<string, unknown>>
    );
    assert.deepStrictEqual(promotions, [{ target_id: 'user-1', category: 'security', level: 'security' }]);

    handle.close();
  });
});

test('bootstrap 幂等：连续执行两次结果一致', () => {
  const handle = freshDatabase();
  seedRows(handle.connection);
  degradeToLegacyShape(handle.connection);

  return ensureStorageSchema(handle.db)
    .then(async () => {
      const first = snapshotAllRows(handle.connection);
      await ensureStorageSchema(handle.db);
      const second = snapshotAllRows(handle.connection);
      assert.deepStrictEqual(second, first, '重复执行 bootstrap 不应改变任何数据');
    })
    .finally(() => handle.close());
});

test('initializeDatabase：老库会重建 schema 并写入 schema.version', async () => {
  const handle = freshDatabase();
  seedRows(handle.connection);
  const { degraded } = degradeToLegacyShape(handle.connection);
  assert.ok(degraded.length > 0);

  resetSchemaVerifiedFlag();
  await expectNoOutboundFetch(() => new StorageService(handle.db).initializeDatabase());

  assert.ok(
    ADDED_COLUMNS.every(({ table, column }) => columnsOf(handle.connection, table).includes(column)),
    '老库被降级的列应全部被 initializeDatabase 补齐'
  );
  const version = handle.connection.prepare('SELECT value FROM config WHERE key = ?').get(SCHEMA_VERSION_KEY) as
    | { value: string }
    | undefined;
  assert.ok(version, 'schema.version 应被写入');
  handle.close();
});

test('initializeDatabase：版本一致且必需表齐全时跳过重建（避免每次请求都跑 schema）', async () => {
  const handle = freshDatabase();
  seedRows(handle.connection);

  resetSchemaVerifiedFlag();
  const storage = new StorageService(handle.db);
  await expectNoOutboundFetch(() => storage.initializeDatabase());

  // 制造一个"非必需表缺失"的现场：版本号仍一致，因此 gate 应当跳过重建
  for (const table of REQUIRED_SCHEMA_TABLES) {
    assert.ok(tableExists(handle.connection, table), `必需表 ${table} 应存在`);
  }
  handle.connection.exec('DROP TABLE folders');

  resetSchemaVerifiedFlag();
  await expectNoOutboundFetch(() => new StorageService(handle.db).initializeDatabase());

  assert.equal(
    tableExists(handle.connection, 'folders'),
    false,
    '版本一致时不应重建 schema；folders 被重建说明 gate 失效、每次请求都会白跑一遍'
  );
  handle.close();
});

test('无管理员时 bootstrap 会把最早注册的用户提权，并写入审计事件（第 5 轮改动的运行时验证）', async () => {
  const handle = freshDatabase();
  // 造两个普通用户，创建时间不同 —— 应提权"最早"的那个
  handle.connection
    .prepare(
      'INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('user-oldest', 'oldest@example.test', 'h', 'k', 0, 600000, 's1', 'user', 'active', '2025-01-01T00:00:00.000Z', NOW);
  handle.connection
    .prepare(
      'INSERT INTO users (id, email, master_password_hash, key, kdf_type, kdf_iterations, security_stamp, role, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)'
    )
    .run('user-newer', 'newer@example.test', 'h', 'k', 0, 600000, 's2', 'user', 'active', '2025-06-01T00:00:00.000Z', NOW);

  await ensureStorageSchema(handle.db);

  const roles = plain(
    handle.connection.prepare('SELECT id, role FROM users ORDER BY id').all() as Array<{ id: string; role: string }>
  );
  assert.deepStrictEqual(roles, [
    { id: 'user-newer', role: 'user' },
    { id: 'user-oldest', role: 'admin' },
  ], '应只把最早注册的用户提权为管理员');

  const audit = plain(
    handle.connection
      .prepare("SELECT action, category, level, actor_user_id, target_id, metadata FROM audit_logs WHERE action = 'user.bootstrap.admin_promoted'")
      .all() as Array<Record<string, unknown>>
  );
  assert.equal(audit.length, 1, '兜底提权必须留下且只留下一条审计事件');
  assert.equal(audit[0].actor_user_id, null, '系统行为不应有操作者');
  assert.equal(audit[0].target_id, 'user-oldest');
  assert.equal(audit[0].category, 'security');
  assert.equal(audit[0].level, 'security');
  assert.equal(String(audit[0].metadata), '{"reason":"no_admin_present"}');

  handle.close();
});
