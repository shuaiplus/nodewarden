// 用 node:sqlite 实现 D1Database 的最小接口 —— 供测试在没有 Cloudflare 运行时的情况下
// 跑**真实 SQL**（D1 本身就是 SQLite，方言一致）。
//
// 为什么不直接用 mock：
//   备份导入走的是「影子表 createShadowTables → 校验计数 → 最后一次性
//   swapShadowTablesIntoPlace」流程。纯 mock 不真正存数据，只能断言"发了哪些 SQL"，
//   **无法验证数据是否原样回来** —— 而那正是 round-trip 测试要回答的问题。
//
// 局限（务必知悉）：
//   node:sqlite 与真实 D1 **不是同一实现**（D1 在其上加了自己的代理层与限制）。
//   因此本适配器只能证明"读写逻辑在 SQLite 语义下自洽"，**不能替代**在
//   `wrangler dev` 上跑的真实端到端验证。
//
// 已实测可用性：本地 Node 26 = SQLite 3.53.4，CI 的 Node 24.18.0 = 3.53.1，均无需 flag。
import { DatabaseSync } from 'node:sqlite';
import type { D1Database, D1Result } from '@cloudflare/workers-types';

/** D1 绑定的合法标量类型收窄（node:sqlite 不接受 boolean / ArrayBuffer / undefined） */
function toSqliteValue(value: unknown): null | number | bigint | string | Uint8Array {
  if (value === undefined || value === null) return null;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (typeof value === 'number' || typeof value === 'bigint' || typeof value === 'string') return value;
  // 真实 D1 同样只接受标量；这里显式抛出，避免静默写入错误数据
  throw new Error(`Unsupported bind value type: ${typeof value}`);
}

function emptyMeta(): D1Result<unknown>['meta'] {
  return { changes: 0, duration: 0, last_row_id: 0, rows_read: 0, rows_written: 0 } as D1Result<unknown>['meta'];
}

class SqliteD1Statement {
  constructor(
    private readonly connection: DatabaseSync,
    private readonly sql: string,
    private readonly params: ReadonlyArray<null | number | bigint | string | Uint8Array> = []
  ) {}

  bind(...values: unknown[]): SqliteD1Statement {
    return new SqliteD1Statement(this.connection, this.sql, values.map(toSqliteValue));
  }

  async first<T = Record<string, unknown>>(columnName?: string): Promise<T | null> {
    const row = this.connection.prepare(this.sql).get(...this.params) as Record<string, unknown> | undefined;
    if (!row) return null;
    if (columnName !== undefined) return (row[columnName] ?? null) as T;
    return row as T;
  }

  async all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    const results = this.connection.prepare(this.sql).all(...this.params) as T[];
    return { results, success: true, meta: emptyMeta() } as D1Result<T>;
  }

  async run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
    return this.execute() as D1Result<T>;
  }

  /** 供 batch() 复用：同步执行并返回 D1 形状的结果 */
  execute(): D1Result<Record<string, unknown>> {
    const info = this.connection.prepare(this.sql).run(...this.params);
    const changes = Number(info.changes ?? 0);
    return {
      results: [],
      success: true,
      meta: {
        changes,
        duration: 0,
        last_row_id: Number(info.lastInsertRowid ?? 0),
        rows_read: 0,
        rows_written: changes,
      },
    } as unknown as D1Result<Record<string, unknown>>;
  }
}

export interface D1SqliteDatabase {
  /** 交给被测代码当 D1Database 用 */
  readonly db: D1Database;
  /** 底层连接：测试可直接执行 DDL / 查询做校验 */
  readonly connection: DatabaseSync;
  close(): void;
}

/**
 * 建一个内存 SQLite 库，并以 D1Database 的形态暴露给被测代码。
 * @param location 默认 `:memory:`；传文件路径可持久化以便用 sqlite3 CLI 交叉检查
 */
export function createD1SqliteDatabase(location = ':memory:'): D1SqliteDatabase {
  const connection = new DatabaseSync(location);
  // 与 src/services/storage-schema.ts 的 ensureStorageSchema 保持一致
  connection.exec('PRAGMA foreign_keys = ON');

  const db = {
    prepare(sql: string) {
      return new SqliteD1Statement(connection, sql);
    },
    // D1 的 batch 是事务性的：要么全部生效，要么全部回滚
    async batch(statements: SqliteD1Statement[]) {
      connection.exec('BEGIN');
      try {
        const results = statements.map((statement) => statement.execute());
        connection.exec('COMMIT');
        return results;
      } catch (error) {
        connection.exec('ROLLBACK');
        throw error;
      }
    },
    async exec(sql: string) {
      const count = sql
        .split(';')
        .map((part) => part.trim())
        .filter(Boolean).length;
      connection.exec(sql);
      return { count, duration: 0 };
    },
  };

  return {
    // 单次显式转换：本适配器只实现 D1Database 的最小可用子集（prepare/batch/exec）
    db: db as unknown as D1Database,
    connection,
    close: () => connection.close(),
  };
}
