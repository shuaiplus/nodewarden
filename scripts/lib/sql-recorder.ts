// SQL 采集器：包一层 Proxy，记录被测代码**实际发出**的每一条 SQL。
//
// 为什么不用正则去源码里抓 SQL 字符串：
//   本仓库大量 SQL 是模板字符串拼出来的（`WHERE ${where} ORDER BY ...`），
//   正则抓不全、抓到的也不是"运行时真正执行的形态"。运行时采集拿到的就是真相。
//
// 为什么用 Proxy 而不是包装 statement：
//   `env.DB.batch([...])` 需要拿到**真正的** statement 对象（`d1-sqlite.ts` 里靠
//   `.execute()` 复用同步执行路径）。如果包装 statement，batch 就会拿到假对象。
//   只拦 `prepare` / `batch`、其余原样转发。
//
// ⚠️ `queries` 与 `roundTrips` 回答的是**两个不同的问题**，别混用：
//   · `queries`    —— 准备好的 SQL 条数。用于"这条 SQL 的查询计划是什么"。
//   · `roundTrips` —— **数据库往返次数**。用于"这次请求会不会随数据量线性变慢"。
//
//   差别在 `batch()` 上体现：`db.batch([...N 条...])` 会先 prepare N 条
//   （`queries` 记 N 条），但只发**一次**往返（`roundTrips` 记 1）。
//   拿 `queries.length` 去断言"N+1 消失了"会得到假阴性 —— 实测踩过这个坑。
import type { D1Database } from '@cloudflare/workers-types';

export interface SqlRecorder {
  /** 交给被测代码当 D1Database 用 */
  readonly db: D1Database;
  /** 按发生顺序记录的全部 SQL（含重复；不含 batch 边界标记） */
  readonly queries: string[];
  /** 去重后的 SQL，保持首次出现的顺序 */
  readonly distinctQueries: readonly string[];
  /** 数据库**往返**次数：逐条执行的语句各算 1 次，一次 batch 算 1 次 */
  readonly roundTrips: number;
  /** 清空已记录内容（便于分段驱动不同场景） */
  reset(): void;
}

/** 归一化：把连续空白压成一个空格，便于去重与输出对齐 */
function normalize(sql: string): string {
  return sql.replace(/\s+/g, ' ').trim();
}

export function recordQueries(inner: D1Database): SqlRecorder {
  const queries: string[] = [];
  /** 被 batch 收编的 statement 对应的 queries 下标 —— 它们不再各自算一次往返 */
  const batchedIndexes = new Set<number>();
  const recordIndexByStatement = new WeakMap<object, number>();
  let batchCount = 0;

  /**
   * 给 statement 再套一层 Proxy，目的是**把 `bind()` 的结果也认出来**。
   *
   * 这一步不能省：`prepare(SQL)` 返回一个 statement，`bind(...)` 会返回**另一个新对象**。
   * 而实际交给 `db.batch()` 的正是 bind 之后那个。如果只跟踪 prepare 的返回值，
   * batch 里就一条都对不上，往返数会算成"N 条逐条执行 + 1 次 batch" ——
   * 实测就踩了这个坑（batch 明明生效，计数却仍随 N 增长）。
   *
   * 注意：proxy 会把 `execute()` 等原样转发给真正的 statement，
   * 因此 `d1-sqlite.ts` 的 batch 实现不受影响。
   */
  function trackStatement(statement: object, queryIndex: number): object {
    const proxy = new Proxy(statement, {
      get(target, property, receiver) {
        const value = Reflect.get(target, property, receiver) as unknown;
        if (property === 'bind' && typeof value === 'function') {
          return (...args: unknown[]) => trackStatement((value as (...a: unknown[]) => object).apply(target, args), queryIndex);
        }
        return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
      },
    });
    recordIndexByStatement.set(proxy, queryIndex);
    return proxy;
  }

  const proxy = new Proxy(inner, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver) as unknown;

      if (property === 'prepare' && typeof value === 'function') {
        return (query: string) => {
          const queryIndex = queries.push(normalize(query)) - 1;
          return trackStatement((value as (q: string) => object).call(target, query), queryIndex);
        };
      }

      if (property === 'batch' && typeof value === 'function') {
        return (statements: object[]) => {
          batchCount += 1;
          for (const statement of statements) {
            const queryIndex = recordIndexByStatement.get(statement);
            if (queryIndex !== undefined) batchedIndexes.add(queryIndex);
          }
          return (value as (s: object[]) => unknown).call(target, statements);
        };
      }

      // 其余方法原样转发，但要把 this 绑回真正的 target
      return typeof value === 'function' ? (value as (...args: unknown[]) => unknown).bind(target) : value;
    },
  });

  return {
    db: proxy as D1Database,
    queries,
    get distinctQueries() {
      return [...new Set(queries)];
    },
    get roundTrips() {
      let single = 0;
      for (let index = 0; index < queries.length; index += 1) {
        if (!batchedIndexes.has(index)) single += 1;
      }
      return single + batchCount;
    },
    reset() {
      queries.length = 0;
      batchedIndexes.clear();
      batchCount = 0;
    },
  };
}
