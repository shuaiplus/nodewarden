import { DrizzleQueryError, and, eq, exists, getColumns, type SQL, type Table } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';

import { relations } from './relations';
import { users } from './schema';
import { SINGLE_ROW, caseWhen, changes, json } from './sql';

export type Orm = ReturnType<typeof drizzle<typeof relations, D1Database>>;

// D1 rejects any statement that binds more than this many parameters.
export const D1_MAX_BOUND_PARAMETERS = 100;

export function columnCount(table: Table): number {
  return Object.keys(getColumns(table)).length;
}

// Splits multi-row INSERT values so each statement stays within D1's bound-parameter limit, less
// any parameters every chunk's statement binds besides the rows.
export function chunkRows<T>(rows: T[], columnsPerRow: number, fixedParameters = 0): T[][] {
  const size = Math.floor((D1_MAX_BOUND_PARAMETERS - fixedParameters) / columnsPerRow);
  return Array.from({ length: Math.ceil(rows.length / size) }, (_, index) => rows.slice(index * size, (index + 1) * size));
}

// Splits items into chunks small enough that statement(chunk) stays within D1's bound-parameter limit.
// Rendering the statement for one and for two items measures what each item and everything else binds
// (JSON paths, literals, NULLs in SET, bound expressions left of IN), which hand counts kept getting wrong.
// Multi-row inserts keep chunkRows(rows, columnCount(table)): which columns bind varies with each row.
export function statementChunks<T>(items: T[], statement: (chunk: T[]) => { toSQL(): { params: unknown[] } }): T[][] {
  if (items.length < 2) return items.length ? [items] : [];
  const [one, two] = [1, 2].map((size) => statement(items.slice(0, size)).toSQL().params.length);
  if (two === one) throw new Error('statementChunks: the statement binds nothing per item');
  return chunkRows(items, two - one, 2 * one - two);
}

// Constructing the driver is cheap, but the relation graph it derives is not:
// memoise per binding so a Worker isolate builds it at most once per database.
const ormByBinding = new WeakMap<D1Database, Orm>();

export function getOrm(d1: D1Database): Orm {
  const existing = ormByBinding.get(d1);
  if (existing) return existing;

  const orm = drizzle(d1, { relations });
  ormByBinding.set(d1, orm);
  return orm;
}

// D1 batches have no conditional rollback. Appending this select after a guarded write aborts the whole
// batch when that write matched no rows: json() of a non-JSON string raises, and D1 rolls the batch back.
export function abortUnlessChanged(orm: Orm, reason: string) {
  return orm.select({ abort: caseWhen(eq(changes(), 0), json(reason)) }).from(SINGLE_ROW);
}

// EXISTS the user's row, narrowed by conditions (undefined ones are skipped). In a WHERE clause it guards a
// write to another table against a concurrent change to that user, such as a rotated security stamp.
export function userRowMatches(orm: Orm, userId: string, ...conditions: (SQL | undefined)[]) {
  return exists(orm.select({ id: users.id }).from(users).where(and(eq(users.id, userId), ...conditions)));
}

// A failed drizzle query's message lists every bound value (password hashes, keys, one-time codes), so
// anything logged keeps the statement text and the driver's own error only.
export function withoutQueryParams(error: unknown): unknown {
  return error instanceof DrizzleQueryError ? new Error(`Failed query: ${error.query}`, { cause: error.cause }) : error;
}
