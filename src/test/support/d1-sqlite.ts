import Database from 'better-sqlite3';

import { ensureStorageSchema } from '../../db/migrate';

type SqliteConnection = InstanceType<typeof Database>;

interface ExecutedStatement {
  columns: string[];
  rows: unknown[][];
  changes: number;
  lastRowId: number;
}

// Production D1 rejects statements above this; SQLite alone allows thousands, so enforce it
// here to catch unchunked queries before they reach a real database.
export const D1_MAX_BOUND_PARAMETERS = 100;

// Object rows are built from positional ones, so duplicate column names resolve the way D1's
// all()/first() resolve them: the last column wins.
function toD1Result({ columns, rows, changes, lastRowId }: ExecutedStatement): D1Result<Record<string, unknown>> {
  return {
    success: true,
    results: rows.map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index]]))),
    meta: {
      duration: 0,
      size_after: 0,
      rows_read: rows.length,
      rows_written: changes,
      last_row_id: lastRowId,
      changed_db: changes > 0,
      changes,
    },
  };
}

class SqliteD1Statement {
  constructor(
    private readonly connection: SqliteConnection,
    private readonly query: string,
    private readonly bindings: unknown[] = [],
  ) {}

  // D1 statements are immutable: drizzle prepares a query once and re-binds it per call.
  // D1 also validates bindings eagerly: undefined is a type error, and booleans and integral numbers
  // bind as INTEGER. better-sqlite3 rejects booleans and binds every number as REAL (a TEXT column
  // would store 1 as '1.0'), so pass integers as bigint, which it binds as INTEGER.
  bind(...values: unknown[]): SqliteD1Statement {
    return new SqliteD1Statement(
      this.connection,
      this.query,
      values.map((value) => {
        if (value === undefined) throw new Error("D1_TYPE_ERROR: Type 'undefined' not supported for value 'undefined'");
        const scalar = typeof value === 'boolean' ? Number(value) : value;
        return Number.isSafeInteger(scalar) ? BigInt(scalar as number) : scalar;
      }),
    );
  }

  // D1 compiles lazily, so SQL errors (including "already exists", which the schema bootstrap
  // tolerates) surface when the statement runs rather than at prepare().
  execute(): ExecutedStatement {
    try {
      if (this.bindings.length > D1_MAX_BOUND_PARAMETERS) {
        throw new Error(`too many SQL variables: ${this.bindings.length} > ${D1_MAX_BOUND_PARAMETERS}`);
      }
      const statement = this.connection.prepare(this.query);
      if (!statement.reader) {
        const { changes, lastInsertRowid } = statement.run(...this.bindings);
        return { columns: [], rows: [], changes, lastRowId: Number(lastInsertRowid) };
      }
      const rows = statement.raw(true).all(...this.bindings) as unknown[][];
      // Row-returning writes (INSERT ... RETURNING) still report their changes, as D1 does.
      const writeInfo = statement.readonly
        ? { changes: 0, lastRowId: 0 }
        : (this.connection.prepare('SELECT changes() AS changes, last_insert_rowid() AS lastRowId').get() as {
            changes: number;
            lastRowId: number;
          });
      return { columns: statement.columns().map((column: { name: string }) => column.name), rows, ...writeInfo };
    } catch (error) {
      throw new Error(`D1_ERROR: ${error instanceof Error ? error.message : String(error)}`, { cause: error });
    }
  }

  async first(column?: string): Promise<unknown> {
    const [row] = toD1Result(this.execute()).results;
    if (column === undefined) return row ?? null;
    if (row && !(column in row)) throw new Error(`D1_COLUMN_NOTFOUND: Column not found (${column})`);
    return row?.[column] ?? null;
  }

  async all(): Promise<D1Result<Record<string, unknown>>> {
    return toD1Result(this.execute());
  }

  async run(): Promise<D1Result<Record<string, unknown>>> {
    return toD1Result(this.execute());
  }

  async raw(options?: { columnNames?: boolean }): Promise<unknown[]> {
    const { columns, rows } = this.execute();
    return options?.columnNames ? [columns, ...rows] : rows;
  }
}

class SqliteD1Database {
  constructor(private readonly connection: SqliteConnection) {}

  prepare(query: string): SqliteD1Statement {
    return new SqliteD1Statement(this.connection, query);
  }

  // D1 runs a batch as one implicit transaction: a failing statement rolls back all of them.
  async batch(statements: SqliteD1Statement[]): Promise<D1Result<Record<string, unknown>>[]> {
    return this.connection.transaction(() => statements.map((statement) => toD1Result(statement.execute())))();
  }

  // D1 exec() runs each line as its own statement, so multi-line SQL fails here as it does there.
  async exec(query: string): Promise<D1ExecResult> {
    const lines = query.trim().split('\n');
    lines.forEach((line) => this.connection.exec(line));
    return { count: lines.length, duration: 0 };
  }
}

// A fresh in-memory database per call, with the schema applied by the production bootstrap.
export async function createSqliteD1(): Promise<D1Database> {
  const database = new SqliteD1Database(new Database(':memory:')) as unknown as D1Database;
  await ensureStorageSchema(database);
  return database;
}
