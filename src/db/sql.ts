import { sql, type SQL } from 'drizzle-orm';

// The only module allowed to write SQL text (the lint rule bans importing `sql` anywhere else). Each
// helper is a typed expression drizzle has no builder for. Arguments may be columns, other expressions
// or plain values; plain values always travel as bound parameters, never as spliced text.

// A one-row source, for selecting bound values (INSERT ... SELECT, guards) where SQLite needs a FROM.
export const SINGLE_ROW = sql`(SELECT 1)`;

// A plain value as a selectable, aliasable expression: bound(now).as('updated_at').
export const bound = <T>(value: T): SQL<T> => sql<T>`${value}`;

// A column read as its stored D1 value, skipping drizzle's mode mapping (booleans, JSON, timestamps).
export const unmapped = <T>(column: unknown): SQL<T> => sql<T>`${column}`;

// A subquery used as a single value.
export const scalar = <T>(query: unknown): SQL<T> => sql<T>`(${query})`;

// The value an upsert tried to insert, for onConflictDoUpdate: excluded(users.password).
export const excluded = <T>(column: { name: string }): SQL<T> => sql<T>`excluded.${sql.identifier(column.name)}`;

export const plus = (left: unknown, right: unknown): SQL<number> => sql<number>`${left} + ${right}`;
export const lower = (value: unknown): SQL<string> => sql<string>`lower(${value})`;
export const castInteger = (value: unknown): SQL<number> => sql<number>`cast(${value} as integer)`;
export const coalesce = <T>(...values: unknown[]): SQL<T> => sql<T>`coalesce(${sql.join(values.map((value) => sql`${value}`), sql`, `)})`;
export const nullIf = <T>(value: unknown, empty: unknown): SQL<T | null> => sql<T | null>`nullif(${value}, ${empty})`;

// A missing otherwise yields SQL NULL.
export const caseWhen = <T>(condition: unknown, then: unknown, otherwise?: unknown): SQL<T> =>
  otherwise === undefined
    ? sql<T>`CASE WHEN ${condition} THEN ${then} END`
    : sql<T>`CASE WHEN ${condition} THEN ${then} ELSE ${otherwise} END`;

// LIKE with backslash as the escape character; callers escape %, _ and \ in user input.
export const likeEscaped = (value: unknown, pattern: string): SQL<boolean> => sql<boolean>`${value} LIKE ${pattern} ESCAPE '\\'`;

// Rows changed by the previous statement of the same connection (the preceding statement of a batch).
export const changes = (): SQL<number> => sql<number>`changes()`;
// json() of a non-JSON string raises, which is how a batch statement aborts the whole batch.
export const json = (value: unknown): SQL<unknown> => sql`json(${value})`;

export const jsonExtract = <T>(document: unknown, path: string): SQL<T> => sql<T>`json_extract(${document}, ${path})`;
export const jsonSet = (document: unknown, path: string, value: unknown): SQL<string> => sql<string>`json_set(${document}, ${path}, ${value})`;
export const jsonRemove = (document: unknown, ...paths: string[]): SQL<string> =>
  sql<string>`json_remove(${document}, ${sql.join(paths.map((path) => sql`${path}`), sql`, `)})`;

// A whole list as one bound JSON parameter, for IN / NOT IN over lists that could exceed D1's 100
// bound parameters: inArray(column, jsonValues(ids)).
export const jsonValues = (values: readonly unknown[]): SQL<unknown> => sql`(SELECT value FROM json_each(${JSON.stringify(values)}))`;
